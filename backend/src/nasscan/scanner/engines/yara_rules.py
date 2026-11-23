"""YARA: community rule sets, downloaded and compiled daily, plus your own rules.

Sources (NASSCAN_YARA_SOURCES): the YARA Forge packages (core, extended, full), which bundle
rules from many public repositories already checked to compile, and Neo23x0's
signature-base, compiled file by file so a rule that doesn't compile (an unsupported module,
say) is dropped without losing the rest. Rules in NASSCAN_YARA_LOCAL_DIR are compiled in too.

Everything is compiled into one file under NASSCAN_DATA_DIR/yara and swapped in atomically;
scanning threads pick up a new set by its modification time.
"""

import io
import json
import logging
import os
import shutil
import threading
import time
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yara

from nasscan.config import Settings
from nasscan.scanner.engines.base import (
    FILE,
    Engine,
    EngineUnavailableError,
    FileContext,
    Finding,
)

log = logging.getLogger(__name__)

NAME = "yara"
FORGE_URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-{}.zip"
SIGBASE_URL = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
SOURCES = {
    "forge-core": FORGE_URL.format("core"),
    "forge-extended": FORGE_URL.format("extended"),
    "forge-full": FORGE_URL.format("full"),
    "signature-base": SIGBASE_URL,
}
# signature-base rules use these external variables; they're filled in per file.
EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}
MATCH_TIMEOUT = 60  # seconds per file
DOWNLOAD_TIMEOUT = 120
USER_AGENT = "nas_scanner (+https://github.com/drewsum/nas_scanner)"


def severity_for(score: object) -> str:
    """YARA Forge's 0-100 score: 80 and up is malicious, 60 and up suspicious."""
    try:
        value = int(score)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return "suspicious"
    if value >= 80:
        return "malicious"
    return "suspicious" if value >= 60 else "info"


@dataclass
class CompileReport:
    rules_files: int
    skipped: list[str]
    sources: dict[str, str]  # source -> "ok" or the error


class RuleStore:
    """Downloaded sources, the compiled set and a small manifest under data_dir/yara."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.root = Path(settings.data_dir) / "yara"
        self.compiled = self.root / "compiled.yarc"
        self.manifest = self.root / "manifest.json"

    def read_manifest(self) -> dict:
        try:
            return json.loads(self.manifest.read_text())
        except (OSError, ValueError):
            return {}

    def due(self) -> bool:
        built = self.read_manifest().get("built_at")
        if not self.compiled.exists() or not built:
            return True
        age = time.time() - datetime.fromisoformat(built).timestamp()
        return age > self.settings.yara_refresh_hours * 3600

    # --- downloads -------------------------------------------------------------------------

    def _download(self, url: str) -> bytes:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:
            return resp.read()

    def fetch(self, source: str) -> Path:
        """Download one source and unpack its .yar files into sources/<name>/."""
        target = self.root / "sources" / source
        tmp = target.with_name(source + ".tmp")
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True)
        with zipfile.ZipFile(io.BytesIO(self._download(SOURCES[source]))) as z:
            for info in z.infolist():
                name = info.filename
                if info.is_dir() or not name.lower().endswith((".yar", ".yara")):
                    continue
                if source == "signature-base" and "/yara/" not in name:
                    continue
                # Flatten: keep only the file name, never a path from the archive.
                (tmp / Path(name).name).write_bytes(z.read(info))
        shutil.rmtree(target, ignore_errors=True)
        tmp.rename(target)
        return target

    # --- compiling -------------------------------------------------------------------------

    def _rule_files(self, report: CompileReport) -> dict[str, str]:
        files: dict[str, str] = {}
        for source in self.settings.yara_source_names:
            folder = self.root / "sources" / source
            if not folder.is_dir():
                continue
            for path in sorted(folder.iterdir()):
                files[f"{source}/{path.stem}"] = str(path)
        local = self.local_files()
        for path in local:
            rel = path.relative_to(self.settings.yara_local_dir).with_suffix("")
            files[f"local/{rel.as_posix()}"] = str(path)
        if local:
            report.sources["local"] = "ok"
        return files

    def local_files(self) -> list[Path]:
        local = Path(self.settings.yara_local_dir)
        if not local.is_dir():
            return []
        return sorted(
            p for p in local.rglob("*") if p.suffix.lower() in (".yar", ".yara") and p.is_file()
        )

    def local_changed(self) -> bool:
        """Local rules added, edited or removed since the last build."""
        manifest = self.read_manifest()
        if not manifest:
            return bool(self.local_files())
        names = sorted(str(p) for p in self.local_files())
        built = datetime.fromisoformat(manifest["built_at"]).timestamp()
        newest = max((p.stat().st_mtime for p in self.local_files()), default=0.0)
        return names != manifest.get("local_files", []) or newest > built

    def build(self) -> CompileReport:
        """Compile every rule file that compiles on its own, together, and swap it in."""
        report = CompileReport(0, [], {})
        candidates = self._rule_files(report)
        good: dict[str, str] = {}
        for namespace, path in candidates.items():
            try:
                yara.compile(filepath=path, externals=EXTERNALS)
            except yara.Error as exc:
                report.skipped.append(f"{namespace}: {str(exc)[:200]}")
                continue
            good[namespace] = path
        if not good:
            raise EngineUnavailableError("no YARA rules compiled")
        rules = yara.compile(filepaths=good, externals=EXTERNALS)
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.compiled.with_suffix(".tmp")
        rules.save(str(tmp))
        os.replace(tmp, self.compiled)
        report.rules_files = len(good)
        return report

    def refresh(self, download: bool = True) -> CompileReport:
        """Download every configured source (keeping the last copy of any that fails) and
        rebuild. Without ``download``, rebuild from the copies on disk (local rules changed)."""
        statuses: dict[str, str] = {}
        if not download:
            statuses = {
                k: v for k, v in self.read_manifest().get("sources", {}).items() if k != "local"
            }
        for source in self.settings.yara_source_names if download else []:
            if source not in SOURCES:
                statuses[source] = "unknown source"
                continue
            try:
                self.fetch(source)
                statuses[source] = "ok"
            except Exception as exc:
                log.warning("YARA source %s: download failed: %s", source, exc)
                statuses[source] = f"download failed: {exc}"
        report = self.build()
        report.sources = {**statuses, **report.sources}
        self.root.mkdir(parents=True, exist_ok=True)
        self.manifest.write_text(
            json.dumps(
                {
                    "built_at": datetime.now(UTC).isoformat(),
                    "rule_files": report.rules_files,
                    "skipped": report.skipped,
                    "sources": report.sources,
                    "local_files": sorted(str(p) for p in self.local_files()),
                },
                indent=1,
            )
        )
        if report.skipped:
            log.info("YARA: skipped %d rule files that don't compile", len(report.skipped))
        log.info("YARA: compiled %d rule files", report.rules_files)
        return report


class YaraEngine(Engine):
    name = NAME

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.store = RuleStore(settings)
        self._rules: yara.Rules | None = None
        self._loaded_mtime = 0.0
        self._checked = 0.0
        self._lock = threading.Lock()
        self.large = settings.large_file_mb * 1024 * 1024

    def rules(self) -> yara.Rules:
        """The compiled set, reloaded when a newer one has been built."""
        with self._lock:
            now = time.monotonic()
            if self._rules is None or now - self._checked > 60:
                self._checked = now
                try:
                    mtime = self.store.compiled.stat().st_mtime
                except OSError:
                    mtime = 0.0
                if mtime and mtime != self._loaded_mtime:
                    self._rules = yara.load(str(self.store.compiled))
                    self._loaded_mtime = mtime
            if self._rules is None:
                raise EngineUnavailableError("no YARA rules compiled yet")
            return self._rules

    def scan(self, ctx: FileContext) -> list[Finding]:
        rules = self.rules()
        externals = {
            "filename": ctx.name,
            "filepath": ctx.path,
            "extension": "." + ctx.extension if ctx.extension else "",
            "filetype": (ctx.magic or "")[:200],
            "owner": "",
        }
        matches: dict[str, tuple[str, yara.Match]] = {}
        if ctx.mode == FILE and ctx.size <= self.large and ctx.full_path is not None:
            parts = [("", rules.match(os.fsdecode(ctx.full_path), externals=externals,
                                      timeout=MATCH_TIMEOUT))]  # fmt: skip
        else:
            pieces = ctx.pieces() if ctx.mode != FILE else [("head", ctx.head), ("tail", ctx.tail)]
            parts = [
                (part, rules.match(data=data, externals=externals, timeout=MATCH_TIMEOUT))
                for part, data in pieces
                if data
            ]
        for part, found in parts:
            for m in found:
                matches.setdefault(f"{m.namespace}:{m.rule}", (part, m))
        findings = []
        for key, (part, m) in matches.items():
            meta = {k: v for k, v in m.meta.items() if isinstance(v, str | int | bool)}
            source = m.namespace.split("/", 1)[0]
            findings.append(
                Finding(
                    engine=NAME,
                    name=m.rule,
                    severity=severity_for(meta.get("score")),
                    description=str(meta.get("description") or f"YARA rule {m.rule}")[:500],
                    details={
                        "rule": m.rule,
                        "source": source,
                        "namespace": m.namespace,
                        "tags": list(m.tags),
                        "score": meta.get("score"),
                        "author": meta.get("author"),
                        "reference": meta.get("reference"),
                        "part": part,
                        "key": key,
                    },
                    member=ctx.member,
                )
            )
        return findings
