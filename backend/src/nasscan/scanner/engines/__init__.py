"""The scanning engines and the pipeline that runs them over each file."""

import logging
from dataclasses import dataclass, field

from nasscan.config import Settings
from nasscan.scanner.engines.base import (
    MEMORY,
    Engine,
    EngineUnavailableError,
    FileContext,
    Finding,
)
from nasscan.scanner.engines.clamav import ClamavEngine
from nasscan.scanner.engines.documents import DocumentsEngine
from nasscan.scanner.engines.heuristics import HeuristicsEngine
from nasscan.scanner.engines.printing import PrintingEngine
from nasscan.scanner.engines.yara_rules import YaraEngine

log = logging.getLogger(__name__)

ENGINE_TYPES: list[type[Engine]] = [
    ClamavEngine,
    YaraEngine,
    HeuristicsEngine,
    DocumentsEngine,
    PrintingEngine,
]


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    # Engines that couldn't scan this file, and why. Their earlier findings are kept.
    errors: dict[str, str] = field(default_factory=dict)


class Pipeline:
    def __init__(self, settings: Settings, engines: list[Engine] | None = None) -> None:
        self.engines = engines if engines is not None else [
            e for e in (cls(settings) for cls in ENGINE_TYPES) if e.enabled()
        ]  # fmt: skip

    @property
    def names(self) -> list[str]:
        return [e.name for e in self.engines]

    def _run(self, ctx: FileContext, result: ScanResult) -> None:
        for engine in self.engines:
            if engine.name in result.errors:
                continue  # already failed on this file
            try:
                if engine.applies(ctx):
                    result.findings.extend(engine.scan(ctx))
            except EngineUnavailableError as exc:
                result.errors[engine.name] = str(exc)
            except Exception as exc:  # one engine's bug or a hostile file: carry on
                log.warning("%s failed on %s: %s", engine.name, ctx.member or ctx.path, exc)
                result.errors[engine.name] = f"{type(exc).__name__}: {exc}"

    def scan(self, ctx: FileContext) -> ScanResult:
        from nasscan.scanner.hashing import MAGIC_BYTES, detect_type

        result = ScanResult()
        self._run(ctx, result)
        for item in ctx.embedded:
            ext = item.name.rsplit(".", 1)[-1].lower()[:32] if "." in item.name else None
            mime, magic = detect_type(item.data[:MAGIC_BYTES])
            member = FileContext(
                path=ctx.path,
                full_path=None,
                size=len(item.data),
                extension=ext,
                mime=mime,
                magic=magic,
                mode=MEMORY,
                data=item.data,
                head=item.data[: 1024 * 1024],
                member=item.name,
            )
            self._run(member, result)
        ctx.embedded.clear()  # let the members' bytes go
        return result
