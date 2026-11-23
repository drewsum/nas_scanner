"""Live hash-lookup providers. Each is sent hashes only; none is ever sent a file."""

import socket
from collections import Counter
from datetime import timedelta

from nasscan.intel.base import Hashes, LookupResult, Provider, ProviderError


class CirclProvider(Provider):
    """CIRCL hashlookup: NSRL and other known-software sets. A hit is known good (so the
    quota-limited providers skip it), unless CIRCL also lists it as known malicious."""

    name = "circl"
    title = "CIRCL hashlookup (NSRL known files)"
    daily_budget = 20000
    per_minute = 30
    batch_size = 100
    known_good_source = True
    url = "https://hashlookup.circl.lu/bulk/sha1"

    def lookup(self, hashes: list[Hashes]) -> dict[str, LookupResult]:
        by_sha1 = {h.sha1.upper(): h.sha256 for h in hashes if h.sha1}
        out = {h.sha256: LookupResult.not_found() for h in hashes}
        if not by_sha1:
            return out
        data = self._json(self._request("POST", self.url, json={"hashes": list(by_sha1)}))
        if not isinstance(data, list):
            raise ProviderError(f"unexpected answer: {str(data)[:200]}", timedelta(minutes=30))
        for entry in data:
            if not isinstance(entry, dict):
                continue
            sha256 = by_sha1.get(str(entry.get("SHA-1", "")).upper())
            if not sha256:
                continue
            trust = entry.get("hashlookup:trust", 50)
            source = entry.get("source") or entry.get("db") or ""
            details = {
                "file_name": entry.get("FileName"),
                "product": (entry.get("ProductCode") or {}).get("ProductName")
                if isinstance(entry.get("ProductCode"), dict)
                else None,
                "source": source,
                "trust": trust,
            }
            if entry.get("KnownMalicious"):
                out[sha256] = LookupResult(
                    "suspicious",
                    "Known malicious",
                    f"CIRCL lists it as known malicious (source: {entry['KnownMalicious']})",
                    details | {"known_malicious": entry["KnownMalicious"]},
                )
            elif isinstance(trust, int | float) and trust >= 50:
                out[sha256] = LookupResult(
                    "known_good", "Known file", f"Known software file ({source})", details
                )
            else:
                out[sha256] = LookupResult(
                    "clean", "Known file (low trust)", f"In {source}, trust {trust}", details
                )
        return out


class CymruProvider(Provider):
    """Team Cymru Malware Hash Registry, over its bulk whois interface: the share of
    antivirus engines that detect a hash."""

    name = "cymru"
    title = "Team Cymru Malware Hash Registry"
    daily_budget = 5000
    per_minute = 10
    batch_size = 200
    host = "hash.cymru.com"
    port = 43

    def lookup(self, hashes: list[Hashes]) -> dict[str, LookupResult]:
        query = "begin\n" + "".join(f"{h.sha256}\n" for h in hashes) + "end\n"
        try:
            with socket.create_connection((self.host, self.port), timeout=30) as sock:
                sock.sendall(query.encode())
                chunks = []
                while chunk := sock.recv(65536):
                    chunks.append(chunk)
        except OSError as exc:
            raise ProviderError(f"whois query failed: {exc}", timedelta(minutes=10)) from exc
        out = {h.sha256: LookupResult.not_found() for h in hashes}
        for line in b"".join(chunks).decode(errors="replace").splitlines():
            parts = line.split()
            if len(parts) != 3 or line.startswith("#"):
                continue
            sha256, _, rate = parts
            sha256 = sha256.lower()
            if sha256 not in out or not rate.isdigit():
                continue  # NO_DATA
            pct = int(rate)
            verdict = "malicious" if pct >= 25 else "suspicious" if pct > 0 else "clean"
            out[sha256] = LookupResult(
                verdict,
                "Malware Hash Registry",
                f"Detected by {pct}% of antivirus engines",
                {"detection_percent": pct, "last_seen": int(parts[1])},
            )
        return out


class MalwareBazaarProvider(Provider):
    name = "malwarebazaar"
    title = "MalwareBazaar (abuse.ch)"
    key_setting = "abusech_auth_key"
    daily_budget = 2000
    per_minute = 30
    link = "https://bazaar.abuse.ch/sample/{sha256}/"
    url = "https://mb-api.abuse.ch/api/v1/"

    def lookup(self, hashes: list[Hashes]) -> dict[str, LookupResult]:
        h = hashes[0]
        data = self._json(
            self._request(
                "POST",
                self.url,
                data={"query": "get_info", "hash": h.sha256},
                headers={"Auth-Key": self.key or ""},
            )
        )
        status = data.get("query_status") if isinstance(data, dict) else None
        if status in ("hash_not_found", "no_results"):
            return {h.sha256: LookupResult.not_found()}
        if status != "ok":
            raise ProviderError(f"query_status {status!r}", timedelta(minutes=30))
        info = (data.get("data") or [{}])[0]
        signature = info.get("signature")
        return {
            h.sha256: LookupResult(
                "malicious",
                signature or "MalwareBazaar sample",
                f"MalwareBazaar sample{f' ({signature})' if signature else ''}, "
                f"first seen {info.get('first_seen', '?')}",
                {
                    "signature": signature,
                    "file_type": info.get("file_type"),
                    "tags": info.get("tags"),
                    "first_seen": info.get("first_seen"),
                    "link": self.page(h.sha256),
                },
            )
        }


def _collect(obj, key: str, out: list[str]) -> list[str]:
    """Every string value under ``key``, anywhere in a nested JSON value."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and isinstance(v, str) and v:
                out.append(v)
            else:
                _collect(v, key, out)
    elif isinstance(obj, list):
        for v in obj:
            _collect(v, key, out)
    return out


class YaraifyProvider(Provider):
    """YARAify (abuse.ch): public YARA rules and ClamAV results for files others scanned."""

    name = "yaraify"
    title = "YARAify (abuse.ch)"
    key_setting = "abusech_auth_key"
    daily_budget = 2000
    per_minute = 30
    url = "https://yaraify-api.abuse.ch/api/v1/"

    def lookup(self, hashes: list[Hashes]) -> dict[str, LookupResult]:
        h = hashes[0]
        data = self._json(
            self._request(
                "POST",
                self.url,
                json={"query": "lookup_hash", "search_term": h.sha256},
                headers={"Auth-Key": self.key or ""},
            )
        )
        status = data.get("query_status") if isinstance(data, dict) else None
        if status in ("hash_not_found", "no_results", "not_found"):
            return {h.sha256: LookupResult.not_found()}
        if status != "ok":
            raise ProviderError(f"query_status {status!r}", timedelta(minutes=30))
        payload = data.get("data")
        rules = sorted(set(_collect(payload, "rule_name", [])))
        clam = sorted(set(_collect(payload, "clamav_results", []))) or sorted(
            {s for s in _collect(payload, "signature", []) if s}
        )
        if clam:
            return {
                h.sha256: LookupResult(
                    "suspicious",
                    clam[0][:200],
                    f"ClamAV results at YARAify: {', '.join(clam[:5])}",
                    {"clamav": clam[:20], "yara_rules": rules[:50]},
                )
            }
        if rules:
            return {
                h.sha256: LookupResult(
                    "info",
                    "YARAify rule matches",
                    f"{len(rules)} public YARA rules match: {', '.join(rules[:5])}",
                    {"yara_rules": rules[:50]},
                )
            }
        return {h.sha256: LookupResult("clean", details={"known": True})}


class VirusTotalProvider(Provider):
    """VirusTotal v3 file reports, looked up by hash; nothing is ever uploaded."""

    name = "virustotal"
    title = "VirusTotal"
    key_setting = "virustotal_api_key"
    daily_budget = 500
    per_minute = 4
    link = "https://www.virustotal.com/gui/file/{sha256}"
    url = "https://www.virustotal.com/api/v3/files/{sha256}"

    def lookup(self, hashes: list[Hashes]) -> dict[str, LookupResult]:
        h = hashes[0]
        response = self._request(
            "GET", self.url.format(sha256=h.sha256), headers={"x-apikey": self.key or ""}
        )
        if response.status_code == 404:
            return {h.sha256: LookupResult.not_found()}
        attrs = (self._json(response).get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(
            int(stats.get(k, 0)) for k in ("malicious", "suspicious", "undetected", "harmless")
        )
        label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
        if malicious >= 5:
            verdict = "malicious"
        elif malicious >= 1 or suspicious >= 3:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return {
            h.sha256: LookupResult(
                verdict,
                label or "VirusTotal detections",
                f"{malicious}/{total} engines detect it"
                + (f", {suspicious} call it suspicious" if suspicious else ""),
                {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total": total,
                    "label": label,
                    "names": (attrs.get("names") or [])[:5],
                    "link": self.page(h.sha256),
                },
            )
        }


class HybridAnalysisProvider(Provider):
    name = "hybrid-analysis"
    title = "Hybrid Analysis"
    key_setting = "hybrid_analysis_api_key"
    daily_budget = 5000
    per_minute = 20
    link = "https://www.hybrid-analysis.com/sample/{sha256}"
    url = "https://www.hybrid-analysis.com/api/v2/overview/{sha256}"

    def lookup(self, hashes: list[Hashes]) -> dict[str, LookupResult]:
        h = hashes[0]
        response = self._request(
            "GET",
            self.url.format(sha256=h.sha256),
            headers={
                "api-key": self.key or "",
                "User-Agent": "Falcon Sandbox",
                "accept": "application/json",
            },
        )
        if response.status_code == 404:
            return {h.sha256: LookupResult.not_found()}
        data = self._json(response)
        verdict_text = str(data.get("verdict") or "").lower()
        family = data.get("vx_family")
        score = data.get("threat_score")
        verdict = {
            "malicious": "malicious",
            "suspicious": "suspicious",
            "whitelisted": "clean",
            "no specific threat": "clean",
        }.get(verdict_text, "clean" if verdict_text else "not_found")
        return {
            h.sha256: LookupResult(
                verdict,
                family or "Hybrid Analysis verdict",
                f"Sandbox verdict: {verdict_text or 'none'}"
                + (f", threat score {score}" if score is not None else ""),
                {
                    "verdict": verdict_text,
                    "threat_score": score,
                    "family": family,
                    "link": self.page(h.sha256),
                },
            )
        }


class MetaDefenderProvider(Provider):
    name = "metadefender"
    title = "MetaDefender Cloud (OPSWAT)"
    key_setting = "metadefender_api_key"
    daily_budget = 2000
    per_minute = 20
    url = "https://api.metadefender.com/v4/hash/{sha256}"

    def lookup(self, hashes: list[Hashes]) -> dict[str, LookupResult]:
        h = hashes[0]
        response = self._request(
            "GET", self.url.format(sha256=h.sha256), headers={"apikey": self.key or ""}
        )
        if response.status_code == 404:
            return {h.sha256: LookupResult.not_found()}
        results = self._json(response).get("scan_results") or {}
        detected = int(results.get("total_detected_avs") or 0)
        total = int(results.get("total_avs") or 0)
        threats = Counter(
            d.get("threat_found")
            for d in (results.get("scan_details") or {}).values()
            if isinstance(d, dict) and d.get("threat_found")
        )
        name = threats.most_common(1)[0][0] if threats else None
        verdict = "malicious" if detected >= 3 else "suspicious" if detected else "clean"
        return {
            h.sha256: LookupResult(
                verdict,
                name or "MetaDefender detections",
                f"{detected}/{total} engines detect it",
                {"detected": detected, "total": total, "threats": dict(threats.most_common(5))},
            )
        }


class OtxProvider(Provider):
    """AlienVault OTX: community threat reports ("pulses") that mention the hash."""

    name = "otx"
    title = "AlienVault OTX"
    key_setting = "otx_api_key"
    daily_budget = 10000
    per_minute = 30
    link = "https://otx.alienvault.com/indicator/file/{sha256}"
    url = "https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general"

    def lookup(self, hashes: list[Hashes]) -> dict[str, LookupResult]:
        h = hashes[0]
        response = self._request(
            "GET", self.url.format(sha256=h.sha256), headers={"X-OTX-API-KEY": self.key or ""}
        )
        if response.status_code == 404:
            return {h.sha256: LookupResult.not_found()}
        pulses = (self._json(response).get("pulse_info") or {}).get("pulses") or []
        if not pulses:
            return {h.sha256: LookupResult.not_found()}
        families = sorted(set(_collect(pulses, "display_name", [])))
        return {
            h.sha256: LookupResult(
                "suspicious",
                families[0] if families else "OTX pulses",
                f"Mentioned in {len(pulses)} OTX pulses"
                + (f" ({', '.join(families[:3])})" if families else ""),
                {
                    "pulses": [p.get("name") for p in pulses[:10]],
                    "families": families[:10],
                    "link": self.page(h.sha256),
                },
            )
        }


class OpenTipProvider(Provider):
    name = "opentip"
    title = "Kaspersky OpenTIP"
    key_setting = "opentip_api_key"
    daily_budget = 1000
    per_minute = 10
    link = "https://opentip.kaspersky.com/{sha256}/"
    url = "https://opentip.kaspersky.com/api/v1/search/hash"

    def lookup(self, hashes: list[Hashes]) -> dict[str, LookupResult]:
        h = hashes[0]
        response = self._request(
            "GET", self.url, params={"request": h.sha256}, headers={"x-api-key": self.key or ""}
        )
        if response.status_code == 404:
            return {h.sha256: LookupResult.not_found()}
        data = self._json(response)
        zone = str(data.get("Zone") or "").lower()
        status = (data.get("FileGeneralInfo") or {}).get("FileStatus")
        detections = [
            d.get("DetectionName") for d in data.get("DetectionsInfo") or [] if isinstance(d, dict)
        ]
        verdict = {"red": "malicious", "yellow": "suspicious", "green": "clean"}.get(
            zone, "not_found"
        )
        return {
            h.sha256: LookupResult(
                verdict,
                (detections[0] if detections and detections[0] else None)
                or status
                or "OpenTIP verdict",
                f"Kaspersky zone {zone or 'unknown'}" + (f", status {status}" if status else ""),
                {
                    "zone": zone,
                    "status": status,
                    "detections": detections[:10],
                    "link": self.page(h.sha256),
                },
            )
        }


# Order matters only for the UI; CIRCL's known-good answers gate the rest.
PROVIDER_TYPES: list[type[Provider]] = [
    CirclProvider,
    CymruProvider,
    MalwareBazaarProvider,
    YaraifyProvider,
    VirusTotalProvider,
    HybridAnalysisProvider,
    MetaDefenderProvider,
    OtxProvider,
    OpenTipProvider,
]
