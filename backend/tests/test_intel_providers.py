"""Threat-intel providers, feed parsing and lookup priority, against canned responses."""

import json
import socket
import threading
import zipfile
from datetime import timedelta

import httpx
import pytest

from nasscan.config import get_settings
from nasscan.intel import priority as prio
from nasscan.intel.base import Hashes, ProviderError
from nasscan.intel.feeds import (
    MalwareBazaarFeed,
    UrlFeed,
    VirusShareFeed,
    all_feeds,
    feed_listed,
    parse_hashes,
    text_lines,
)
from nasscan.intel.lookups import (
    CirclProvider,
    CymruProvider,
    HybridAnalysisProvider,
    MalwareBazaarProvider,
    MetaDefenderProvider,
    OpenTipProvider,
    OtxProvider,
    VirusTotalProvider,
    YaraifyProvider,
)
from nasscan.scanner.engines.base import Finding

EICAR = Hashes(
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "3395856ce81f2b7382dee72602f798b642f14140",
    "44d88612fea8a8f36de82e1278abb02f",
)
OTHER = Hashes("ab" * 32, "cd" * 20, "ef" * 16)


def settings(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(f"NASSCAN_{k.upper()}", v)
    get_settings.cache_clear()
    return get_settings()


def client(handler) -> tuple[httpx.Client, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    return httpx.Client(transport=httpx.MockTransport(wrapped)), seen


# --- framework -------------------------------------------------------------------------------


def test_providers_without_keys_are_off_and_keyless_ones_on(monkeypatch):
    s = settings(monkeypatch)
    assert CirclProvider(s).enabled() and CymruProvider(s).enabled()
    vt = VirusTotalProvider(s)
    assert not vt.enabled() and "NASSCAN_VIRUSTOTAL_API_KEY" in vt.disabled_reason()
    s = settings(monkeypatch, virustotal_api_key="k", intel_disabled="circl")
    assert VirusTotalProvider(s).enabled() and not CirclProvider(s).enabled()
    s = settings(monkeypatch, intel_lookups="false")
    assert not CymruProvider(s).enabled()


def test_limits_can_be_overridden(monkeypatch):
    s = settings(monkeypatch, virustotal_api_key="k", intel_limits="virustotal=1000/30,cymru=/2")
    vt = VirusTotalProvider(s)
    assert (vt.daily_budget, vt.per_minute) == (1000, 30)
    cymru = CymruProvider(s)
    assert (cymru.daily_budget, cymru.per_minute) == (5000, 2)


@pytest.mark.parametrize(
    ("status", "pause"),
    [(429, timedelta(minutes=15)), (401, timedelta(hours=6)), (503, timedelta(minutes=10))],
)
def test_http_failures_pause_the_provider(monkeypatch, status, pause):
    c, _ = client(lambda r: httpx.Response(status))
    vt = VirusTotalProvider(settings(monkeypatch, virustotal_api_key="k"), client=c)
    with pytest.raises(ProviderError) as err:
        vt.lookup([EICAR])
    assert err.value.pause == pause


def test_retry_after_is_honoured(monkeypatch):
    c, _ = client(lambda r: httpx.Response(429, headers={"Retry-After": "120"}))
    vt = VirusTotalProvider(settings(monkeypatch, virustotal_api_key="k"), client=c)
    with pytest.raises(ProviderError) as err:
        vt.lookup([EICAR])
    assert err.value.pause == timedelta(seconds=120)


# --- providers ------------------------------------------------------------------------------


def test_circl_known_good_known_malicious_and_unknown(monkeypatch):
    def handler(request):
        body = json.loads(request.content)
        assert set(body["hashes"]) == {EICAR.sha1.upper(), OTHER.sha1.upper()}
        return httpx.Response(
            200,
            json=[
                {
                    "SHA-1": EICAR.sha1.upper(),
                    "KnownMalicious": "malshare.com",
                    "hashlookup:trust": 100,
                    "FileName": "eicar.com",
                },
            ],
        )

    c, seen = client(handler)
    out = CirclProvider(settings(monkeypatch), client=c).lookup([EICAR, OTHER])
    assert seen[0].url.path == "/bulk/sha1"
    assert out[EICAR.sha256].verdict == "suspicious"
    assert "malshare.com" in out[EICAR.sha256].description
    assert out[OTHER.sha256].verdict == "not_found"

    c, _ = client(
        lambda r: httpx.Response(200, json=[{"SHA-1": OTHER.sha1.upper(), "hashlookup:trust": 100}])
    )
    out = CirclProvider(settings(monkeypatch), client=c).lookup([OTHER])
    assert out[OTHER.sha256].verdict == "known_good"


def test_cymru_bulk_whois(monkeypatch):
    server = socket.create_server(("127.0.0.1", 0))
    received = []

    def serve():
        conn, _ = server.accept()
        with conn:
            data = b""
            while not data.endswith(b"end\n"):
                data += conn.recv(4096)
            received.append(data.decode())
            conn.sendall(
                b"# Bulk Mode; hash.cymru.com\n"
                + f"{EICAR.sha256} 1795376675 100\n{OTHER.sha256} 1795395024 NO_DATA\n".encode()
            )

    t = threading.Thread(target=serve)
    t.start()
    p = CymruProvider(settings(monkeypatch))
    p.host, p.port = "127.0.0.1", server.getsockname()[1]
    out = p.lookup([EICAR, OTHER])
    t.join()
    server.close()
    assert received[0] == f"begin\n{EICAR.sha256}\n{OTHER.sha256}\nend\n"
    assert out[EICAR.sha256].verdict == "malicious"
    assert out[EICAR.sha256].details["detection_percent"] == 100
    assert out[OTHER.sha256].verdict == "not_found"


def test_cymru_unreachable_is_a_provider_error(monkeypatch):
    p = CymruProvider(settings(monkeypatch))
    p.host, p.port = "127.0.0.1", 1  # nothing listens there
    with pytest.raises(ProviderError):
        p.lookup([EICAR])


def test_malwarebazaar(monkeypatch):
    def handler(request):
        assert request.headers["Auth-Key"] == "abc"
        if EICAR.sha256 in request.content.decode():
            return httpx.Response(
                200,
                json={
                    "query_status": "ok",
                    "data": [
                        {"signature": "AgentTesla", "file_type": "exe", "first_seen": "2026-01-01"}
                    ],
                },
            )
        return httpx.Response(200, json={"query_status": "hash_not_found"})

    c, _ = client(handler)
    p = MalwareBazaarProvider(settings(monkeypatch, abusech_auth_key="abc"), client=c)
    hit = p.lookup([EICAR])[EICAR.sha256]
    assert (hit.verdict, hit.name) == ("malicious", "AgentTesla")
    assert hit.details["link"].endswith(f"/sample/{EICAR.sha256}/")
    assert p.lookup([OTHER])[OTHER.sha256].verdict == "not_found"

    c, _ = client(lambda r: httpx.Response(200, json={"query_status": "unknown_auth_key"}))
    with pytest.raises(ProviderError):
        MalwareBazaarProvider(settings(monkeypatch, abusech_auth_key="x"), client=c).lookup([EICAR])


def test_yaraify(monkeypatch):
    c, _ = client(
        lambda r: httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": {
                    "tasks": [
                        {
                            "static_results": [
                                {"rule_name": "SUSP_Packer"},
                                {"rule_name": "Base64"},
                            ],
                            "clamav_results": [],
                        }
                    ]
                },
            },
        )
    )
    out = YaraifyProvider(settings(monkeypatch, abusech_auth_key="k"), client=c).lookup([EICAR])
    r = out[EICAR.sha256]
    assert r.verdict == "info" and r.details["yara_rules"] == ["Base64", "SUSP_Packer"]


def test_virustotal_thresholds(monkeypatch):
    stats = {"malicious": 0, "suspicious": 0, "undetected": 60, "harmless": 0}

    def handler(request):
        if OTHER.sha256 in str(request.url):
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
        assert request.headers["x-apikey"] == "k"
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": stats,
                        "popular_threat_classification": {
                            "suggested_threat_label": "trojan.eicar/test"
                        },
                    }
                }
            },
        )

    c, _ = client(handler)
    vt = VirusTotalProvider(settings(monkeypatch, virustotal_api_key="k"), client=c)
    assert vt.lookup([OTHER])[OTHER.sha256].verdict == "not_found"
    assert vt.lookup([EICAR])[EICAR.sha256].verdict == "clean"
    stats["malicious"] = 2
    r = vt.lookup([EICAR])[EICAR.sha256]
    assert r.verdict == "suspicious" and r.description == "2/62 engines detect it"
    stats["malicious"] = 50
    r = vt.lookup([EICAR])[EICAR.sha256]
    assert (r.verdict, r.name) == ("malicious", "trojan.eicar/test")
    assert r.details["link"] == f"https://www.virustotal.com/gui/file/{EICAR.sha256}"


def test_hybrid_metadefender_otx_opentip(monkeypatch):
    s = settings(
        monkeypatch,
        hybrid_analysis_api_key="k",
        metadefender_api_key="k",
        otx_api_key="k",
        opentip_api_key="k",
    )
    c, _ = client(
        lambda r: httpx.Response(
            200, json={"verdict": "malicious", "threat_score": 100, "vx_family": "EICAR"}
        )
    )
    r = HybridAnalysisProvider(s, client=c).lookup([EICAR])[EICAR.sha256]
    assert (r.verdict, r.name) == ("malicious", "EICAR")

    c, _ = client(
        lambda r: httpx.Response(
            200,
            json={
                "scan_results": {
                    "total_detected_avs": 2,
                    "total_avs": 20,
                    "scan_details": {
                        "A": {"threat_found": "EICAR-Test"},
                        "B": {"threat_found": ""},
                    },
                }
            },
        )
    )
    r = MetaDefenderProvider(s, client=c).lookup([EICAR])[EICAR.sha256]
    assert (r.verdict, r.name, r.description) == (
        "suspicious",
        "EICAR-Test",
        "2/20 engines detect it",
    )

    c, _ = client(lambda r: httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}}))
    assert OtxProvider(s, client=c).lookup([OTHER])[OTHER.sha256].verdict == "not_found"
    c, _ = client(
        lambda r: httpx.Response(
            200,
            json={
                "pulse_info": {
                    "pulses": [
                        {"name": "Campaign", "malware_families": [{"display_name": "Emotet"}]}
                    ]
                }
            },
        )
    )
    r = OtxProvider(s, client=c).lookup([EICAR])[EICAR.sha256]
    assert (r.verdict, r.name) == ("suspicious", "Emotet")

    c, seen = client(
        lambda r: httpx.Response(
            200,
            json={
                "Zone": "Red",
                "FileGeneralInfo": {"FileStatus": "Malware"},
                "DetectionsInfo": [{"DetectionName": "EICAR-Test-File"}],
            },
        )
    )
    r = OpenTipProvider(s, client=c).lookup([EICAR])[EICAR.sha256]
    assert (r.verdict, r.name) == ("malicious", "EICAR-Test-File")
    assert seen[0].url.params["request"] == EICAR.sha256


def test_only_hashes_are_sent(monkeypatch):
    """Every provider request carries the hash and nothing about the file."""
    s = settings(monkeypatch, virustotal_api_key="k", abusech_auth_key="k")
    c, seen = client(lambda r: httpx.Response(404))
    VirusTotalProvider(s, client=c).lookup([EICAR])
    c2, seen2 = client(lambda r: httpx.Response(200, json={"query_status": "hash_not_found"}))
    MalwareBazaarProvider(s, client=c2).lookup([EICAR])
    for request in seen + seen2:
        assert request.method in ("GET", "POST")
        assert len(request.content) < 200  # a hash and a query name, never file bytes


# --- feeds ----------------------------------------------------------------------------------

BAZAAR_CSV = f"""################################################################
# MalwareBazaar full data dump (CSV)                           #
################################################################
#
# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"
"2026-11-22 10:00:00", "{EICAR.sha256}", "{EICAR.md5}", "{EICAR.sha1}", "someone", "x.exe", "exe", "application/x-dosexec", "AgentTesla", "n/a", "n/a", "n/a", "n/a", "n/a"
"2026-11-22 11:00:00", "{OTHER.sha256}", "{OTHER.md5}", "{OTHER.sha1}", "someone", "y.exe", "exe", "application/x-dosexec", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a"
#
"""  # noqa: E501

THREATFOX_CSV = f"""# ThreatFox IOCs: CSV export
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","reference","tags","anonymous","reporter"
"2026-11-01 00:00:00","1","{EICAR.md5}","md5_hash","payload","win.x","","Cobalt Strike","","100","","","0","r"
"2026-11-01 00:00:00","2","http://{OTHER.sha256}.example/","url","payload_delivery","win.x","","Cobalt Strike","","100","","","0","r"
"2026-11-01 00:00:00","3","{OTHER.sha256}","sha256_hash","payload","win.y","","Emotet","","100","","","0","r"
"""  # noqa: E501


def test_parse_malwarebazaar_csv():
    rows = list(parse_hashes(iter(BAZAAR_CSV.splitlines())))
    by_hash = {h.hex(): n for h, n in rows}
    assert by_hash[EICAR.sha256] == by_hash[EICAR.md5] == "AgentTesla"
    assert by_hash[OTHER.sha256] is None  # "n/a"
    assert len(rows) == 6  # sha256, sha1, md5 of each


def test_parse_threatfox_uses_only_hash_iocs():
    rows = {h.hex(): n for h, n in parse_hashes(iter(THREATFOX_CSV.splitlines()))}
    assert rows == {EICAR.md5: "Cobalt Strike", OTHER.sha256: "Emotet"}


def test_parse_plain_list_and_zip(tmp_path):
    text = f"# VirusShare list\n{EICAR.md5}\n{OTHER.md5.upper()}\nnot-a-hash\n"
    rows = list(parse_hashes(iter(text.splitlines())))
    assert [h.hex() for h, _ in rows] == [EICAR.md5, OTHER.md5]
    path = tmp_path / "f.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("full.csv", BAZAAR_CSV)
    assert len(list(parse_hashes(text_lines(path)))) == 6


def test_feed_selection(monkeypatch):
    s = settings(monkeypatch, intel_extra_feeds="mine=https://example.com/{abusech_key}/h.txt")
    feeds = {f.name: f for f in all_feeds(s)}
    assert set(feeds) == {"malwarebazaar-feed", "threatfox-feed", "virusshare-feed", "mine-feed"}
    assert feeds["malwarebazaar-feed"].disabled_reason()  # no abuse.ch key
    assert feeds["virusshare-feed"].disabled_reason() is None
    assert feeds["mine-feed"].disabled_reason()  # its URL needs the key
    s = settings(monkeypatch, intel_feeds="virusshare", abusech_auth_key="k")
    feeds = {f.name: f for f in all_feeds(s)}
    assert not feed_listed(s, feeds["malwarebazaar-feed"])
    assert feed_listed(s, feeds["virusshare-feed"])


def test_malwarebazaar_full_then_recent(monkeypatch):
    feed = MalwareBazaarFeed(settings(monkeypatch, abusech_auth_key="KEY"))
    state: dict = {}
    first = feed.downloads(state, httpx.Client())
    assert [(d.url, d.replace) for d in first] == [
        ("https://mb-api.abuse.ch/v2/files/exports/KEY/full.csv.zip", True)
    ]
    assert "KEY" not in first[0].label
    feed.after_import(state, first[0])
    assert [d.label for d in feed.downloads(state, httpx.Client())] == ["recent.csv"]


def test_virusshare_fetches_new_lists_and_the_newest(monkeypatch):
    page = "".join(f'<a href="hashfiles/VirusShare_{n:05d}.md5">x</a>' for n in range(0, 512))
    c, _ = client(lambda r: httpx.Response(200, text=page))
    feed = VirusShareFeed(settings(monkeypatch, virusshare_lists="3"))
    state: dict = {}
    downloads = feed.downloads(state, c)
    assert [d.label for d in downloads] == [f"VirusShare_{n:05d}.md5" for n in (509, 510, 511)]
    for d in downloads:
        feed.after_import(state, d)
    assert state["lists"] == [509, 510, 511]
    assert [d.label for d in feed.downloads(state, c)] == ["VirusShare_00511.md5"]


def test_custom_feed_hides_the_key_in_labels(monkeypatch):
    s = settings(monkeypatch, abusech_auth_key="SECRET")
    feed = UrlFeed(
        s, "payloads", "https://urlhaus-api.abuse.ch/v2/files/exports/{abusech_key}/p.zip"
    )
    (d,) = feed.downloads({}, httpx.Client())
    assert "SECRET" in d.url and "SECRET" not in d.label


# --- priority -------------------------------------------------------------------------------


def finding(engine, severity, name="x", description=""):
    return Finding(engine=engine, name=name, severity=severity, description=description)


@pytest.mark.parametrize(
    ("ext", "mime", "findings", "expected"),
    [
        ("mkv", "video/x-matroska", [], prio.NONE),
        ("jpg", "image/jpeg", [], prio.NONE),
        ("3mf", "application/zip", [], prio.NONE),
        ("docx", "application/zip", [], prio.NONE),
        ("exe", "application/x-dosexec", [], prio.EXECUTABLE),
        ("txt", "application/x-dosexec", [], prio.EXECUTABLE),
        ("ps1", "text/plain", [], prio.SCRIPT),
        ("xlsm", "application/vnd.ms-excel", [], prio.MACRO_FORMAT),
        ("zip", "application/zip", [], prio.ARCHIVE),
        ("bin", "application/x-7z-compressed", [], prio.ARCHIVE),
        ("pdf", "application/pdf", [], prio.PDF),
        ("mkv", "video/x-matroska", [finding("clamav", "malicious")], prio.LOCALLY_MALICIOUS),
        ("exe", None, [finding("heuristics", "suspicious")], prio.DISGUISED),
        ("docm", None, [finding("documents", "info", "VBA macros")], prio.MACROS),
        ("txt", None, [finding("yara", "info")], prio.LOCAL_INFO),
    ],
)
def test_priority(ext, mime, findings, expected):
    assert prio.priority_for(ext, mime, findings) == expected


def test_dropped_downloads_are_retried(tmp_path):
    from nasscan.intel.feeds import Download, FeedError, fetch

    calls = []

    def handler(request):
        calls.append(1)
        if len(calls) < 3:
            raise httpx.RemoteProtocolError("peer closed connection", request=request)
        return httpx.Response(200, content=b"hashes")

    c, _ = client(handler)
    d = Download("https://example.com/k/full.csv.zip", True, "full.csv.zip")
    assert fetch(c, d, tmp_path / "f", wait=0).read_bytes() == b"hashes"
    assert len(calls) == 3
    calls.clear()
    c, _ = client(lambda r: (_ for _ in ()).throw(httpx.RemoteProtocolError("cut", request=r)))
    with pytest.raises(FeedError, match="tried 3 times") as err:
        fetch(c, d, tmp_path / "f", wait=0)
    assert "example.com" not in str(err.value)  # never the URL, which may hold a key
    c, _ = client(lambda r: httpx.Response(404))
    with pytest.raises(FeedError, match="HTTP 404"):
        fetch(c, d, tmp_path / "f", wait=0)


def test_dropped_downloads_resume_where_they_stopped(tmp_path):
    from nasscan.intel.feeds import Download, fetch

    data = bytes(range(256)) * 40
    ranges = []

    def handler(request):
        rng = request.headers.get("range")
        ranges.append(rng)
        start = int(rng.removeprefix("bytes=").rstrip("-")) if rng else 0
        part = data[start : start + 3000]

        def body():
            yield part
            if start + len(part) < len(data):
                raise httpx.RemoteProtocolError("peer closed connection", request=request)

        status = 206 if rng else 200
        return httpx.Response(status, content=body())

    c, _ = client(handler)
    d = Download("https://example.com/k/full.csv.zip", True, "full.csv.zip")
    # Four cuts, each after progress: more than `attempts`, still fine.
    assert fetch(c, d, tmp_path / "f", wait=0).read_bytes() == data
    assert ranges == [None, "bytes=3000-", "bytes=6000-", "bytes=9000-"]

    # A server that ignores the Range header gets the file from the start again.
    ignored = []

    def no_ranges(request):
        ignored.append(1)
        if len(ignored) == 1:

            def cut():
                yield data[:100]
                raise httpx.RemoteProtocolError("cut", request=request)

            return httpx.Response(200, content=cut())
        return httpx.Response(200, content=data)

    c, _ = client(no_ranges)
    assert fetch(c, d, tmp_path / "g", wait=0).read_bytes() == data


def test_malwarebazaar_falls_back_to_recent(monkeypatch):
    feed = MalwareBazaarFeed(settings(monkeypatch, abusech_auth_key="KEY"))
    (full,) = feed.downloads({}, httpx.Client())
    smaller = feed.fallback(full)
    assert smaller.label == "recent.csv" and not smaller.replace
    assert feed.fallback(smaller) is None


def test_http_request_logs_are_quiet():
    import logging

    from nasscan.cli import quiet_http_logs

    quiet_http_logs()
    assert not logging.getLogger("httpx").isEnabledFor(logging.INFO)
