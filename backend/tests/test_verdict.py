"""Verdict scoring for representative evidence combinations."""

import pytest

from nasscan.config import Settings
from nasscan.verdict import Evidence, Scoring, judge

DEFAULT = Scoring()


def ev(engine, severity, name="x", **kw):
    return Evidence(engine=engine, name=name, severity=severity, **kw)


def test_nothing_is_clean():
    v = judge([], DEFAULT)
    assert (v.verdict, v.score, v.evidence) == ("clean", 0, [])


def test_one_antivirus_hit_is_malicious():
    v = judge([ev("clamav", "malicious", "Eicar-Signature")], DEFAULT)
    assert (v.verdict, v.score) == ("malicious", 100)


def test_a_feed_listing_is_malicious():
    v = judge([ev("malwarebazaar-feed", "malicious", "AgentTesla")], DEFAULT)
    assert v.verdict == "malicious"


def test_one_heuristic_is_suspicious():
    v = judge([ev("heuristics", "suspicious", "double-extension")], DEFAULT)
    assert (v.verdict, v.score) == ("suspicious", 40)


def test_info_alone_stays_clean():
    v = judge([ev("documents", "info", "pdf-has-javascript"), ev("yara", "info")], DEFAULT)
    assert (v.verdict, v.score) == ("clean", 10)


def test_many_hits_from_one_engine_count_once():
    v = judge([ev("yara", "suspicious", f"rule{i}") for i in range(10)], DEFAULT)
    assert (v.verdict, v.score) == ("suspicious", 40)
    assert [e["points"] for e in v.evidence].count(40) == 1


def test_engines_agreeing_add_up_to_malicious():
    two = [ev("heuristics", "suspicious"), ev("yara", "suspicious")]
    assert judge(two, DEFAULT).verdict == "suspicious"
    three = [*two, ev("otx", "suspicious")]
    v = judge(three, DEFAULT)
    assert (v.verdict, v.score) == ("malicious", 120)


def test_an_engines_most_severe_detection_counts():
    v = judge([ev("yara", "info", "a"), ev("yara", "malicious", "b")], DEFAULT)
    assert v.score == 100
    assert v.evidence[0]["name"] == "b"


def test_weights_scale_an_engine():
    scoring = Scoring(weights={"heuristics": 0.5, "virustotal": 1.5})
    assert judge([ev("heuristics", "suspicious")], scoring).verdict == "clean"
    v = judge([ev("virustotal", "suspicious"), ev("heuristics", "suspicious")], scoring)
    assert (v.verdict, v.score) == ("suspicious", 80)


def test_known_good_softens_suspicious_but_not_malicious():
    weak = [ev("heuristics", "suspicious")]
    v = judge(weak, DEFAULT, known_good=True)
    assert (v.verdict, v.score) == ("clean", 20)
    assert v.evidence[-1]["engine"] == "known-good"
    strong = [ev("clamav", "malicious")]
    assert judge(strong, DEFAULT, known_good=True).score == 100


def test_thresholds_are_configurable():
    strict = Scoring(suspicious_score=10, malicious_score=40)
    assert judge([ev("yara", "info"), ev("documents", "info")], strict).verdict == "suspicious"
    assert judge([ev("heuristics", "suspicious")], strict).verdict == "malicious"


def test_evidence_carries_links_and_members():
    v = judge(
        [ev("virustotal", "malicious", "trojan", link="https://example/vt", member="a.exe")],
        DEFAULT,
    )
    assert v.evidence[0] | {} == {
        "engine": "virustotal",
        "name": "trojan",
        "member": "a.exe",
        "severity": "malicious",
        "description": None,
        "link": "https://example/vt",
        "points": 100,
    }


def test_settings_parse_weights_and_thresholds():
    s = Settings(
        verdict_weights="Heuristics=0.5, virustotal=2,bad=x,neg=-1,=3",
        verdict_suspicious_score=30,
        verdict_malicious_score=90,
    )
    scoring = Scoring.from_settings(s)
    assert scoring.weights == {"heuristics": 0.5, "virustotal": 2.0}
    assert (scoring.suspicious_score, scoring.malicious_score) == (30, 90)


def test_malicious_threshold_must_not_be_below_suspicious():
    with pytest.raises(ValueError):
        Settings(verdict_suspicious_score=80, verdict_malicious_score=50)
