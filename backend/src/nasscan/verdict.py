"""Turn a file's detections into one verdict: clean, suspicious or malicious, with a score.

Each engine or provider counts once, with the points of its most severe detection times its
weight. One engine with many matching rules is still one opinion; separate engines agreeing
add up. See docs/verdicts.md.
"""

from collections.abc import Iterable
from dataclasses import dataclass, field

from nasscan.config import Settings

POINTS = {"malicious": 100, "suspicious": 40, "info": 5}
RANK = {"clean": 0, "suspicious": 1, "malicious": 2}
# Evidence kept per finding; a YARA-heavy archive can match hundreds of rules.
MAX_EVIDENCE = 50


@dataclass(frozen=True)
class Evidence:
    engine: str
    name: str
    severity: str
    member: str = ""
    description: str | None = None
    link: str | None = None


@dataclass
class Verdict:
    verdict: str
    score: int
    evidence: list[dict] = field(default_factory=list)


@dataclass(frozen=True)
class Scoring:
    suspicious_score: int = 40
    malicious_score: int = 100
    known_good_factor: float = 0.5
    weights: dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_settings(cls, settings: Settings) -> "Scoring":
        return cls(
            suspicious_score=settings.verdict_suspicious_score,
            malicious_score=settings.verdict_malicious_score,
            known_good_factor=settings.verdict_known_good_factor,
            weights=settings.verdict_weight_overrides,
        )

    def weight(self, engine: str) -> float:
        return self.weights.get(engine, 1.0)


def judge(items: Iterable[Evidence], scoring: Scoring, known_good: bool = False) -> Verdict:
    items = sorted(items, key=lambda e: (-POINTS.get(e.severity, 0), e.engine, e.member, e.name))
    best: dict[str, float] = {}
    evidence = []
    for e in items:
        points = POINTS.get(e.severity, 0) * scoring.weight(e.engine)
        counted = e.engine not in best
        if counted:
            best[e.engine] = points
        if len(evidence) < MAX_EVIDENCE:
            evidence.append(
                {
                    "engine": e.engine,
                    "name": e.name,
                    "member": e.member,
                    "severity": e.severity,
                    "description": e.description,
                    "link": e.link,
                    # Only each engine's top detection adds to the score.
                    "points": round(points, 1) if counted else 0,
                }
            )
    total = sum(best.values())
    malicious_seen = any(e.severity == "malicious" for e in items)
    if known_good and not malicious_seen and total:
        total *= scoring.known_good_factor
        evidence.append(
            {
                "engine": "known-good",
                "name": "Known good",
                "member": "",
                "severity": "info",
                "description": "On a known-good list (NSRL); score multiplied by "
                f"{scoring.known_good_factor:g}",
                "link": None,
                "points": 0,
            }
        )
    score = round(total)
    if score >= scoring.malicious_score:
        verdict = "malicious"
    elif score >= scoring.suspicious_score:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return Verdict(verdict, score, evidence)
