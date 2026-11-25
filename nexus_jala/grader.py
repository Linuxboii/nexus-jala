"""Run all checks and turn the result into a letter grade."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import checks
from .headers import HeaderSet

GRADE_STEPS = [(95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D")]
GRADE_ORDER = ["F", "D", "C", "B", "A", "A+"]


def letter_grade(percent: float) -> str:
    for threshold, letter in GRADE_STEPS:
        if percent >= threshold:
            return letter
    return "F"


def grade_at_least(grade: str, minimum: str) -> bool:
    return GRADE_ORDER.index(grade) >= GRADE_ORDER.index(minimum)


@dataclass
class Report:
    target: str
    https: bool
    status: int | None
    findings: list[checks.Finding] = field(default_factory=list)
    final_url: str | None = None

    @property
    def score(self) -> int:
        return sum(f.score for f in self.findings)

    @property
    def max_score(self) -> int:
        return sum(f.max_score for f in self.findings)

    @property
    def percent(self) -> int:
        return round(100 * self.score / self.max_score) if self.max_score else 0

    @property
    def grade(self) -> str:
        return letter_grade(self.percent)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "final_url": self.final_url,
            "https": self.https,
            "status": self.status,
            "grade": self.grade,
            "score": self.score,
            "max_score": self.max_score,
            "percent": self.percent,
            "findings": [f.to_dict() for f in self.findings],
        }


def audit(headers: HeaderSet, target: str, https: bool, status: int | None = None,
          final_url: str | None = None) -> Report:
    findings = [
        checks.check_csp(headers),
        checks.check_hsts(headers, https=https),
        checks.check_xfo(headers),
        checks.check_xcto(headers),
        checks.check_referrer(headers),
        checks.check_permissions(headers),
        checks.check_coop(headers),
        checks.check_coep(headers),
        checks.check_cookies(headers, https=https),
        checks.check_leaks(headers),
    ]
    cors = checks.check_cors(headers)
    if cors is not None:
        findings.append(cors)
    return Report(target=target, https=https, status=status, findings=findings, final_url=final_url)
