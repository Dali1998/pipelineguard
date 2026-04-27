from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IssueCategory(str, Enum):
    SECRET = "secret"
    DOCKER = "docker"
    PERMISSIONS = "permissions"
    ISOLATION = "isolation"
    SUPPLY_CHAIN = "supply_chain"
    MISCONFIGURATION = "misconfiguration"


@dataclass
class Issue:
    """A single security finding produced by a rule."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    category: IssueCategory

    # Location context
    source_file: str
    job_name: str | None = None
    line_number: int | None = None

    # Extra detail
    evidence: str | None = None          # redacted snippet that triggered the rule
    remediation: str | None = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "source_file": self.source_file,
            "job_name": self.job_name,
            "line_number": self.line_number,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
        }

    def __repr__(self) -> str:
        return (
            f"Issue(rule={self.rule_id}, severity={self.severity.value}, "
            f"job={self.job_name!r})"
        )
