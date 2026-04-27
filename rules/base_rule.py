"""Abstract base class every rule must implement."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipelineguard.models import Issue, Pipeline


class BaseRule(ABC):
    """
    Interface for all PipelineGuard security rules.

    Each subclass must declare:
      - rule_id  : unique kebab-case identifier  e.g. "SEC-001"
      - title    : short human-readable title
      - severity : default Severity for findings
      - category : IssueCategory for findings
    """

    rule_id: str
    title: str

    @abstractmethod
    def check(self, pipeline: "Pipeline") -> list["Issue"]:
        """
        Analyse the pipeline and return a (possibly empty) list of Issues.
        Rules MUST NOT raise exceptions; catch internally and return [].
        """

    # ------------------------------------------------------------------
    # Optional hooks – override when needed
    # ------------------------------------------------------------------

    def enabled(self) -> bool:
        """Return False to disable this rule at class level."""
        return True

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(id={self.rule_id!r})"
