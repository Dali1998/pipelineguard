"""
Orchestrator: discovers files → parses → runs rules → returns ScanResult.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from pipelineguard.core.loader import find_pipeline_files
from pipelineguard.core.normalizer import normalize
from pipelineguard.models.issue import Issue, Severity
from pipelineguard.models.pipeline import Pipeline
from pipelineguard.rules.base_rule import BaseRule
from pipelineguard.rules.registry import load_rules

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    pipelines: list[Pipeline] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)

    # ── convenience helpers ──────────────────────────────────────────────
    def by_severity(self, severity: Severity) -> list[Issue]:
        return [i for i in self.issues if i.severity == severity]

    @property
    def critical(self) -> list[Issue]:
        return self.by_severity(Severity.CRITICAL)

    @property
    def high(self) -> list[Issue]:
        return self.by_severity(Severity.HIGH)

    @property
    def has_failures(self) -> bool:
        """True if there are any CRITICAL or HIGH findings."""
        return bool(self.critical or self.high)

    def summary(self) -> dict:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for issue in self.issues:
            counts[issue.severity.value] += 1
        return {
            "total_issues": len(self.issues),
            "by_severity": counts,
            "scanned_files": len(self.scanned_files),
            "skipped_files": len(self.skipped_files),
        }


class Scanner:
    def __init__(
        self,
        rules: list[BaseRule] | None = None,
        severity_filter: list[Severity] | None = None,
    ):
        self.rules: list[BaseRule] = rules if rules is not None else load_rules(severity_filter)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, path: str | Path) -> ScanResult:
        """
        Scan a single file OR an entire directory tree.
        Returns a ScanResult with all discovered issues.
        """
        target = Path(path)
        result = ScanResult()

        pipeline_files = (
            [self._detect_single(target)]
            if target.is_file()
            else find_pipeline_files(target)
        )
        pipeline_files = [pf for pf in pipeline_files if pf is not None]

        for pf in pipeline_files:
            pipeline = normalize(pf)
            if pipeline is None:
                result.skipped_files.append(str(pf.path))
                continue

            result.scanned_files.append(str(pf.path))
            result.pipelines.append(pipeline)

            for rule in self.rules:
                try:
                    findings = rule.check(pipeline)
                    result.issues.extend(findings)
                except Exception as exc:
                    logger.error("Rule %s raised an exception: %s", rule.rule_id, exc)

        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_single(path: Path):
        """Detect the pipeline type of a single file."""
        from pipelineguard.core.loader import _MATCHERS, PipelineFile
        for pipeline_type, matcher in _MATCHERS:
            if matcher(path):
                return PipelineFile(path=path, pipeline_type=pipeline_type)
        logger.warning("Could not detect pipeline type for %s; skipping.", path)
        return None
