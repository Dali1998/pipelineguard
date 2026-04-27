"""
Rules that detect hardcoded or leaked secrets in pipeline definitions.
"""

import re
from pipelineguard.rules.base_rule import BaseRule
from pipelineguard.models.pipeline import Pipeline
from pipelineguard.models.issue import Issue, Severity, IssueCategory
from pipelineguard.utils.patterns import (
    AWS_ACCESS_KEY,
    GITHUB_TOKEN,
    GITLAB_TOKEN,
    GENERIC_SECRET,
    PRIVATE_KEY_HEADER,
    has_high_entropy,
)


def _make_issue(
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    pipeline: Pipeline,
    job_name: str | None,
    evidence: str | None,
    remediation: str,
) -> Issue:
    return Issue(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        category=IssueCategory.SECRET,
        source_file=pipeline.source_file,
        job_name=job_name,
        evidence=_redact(evidence),
        remediation=remediation,
    )


def _redact(value: str | None, keep: int = 4) -> str | None:
    """Show only first `keep` chars to avoid leaking secrets in reports."""
    if not value:
        return value
    return value[:keep] + "***" if len(value) > keep else "***"


class HardcodedAwsKeyRule(BaseRule):
    rule_id = "SEC-001"
    title = "Hardcoded AWS Access Key"
    severity = Severity.CRITICAL

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            for cmd in job.all_commands():
                match = AWS_ACCESS_KEY.search(cmd)
                if match:
                    issues.append(_make_issue(
                        self.rule_id, self.title,
                        "An AWS access key ID was found hardcoded in a pipeline command.",
                        self.severity, pipeline, job.name, match.group(),
                        "Use CI/CD secret variables or AWS IAM roles with OIDC instead.",
                    ))
        return issues


class HardcodedGitHubTokenRule(BaseRule):
    rule_id = "SEC-002"
    title = "Hardcoded GitHub Token"
    severity = Severity.CRITICAL

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            for cmd in job.all_commands():
                match = GITHUB_TOKEN.search(cmd)
                if match:
                    issues.append(_make_issue(
                        self.rule_id, self.title,
                        "A GitHub personal/fine-grained access token was found in a command.",
                        self.severity, pipeline, job.name, match.group(),
                        "Store tokens in encrypted CI/CD secrets and reference them via env vars.",
                    ))
        return issues


class HardcodedGitLabTokenRule(BaseRule):
    rule_id = "SEC-003"
    title = "Hardcoded GitLab Token"
    severity = Severity.CRITICAL

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            for cmd in job.all_commands():
                match = GITLAB_TOKEN.search(cmd)
                if match:
                    issues.append(_make_issue(
                        self.rule_id, self.title,
                        "A GitLab project/personal access token was found in a command.",
                        self.severity, pipeline, job.name, match.group(),
                        "Use GitLab CI/CD masked variables or HashiCorp Vault.",
                    ))
        return issues


class GenericSecretInEnvRule(BaseRule):
    rule_id = "SEC-004"
    title = "Plaintext Secret in Environment Variable"
    severity = Severity.HIGH

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []

        def _scan_env(env: dict, job_name: str | None) -> None:
            for key, value in env.items():
                if not isinstance(value, str):
                    continue
                suspicious_key = bool(re.search(
                    r"(?i)(password|secret|token|api.?key|private.?key|credential)", key
                ))
                if suspicious_key and has_high_entropy(value):
                    issues.append(_make_issue(
                        self.rule_id, self.title,
                        f"Environment variable '{key}' appears to contain a plaintext secret.",
                        self.severity, pipeline, job_name, value,
                        "Use masked/protected CI variables. Never hardcode secrets in pipeline YAML.",
                    ))

        _scan_env(pipeline.env_vars, None)
        for job in pipeline.jobs:
            _scan_env(job.env_vars, job.name)

        return issues


class PrivateKeyInScriptRule(BaseRule):
    rule_id = "SEC-005"
    title = "Private Key Material in Script"
    severity = Severity.CRITICAL

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            for cmd in job.all_commands():
                if PRIVATE_KEY_HEADER.search(cmd):
                    issues.append(_make_issue(
                        self.rule_id, self.title,
                        "A PEM private key header was detected inside a pipeline script block.",
                        self.severity, pipeline, job.name, "-----BEGIN PRIVATE KEY-----",
                        "Store private keys in CI secret variables or a secrets manager.",
                    ))
        return issues
