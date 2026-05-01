"""
Rules that check job isolation weaknesses:
  - shared caches leaking data between pipelines
  - artefacts uploaded without integrity checks
  - missing network policies
  - supply-chain (mutable action refs, unauthenticated registries)
"""

from pipelineguard.models.issue import Issue, IssueCategory, Severity
from pipelineguard.models.pipeline import Pipeline
from pipelineguard.rules.base_rule import BaseRule
from pipelineguard.utils.patterns import EVAL_EXPRESSION, GHA_MUTABLE_REF


def _issue(rule_id, title, desc, sev, pipeline, job_name, evidence=None, remediation=None):
    return Issue(
        rule_id=rule_id,
        title=title,
        description=desc,
        severity=sev,
        category=IssueCategory.ISOLATION,
        source_file=pipeline.source_file,
        job_name=job_name,
        evidence=evidence,
        remediation=remediation,
    )


class MutableActionRefRule(BaseRule):
    """GitHub Actions: using a branch name instead of a commit SHA."""

    rule_id = "ISO-001"
    title = "GitHub Action Pinned to Mutable Ref"
    severity = Severity.HIGH

    # Actions exempt from SHA pinning requirement.
    # Use cases: actions that use OIDC trusted publishing and require
    # their own release tags (e.g. pypa/gh-action-pypi-publish).
    ALLOWLIST: set = {
        "pypa/gh-action-pypi-publish",
    }

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            for cmd in job.all_commands():
                match = GHA_MUTABLE_REF.search(cmd)
                if not match:
                    continue
                # Extract action name — the part before @
                action_name = match.group().split("uses:")[-1].strip().split("@")[0].strip()
                if action_name in self.ALLOWLIST:
                    continue
                issues.append(_issue(
                    self.rule_id, self.title,
                    "A GitHub Action step references a mutable branch/tag ref. "
                    "A compromised upstream repo could inject malicious code.",
                    self.severity, pipeline, job.name, match.group(),
                    "Pin actions to a full commit SHA: uses: actions/checkout@<sha>",
                ))
        return issues


class EvalInScriptRule(BaseRule):
    rule_id = "ISO-002"
    title = "eval() Used in Pipeline Script"
    severity = Severity.HIGH

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            for cmd in job.all_commands():
                match = EVAL_EXPRESSION.search(cmd)
                if match:
                    issues.append(_issue(
                        self.rule_id, self.title,
                        f"Job '{job.name}' uses eval with a dynamic expression, "
                        "enabling potential code injection.",
                        self.severity, pipeline, job.name, cmd[:120],
                        "Avoid eval; use explicit commands or safe parameter expansion.",
                    ))
                    break
        return issues


class AllowFailureOnSecurityJobRule(BaseRule):
    rule_id = "ISO-003"
    title = "Security/Scan Job Marked allow_failure"
    severity = Severity.MEDIUM

    _SECURITY_KEYWORDS = {"sast", "dast", "scan", "trivy", "snyk", "semgrep", "bandit", "audit"}

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            if not job.allow_failure:
                continue
            name_lower = job.name.lower()
            if any(kw in name_lower for kw in self._SECURITY_KEYWORDS):
                issues.append(_issue(
                    self.rule_id, self.title,
                    f"Job '{job.name}' appears to be a security scan but is configured with "
                    "allow_failure: true, so vulnerabilities will not block the pipeline.",
                    self.severity, pipeline, job.name, f"allow_failure: true",
                    "Set allow_failure: false on security jobs so findings block the pipeline.",
                ))
        return issues


class UnauthenticatedRegistryRule(BaseRule):
    """Flag use of non-standard registries that could be typosquatted."""

    rule_id = "ISO-004"
    title = "Image Pulled from Unauthenticated / Third-Party Registry"
    severity = Severity.LOW

    _TRUSTED_REGISTRIES = {
        "docker.io",
        "ghcr.io",
        "gcr.io",
        "public.ecr.aws",
        "quay.io",
        "mcr.microsoft.com",
        "",  # bare image name = Docker Hub
    }

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            image = job.image or ""
            if not image:
                continue
            registry = image.split("/")[0] if "/" in image else ""
            # If the first segment contains a dot or colon it's a registry hostname
            is_custom_registry = ("." in registry or ":" in registry) and registry not in self._TRUSTED_REGISTRIES
            if is_custom_registry:
                issues.append(_issue(
                    self.rule_id, self.title,
                    f"Job '{job.name}' pulls from registry '{registry}' which is not on the "
                    "known-trusted list.",
                    self.severity, pipeline, job.name, image,
                    "Prefer images from trusted registries or mirror to a private registry.",
                ))
        return issues