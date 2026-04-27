"""
Rules that check for over-privileged permissions in pipeline jobs.
Covers GitHub Actions GITHUB_TOKEN scopes, GitLab job tokens, OIDC, etc.
"""

from pipelineguard.models.issue import Issue, IssueCategory, Severity
from pipelineguard.models.pipeline import Pipeline
from pipelineguard.rules.base_rule import BaseRule
from pipelineguard.utils.patterns import SUDO_USAGE

_WRITE_PERMISSIONS = {
    "contents": "write",
    "packages": "write",
    "id-token": "write",
    "actions": "write",
    "deployments": "write",
    "pull-requests": "write",
    "security-events": "write",
}


def _issue(rule_id, title, desc, sev, pipeline, job_name, evidence=None, remediation=None):
    return Issue(
        rule_id=rule_id,
        title=title,
        description=desc,
        severity=sev,
        category=IssueCategory.PERMISSIONS,
        source_file=pipeline.source_file,
        job_name=job_name,
        evidence=evidence,
        remediation=remediation,
    )


class WriteAllPermissionsRule(BaseRule):
    rule_id = "PRM-001"
    title = "Job Granted write-all Permissions"
    severity = Severity.HIGH

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            perms = job.permissions
            if perms.get("contents") == "write" and len(perms) == 1:
                # Only a broad 'write-all' style grant
                pass
            if perms.get("all") == "write" or perms.get("permissions") == "write-all":
                issues.append(_issue(
                    self.rule_id, self.title,
                    f"Job '{job.name}' is granted write-all permissions. "
                    "This violates least-privilege.",
                    self.severity, pipeline, job.name, str(perms),
                    "Enumerate only the specific permissions your job needs.",
                ))
        return issues


class BroadWritePermissionsRule(BaseRule):
    rule_id = "PRM-002"
    title = "Job Requests Multiple Write Permissions"
    severity = Severity.MEDIUM

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            write_scopes = [
                k for k, v in job.permissions.items()
                if v == "write" and k in _WRITE_PERMISSIONS
            ]
            if len(write_scopes) >= 3:
                issues.append(_issue(
                    self.rule_id, self.title,
                    f"Job '{job.name}' requests {len(write_scopes)} write-level permissions: "
                    f"{', '.join(write_scopes)}.",
                    self.severity, pipeline, job.name,
                    f"permissions: {job.permissions}",
                    "Reduce permissions to only what is strictly necessary for each job.",
                ))
        return issues


class MissingIdTokenPermissionRule(BaseRule):
    """
    If a job uses OIDC (e.g., aws-actions/configure-aws-credentials) it needs
    id-token: write — but having it when not needed is also risky.
    This rule flags jobs that request id-token: write without an obvious OIDC action.
    """

    rule_id = "PRM-003"
    title = "id-token:write Granted Without OIDC Usage"
    severity = Severity.LOW

    _OIDC_KEYWORDS = {"configure-aws-credentials", "oidc", "workload-identity", "auth"}

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            if job.permissions.get("id-token") != "write":
                continue
            # Check if any command or step references an OIDC-related keyword
            combined = " ".join(job.all_commands()).lower()
            if not any(kw in combined for kw in self._OIDC_KEYWORDS):
                issues.append(_issue(
                    self.rule_id, self.title,
                    f"Job '{job.name}' grants id-token:write but no OIDC-related step was found.",
                    self.severity, pipeline, job.name, "id-token: write",
                    "Remove id-token:write unless the job explicitly uses OIDC authentication.",
                ))
        return issues


class SudoInCiRule(BaseRule):
    rule_id = "PRM-004"
    title = "sudo Used in Pipeline Script"
    severity = Severity.MEDIUM

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            for cmd in job.all_commands():
                if SUDO_USAGE.search(cmd):
                    issues.append(_issue(
                        self.rule_id, self.title,
                        f"Job '{job.name}' uses sudo in a script step. "
                        "Running CI workloads with sudo escalates privileges unnecessarily.",
                        self.severity, pipeline, job.name, cmd[:100],
                        "Run CI jobs as a non-root user; install deps in the image build phase.",
                    ))
                    break  # one finding per job is enough
        return issues
