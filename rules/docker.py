"""
Rules that check Docker image hygiene and container security in pipelines.
"""

from pipelineguard.models.issue import Issue, IssueCategory, Severity
from pipelineguard.models.pipeline import Pipeline
from pipelineguard.rules.base_rule import BaseRule
from pipelineguard.utils.patterns import (
    CURL_PIPE_SHELL,
    DOCKER_IMAGE_DIGEST,
    DOCKER_IMAGE_LATEST,
    DOCKER_SOCKET,
)


def _issue(rule_id, title, desc, sev, pipeline, job_name, evidence=None, remediation=None):
    return Issue(
        rule_id=rule_id,
        title=title,
        description=desc,
        severity=sev,
        category=IssueCategory.DOCKER,
        source_file=pipeline.source_file,
        job_name=job_name,
        evidence=evidence,
        remediation=remediation,
    )


class UnpinnedDockerImageRule(BaseRule):
    rule_id = "DOC-001"
    title = "Unpinned Docker Image"
    severity = Severity.MEDIUM

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            image = job.image
            if not image:
                continue
            # No digest → mutable reference
            if not DOCKER_IMAGE_DIGEST.search(image):
                issues.append(_issue(
                    self.rule_id, self.title,
                    f"Image '{image}' is not pinned to a SHA256 digest. "
                    "A compromised or updated upstream image could silently break your pipeline.",
                    self.severity, pipeline, job.name, image,
                    "Pin images to a digest: e.g. python:3.12-slim@sha256:<hash>",
                ))
        return issues


class LatestTagRule(BaseRule):
    rule_id = "DOC-002"
    title = "Docker Image Uses :latest Tag"
    severity = Severity.LOW

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            image = job.image or ""
            if image.endswith(":latest") or DOCKER_IMAGE_LATEST.fullmatch(image):
                issues.append(_issue(
                    self.rule_id, self.title,
                    f"Image '{image}' uses the ':latest' tag (or no tag), which is mutable.",
                    self.severity, pipeline, job.name, image,
                    "Use an explicit version tag and ideally a digest pin.",
                ))
        return issues


class PrivilegedContainerRule(BaseRule):
    rule_id = "DOC-003"
    title = "Privileged Container Mode Enabled"
    severity = Severity.HIGH

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            if job.privileged:
                issues.append(_issue(
                    self.rule_id, self.title,
                    f"Job '{job.name}' runs its container in privileged mode, "
                    "granting full host kernel access.",
                    self.severity, pipeline, job.name, "privileged: true",
                    "Remove privileged mode. Use targeted capabilities (cap_add) if needed.",
                ))
        return issues


class DockerSocketMountRule(BaseRule):
    rule_id = "DOC-004"
    title = "Docker Socket Mounted Inside Container"
    severity = Severity.CRITICAL

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            for vol in job.volumes:
                if DOCKER_SOCKET.search(vol):
                    issues.append(_issue(
                        self.rule_id, self.title,
                        "Mounting /var/run/docker.sock gives the container full Docker daemon "
                        "access — equivalent to root on the host.",
                        Severity.CRITICAL, pipeline, job.name, vol,
                        "Use Docker-in-Docker (dind) with TLS, or a rootless alternative like Podman.",
                    ))
        return issues


class CurlPipeShellRule(BaseRule):
    rule_id = "DOC-005"
    title = "curl/wget Output Piped Directly to Shell"
    severity = Severity.HIGH

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            for cmd in job.all_commands():
                match = CURL_PIPE_SHELL.search(cmd)
                if match:
                    issues.append(_issue(
                        self.rule_id, self.title,
                        "Piping curl/wget directly to sh/bash allows arbitrary remote code execution "
                        "if the URL is compromised.",
                        self.severity, pipeline, job.name, match.group()[:80],
                        "Download the script, verify its checksum, then execute it explicitly.",
                    ))
        return issues


class SidecarImageUnpinnedRule(BaseRule):
    rule_id = "DOC-006"
    title = "Unpinned Sidecar / Service Image"
    severity = Severity.MEDIUM

    def check(self, pipeline: Pipeline) -> list[Issue]:
        issues: list[Issue] = []
        for job in pipeline.jobs:
            for svc in job.services:
                if not DOCKER_IMAGE_DIGEST.search(svc):
                    issues.append(_issue(
                        self.rule_id, self.title,
                        f"Sidecar service image '{svc}' is not pinned to a digest.",
                        self.severity, pipeline, job.name, svc,
                        "Pin sidecar images to SHA256 digests the same as primary images.",
                    ))
        return issues
