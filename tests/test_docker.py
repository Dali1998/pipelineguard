"""Unit tests for Docker rules."""

from pipelineguard.models.job import Job
from pipelineguard.models.pipeline import Pipeline, PipelineType
from pipelineguard.rules.docker import (
    CurlPipeShellRule,
    DockerSocketMountRule,
    LatestTagRule,
    PrivilegedContainerRule,
    UnpinnedDockerImageRule,
)


def _pipeline(*jobs: Job) -> Pipeline:
    p = Pipeline(source_file="test.yml", pipeline_type=PipelineType.GITHUB)
    for j in jobs:
        p.add_job(j)
    return p


class TestUnpinnedDockerImage:
    rule = UnpinnedDockerImageRule()

    def test_flags_no_digest(self):
        job = Job(name="build", image="python:3.12-slim")
        assert len(self.rule.check(_pipeline(job))) == 1

    def test_passes_with_digest(self):
        job = Job(name="build", image="python:3.12-slim@sha256:" + "a" * 64)
        assert self.rule.check(_pipeline(job)) == []

    def test_no_image_no_issue(self):
        job = Job(name="test")
        assert self.rule.check(_pipeline(job)) == []


class TestLatestTag:
    rule = LatestTagRule()

    def test_flags_latest(self):
        job = Job(name="x", image="nginx:latest")
        assert len(self.rule.check(_pipeline(job))) == 1

    def test_flags_bare_name(self):
        job = Job(name="x", image="nginx")
        assert len(self.rule.check(_pipeline(job))) == 1

    def test_passes_versioned(self):
        job = Job(name="x", image="nginx:1.27.0")
        assert self.rule.check(_pipeline(job)) == []


class TestPrivilegedContainer:
    rule = PrivilegedContainerRule()

    def test_flags_privileged(self):
        job = Job(name="dind", privileged=True)
        assert len(self.rule.check(_pipeline(job))) == 1

    def test_passes_normal(self):
        job = Job(name="test", privileged=False)
        assert self.rule.check(_pipeline(job)) == []


class TestDockerSocket:
    rule = DockerSocketMountRule()

    def test_flags_socket_mount(self):
        job = Job(name="build", volumes=["/var/run/docker.sock:/var/run/docker.sock"])
        assert len(self.rule.check(_pipeline(job))) == 1

    def test_clean_volume(self):
        job = Job(name="build", volumes=["/data:/data"])
        assert self.rule.check(_pipeline(job)) == []


class TestCurlPipeShell:
    rule = CurlPipeShellRule()

    def test_flags_curl_pipe(self):
        job = Job(name="install", script=["curl https://example.com/install.sh | bash"])
        assert len(self.rule.check(_pipeline(job))) == 1

    def test_safe_curl(self):
        job = Job(name="download", script=["curl -o file.sh https://example.com/install.sh"])
        assert self.rule.check(_pipeline(job)) == []
