"""Unit tests for secrets rules."""

import pytest
from pipelineguard.models.pipeline import Pipeline, PipelineType
from pipelineguard.models.job import Job
from pipelineguard.rules.secrets import (
    HardcodedAwsKeyRule,
    HardcodedGitHubTokenRule,
    GenericSecretInEnvRule,
    PrivateKeyInScriptRule,
)


def _pipeline(*jobs: Job) -> Pipeline:
    p = Pipeline(source_file="test.yml", pipeline_type=PipelineType.GITLAB)
    for j in jobs:
        p.add_job(j)
    return p


class TestHardcodedAwsKey:
    rule = HardcodedAwsKeyRule()

    def test_detects_access_key(self):
        job = Job(name="deploy", script=["export AWS_KEY=AKIAIOSFODNN7EXAMPLE"])
        issues = self.rule.check(_pipeline(job))
        assert len(issues) == 1
        assert issues[0].rule_id == "SEC-001"

    def test_no_false_positive(self):
        job = Job(name="build", script=["echo hello"])
        assert self.rule.check(_pipeline(job)) == []


class TestGenericSecretInEnv:
    rule = GenericSecretInEnvRule()

    def test_detects_high_entropy_password(self):
        p = _pipeline()
        p.env_vars = {"DATABASE_PASSWORD": "xK9#mP2$vL5@nR8&qT4^"}
        issues = self.rule.check(p)
        assert any(i.rule_id == "SEC-004" for i in issues)

    def test_ignores_placeholder(self):
        p = _pipeline()
        p.env_vars = {"DATABASE_PASSWORD": "changeme"}
        issues = self.rule.check(p)
        assert issues == []


class TestPrivateKeyInScript:
    rule = PrivateKeyInScriptRule()

    def test_detects_pem_header(self):
        job = Job(name="ssh", script=["echo '-----BEGIN RSA PRIVATE KEY-----'"])
        issues = self.rule.check(_pipeline(job))
        assert len(issues) == 1

    def test_clean_script(self):
        job = Job(name="build", script=["pip install -r requirements.txt"])
        assert self.rule.check(_pipeline(job)) == []
