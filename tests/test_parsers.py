"""Integration tests for parsers using fixture YAML/Groovy files."""

import textwrap
import pytest
from pathlib import Path

from pipelineguard.parsers.gitlab_parser import parse as parse_gitlab
from pipelineguard.parsers.github_parser import parse as parse_github
from pipelineguard.parsers.jenkins_parser import parse as parse_jenkins
from pipelineguard.models.pipeline import PipelineType


@pytest.fixture
def tmp_file(tmp_path):
    def _write(name: str, content: str) -> Path:
        p = tmp_path / name
        p.write_text(textwrap.dedent(content))
        return p
    return _write


class TestGitLabParser:
    def test_basic(self, tmp_file):
        f = tmp_file(".gitlab-ci.yml", """
            stages: [build, test]
            variables:
              ENV: production
            build:
              stage: build
              image: python:3.12
              script:
                - pip install .
        """)
        p = parse_gitlab(f)
        assert p.pipeline_type == PipelineType.GITLAB
        assert len(p.jobs) == 1
        assert p.jobs[0].name == "build"
        assert p.jobs[0].image == "python:3.12"
        assert "ENV" in p.env_vars

    def test_anchor_keys_skipped(self, tmp_file):
        f = tmp_file(".gitlab-ci.yml", """
            .template: &tmpl
              script: [echo hi]
            real_job:
              script: [echo hello]
        """)
        p = parse_gitlab(f)
        job_names = [j.name for j in p.jobs]
        assert "real_job" in job_names
        assert ".template" not in job_names


class TestGitHubParser:
    def test_basic(self, tmp_file):
        f = tmp_file("ci.yml", """
            name: CI
            on: [push]
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - run: pip install .
        """)
        p = parse_github(f)
        assert p.pipeline_type == PipelineType.GITHUB
        assert p.name == "CI"
        assert len(p.jobs) == 1
        assert "uses: actions/checkout@v4" in p.jobs[0].commands

    def test_permissions_parsed(self, tmp_file):
        f = tmp_file("ci.yml", """
            name: Deploy
            on: [push]
            jobs:
              deploy:
                runs-on: ubuntu-latest
                permissions:
                  id-token: write
                  contents: read
                steps:
                  - run: echo deploy
        """)
        p = parse_github(f)
        assert p.jobs[0].permissions.get("id-token") == "write"


class TestJenkinsParser:
    def test_basic(self, tmp_file):
        f = tmp_file("Jenkinsfile", """
            pipeline {
              agent { image 'python:3.12' }
              stages {
                stage('Build') {
                  steps {
                    sh 'pip install .'
                  }
                }
              }
            }
        """)
        p = parse_jenkins(f)
        assert p.pipeline_type == PipelineType.JENKINS
        assert any("Build" in j.name for j in p.jobs)
