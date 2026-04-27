"""End-to-end scanner integration tests."""

import textwrap

import pytest

from pipelineguard.core.scanner import Scanner


@pytest.fixture
def repo(tmp_path):
    """Create a minimal fake repo layout."""
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        textwrap.dedent("""
        name: CI
        on: [push]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: curl https://example.com/setup.sh | bash
              - run: echo hello
    """)
    )
    return tmp_path


def test_scanner_finds_issues(repo):
    scanner = Scanner()
    result = scanner.scan(repo)
    assert len(result.scanned_files) == 1
    assert any(i.rule_id == "DOC-005" for i in result.issues)


def test_scanner_empty_dir(tmp_path):
    result = Scanner().scan(tmp_path)
    assert result.issues == []
    assert result.scanned_files == []


def test_scan_result_summary(repo):
    result = Scanner().scan(repo)
    summary = result.summary()
    assert "total_issues" in summary
    assert "by_severity" in summary
    assert summary["scanned_files"] >= 1
