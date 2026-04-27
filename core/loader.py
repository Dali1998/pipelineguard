"""
Discovers pipeline files in a repository tree.
Returns typed PipelineFile objects so the scanner knows which parser to call.
"""

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path

from pipelineguard.models.pipeline import PipelineType


@dataclass
class PipelineFile:
    path: Path
    pipeline_type: PipelineType


# Filename / path matchers in priority order
_MATCHERS: list[tuple[PipelineType, callable]] = [
    (
        PipelineType.GITLAB,
        lambda p: p.name == ".gitlab-ci.yml",
    ),
    (
        PipelineType.GITHUB,
        lambda p: ".github/workflows" in str(p) and p.suffix in {".yml", ".yaml"},
    ),
    (
        PipelineType.JENKINS,
        lambda p: p.name in {"Jenkinsfile", "Jenkinsfile.groovy"} or p.suffix == ".jenkinsfile",
    ),
]


def find_pipeline_files(root: str | Path) -> list[PipelineFile]:
    """
    Walk `root` recursively and return all detected pipeline files in the repository.
    Skips hidden directories and common noise dirs (node_modules, .git, venv, etc.).
    """
    root = Path(root).resolve()
    results: list[PipelineFile] = []

    for path in _walk(root):
        for pipeline_type, matcher in _MATCHERS:
            if matcher(path):
                results.append(PipelineFile(path=path, pipeline_type=pipeline_type))
                break  # a file matches at most one type

    return results


def _walk(root: Path):
    """Yield all files, skipping uninteresting directories."""
    _SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", "dist", "build"}
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path
