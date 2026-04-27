"""
Parser for Jenkins declarative pipeline files (Jenkinsfile).

Jenkins pipelines are Groovy DSL, not YAML, so we use regex-based
heuristics rather than a full AST parser.  Coverage is best-effort;
a real implementation could use `python-jenkinsfile` or invoke
`jenkins-lint` as a subprocess.
"""

from __future__ import annotations

import re
from pathlib import Path

from pipelineguard.models.job import Job
from pipelineguard.models.pipeline import Pipeline, PipelineType

# Regex patterns for declarative Jenkinsfile constructs
_STAGE_RE = re.compile(r"stage\s*\(\s*['\"](.+?)['\"]\s*\)", re.MULTILINE)
_AGENT_IMAGE_RE = re.compile(r"image\s*['\"](.+?)['\"]")
_DOCKER_IMAGE_RE = re.compile(r"docker\.image\s*\(\s*['\"](.+?)['\"]\s*\)")
_SH_RE = re.compile(r"\bsh\s+(?:'''|\"\"\")(.*?)(?:'''|\"\"\")", re.DOTALL)
_SH_SINGLE_RE = re.compile(r"""\bsh\s+['"](.*?)['"]""")
_ENV_RE = re.compile(r"(\w+)\s*=\s*['\"](.+?)['\"]")


def parse(file_path: str | Path) -> Pipeline:
    """Parse a Jenkinsfile and return a unified Pipeline (best-effort)."""
    path = Path(file_path)
    content = path.read_text()

    pipeline = Pipeline(
        source_file=str(path),
        pipeline_type=PipelineType.JENKINS,
        raw={"content": content},
    )

    # Extract global agent image if present
    global_image: str | None = None
    agent_match = _AGENT_IMAGE_RE.search(content)
    if agent_match:
        global_image = agent_match.group(1)

    # Extract stage blocks naively by finding stage('name') { ... }
    stage_names = _STAGE_RE.findall(content)

    # Split content by stage boundaries for per-stage analysis
    stage_chunks = _split_by_stages(content, stage_names)

    for stage_name, chunk in stage_chunks.items():
        job = _parse_stage(stage_name, chunk, global_image)
        pipeline.add_job(job)

    # If no stages found treat entire file as one job
    if not pipeline.jobs:
        job = _parse_stage("main", content, global_image)
        pipeline.add_job(job)

    return pipeline


def _split_by_stages(content: str, stage_names: list[str]) -> dict[str, str]:
    """Crude chunk split – good enough for heuristic scanning."""
    if not stage_names:
        return {}
    result: dict[str, str] = {}
    positions = [
        (m.start(), m.group(1))
        for m in _STAGE_RE.finditer(content)
    ]
    for i, (pos, name) in enumerate(positions):
        end = positions[i + 1][0] if i + 1 < len(positions) else len(content)
        result[name] = content[pos:end]
    return result


def _parse_stage(name: str, chunk: str, global_image: str | None) -> Job:
    # Image override inside stage
    img_match = _AGENT_IMAGE_RE.search(chunk) or _DOCKER_IMAGE_RE.search(chunk)
    image = img_match.group(1) if img_match else global_image

    # Extract sh commands (multi-line and single-line)
    commands: list[str] = []
    for m in _SH_RE.finditer(chunk):
        commands.extend(m.group(1).strip().splitlines())
    for m in _SH_SINGLE_RE.finditer(chunk):
        commands.append(m.group(1).strip())

    # Extract environment variables
    env_vars: dict[str, str] = {}
    for m in _ENV_RE.finditer(chunk):
        env_vars[m.group(1)] = m.group(2)

    return Job(
        name=name,
        image=image,
        commands=commands,
        env_vars=env_vars,
        raw={"chunk": chunk},
    )
