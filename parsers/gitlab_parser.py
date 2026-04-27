"""
Parser for GitLab CI pipeline files (.gitlab-ci.yml).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from pipelineguard.models.job import Job
from pipelineguard.models.pipeline import Pipeline, PipelineType

# Top-level keys that are NOT job definitions
_GITLAB_RESERVED = {
    "stages", "variables", "image", "services", "before_script",
    "after_script", "cache", "include", "workflow", "default",
}


def parse(file_path: str | Path) -> Pipeline:
    """Parse a .gitlab-ci.yml file and return a unified Pipeline."""
    path = Path(file_path)
    raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}

    pipeline = Pipeline(
        source_file=str(path),
        pipeline_type=PipelineType.GITLAB,
        raw=raw,
    )

    # Global variables
    pipeline.env_vars = _flatten_vars(raw.get("variables", {}))
    pipeline.stages = raw.get("stages", [])

    # Global default image
    global_image: str | None = None
    default_block = raw.get("default", {})
    if isinstance(default_block, dict):
        global_image = default_block.get("image") or raw.get("image")
    else:
        global_image = raw.get("image")

    # Parse each job
    for key, value in raw.items():
        if key in _GITLAB_RESERVED or key.startswith("."):
            continue
        if not isinstance(value, dict):
            continue
        job = _parse_job(key, value, global_image)
        pipeline.add_job(job)

    return pipeline


def _parse_job(name: str, data: dict, global_image: str | None) -> Job:
    image = data.get("image") or global_image
    if isinstance(image, dict):
        image = image.get("name")  # GitLab allows image: {name: ..., entrypoint: ...}

    script = _to_list(data.get("script", []))
    before = _to_list(data.get("before_script", []))
    after = _to_list(data.get("after_script", []))

    services_raw = data.get("services", [])
    services = [
        (s["name"] if isinstance(s, dict) else s)
        for s in services_raw
    ]

    volumes: list[str] = []
    # GitLab runners expose volumes via runner config, not pipeline YAML,
    # but some CI configs embed docker options
    docker_opts = data.get("variables", {})

    return Job(
        name=name,
        stage=data.get("stage"),
        image=image,
        script=before + script + after,
        env_vars=_flatten_vars(data.get("variables", {})),
        allow_failure=bool(data.get("allow_failure", False)),
        services=services,
        volumes=volumes,
        raw=data,
    )


def _flatten_vars(variables: Any) -> dict[str, str]:
    if not isinstance(variables, dict):
        return {}
    return {k: str(v) for k, v in variables.items()}


def _to_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []
