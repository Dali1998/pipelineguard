"""
Parser for GitHub Actions workflow files (.github/workflows/*.yml).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from pipelineguard.models.job import Job
from pipelineguard.models.pipeline import Pipeline, PipelineType


def parse(file_path: str | Path) -> Pipeline:
    """Parse a GitHub Actions workflow YAML and return a unified Pipeline."""
    path = Path(file_path)
    raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}

    pipeline = Pipeline(
        source_file=str(path),
        pipeline_type=PipelineType.GITHUB,
        name=raw.get("name"),
        raw=raw,
    )

    # Workflow-level env
    pipeline.env_vars = _flatten_env(raw.get("env", {}))

    jobs_block: dict[str, Any] = raw.get("jobs", {})
    for job_id, job_data in jobs_block.items():
        if not isinstance(job_data, dict):
            continue
        pipeline.add_job(_parse_job(job_id, job_data))

    return pipeline


def _parse_job(job_id: str, data: dict) -> Job:
    container = data.get("container", {})
    image: str | None = None
    if isinstance(container, str):
        image = container
    elif isinstance(container, dict):
        image = container.get("image")

    steps = data.get("steps", [])
    commands: list[str] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        if "run" in step:
            commands.append(step["run"])
        if "uses" in step:
            # Treat `uses:` lines as a special command for rule evaluation
            commands.append(f"uses: {step['uses']}")

    permissions = data.get("permissions", {})
    if isinstance(permissions, str):
        permissions = {"all": permissions}

    env_vars = _flatten_env(data.get("env", {}))

    services_raw = data.get("services", {})
    services = [
        v.get("image", "") if isinstance(v, dict) else str(v)
        for v in services_raw.values()
    ] if isinstance(services_raw, dict) else []

    return Job(
        name=job_id,
        image=image,
        commands=commands,
        env_vars=env_vars,
        permissions=permissions if isinstance(permissions, dict) else {},
        allow_failure=bool(data.get("continue-on-error", False)),
        services=services,
        raw=data,
    )


def _flatten_env(env: Any) -> dict[str, str]:
    if not isinstance(env, dict):
        return {}
    return {k: str(v) for k, v in env.items()}
