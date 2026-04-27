from dataclasses import dataclass, field
from enum import Enum


class PipelineType(str, Enum):
    GITLAB = "gitlab"
    GITHUB = "github"
    JENKINS = "jenkins"
    UNKNOWN = "unknown"


@dataclass
class Pipeline:
    """Unified representation of a CI/CD pipeline."""

    source_file: str
    pipeline_type: PipelineType
    jobs: list["Job"] = field(default_factory=list)
    env_vars: dict[str, str] = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    # Optional metadata
    name: str | None = None
    stages: list[str] = field(default_factory=list)

    def add_job(self, job: "Job") -> None:
        self.jobs.append(job)

    def __repr__(self) -> str:
        return (
            f"Pipeline(type={self.pipeline_type}, "
            f"file={self.source_file}, jobs={len(self.jobs)})"
        )
