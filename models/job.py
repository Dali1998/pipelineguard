from dataclasses import dataclass, field


@dataclass
class Job:
    """Unified representation of a single pipeline job/step."""

    name: str
    stage: str | None = None

    # Execution
    image: str | None = None  # Docker image used
    script: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)

    # Environment
    env_vars: dict[str, str] = field(default_factory=dict)
    secrets: list[str] = field(default_factory=list)  # referenced secret names

    # Permissions / OIDC / IAM
    permissions: dict[str, str] = field(default_factory=dict)
    allow_failure: bool = False

    # Docker / container specifics
    privileged: bool = False
    volumes: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)  # sidecar images

    # Raw snippet for context in reports
    raw: dict = field(default_factory=dict)

    def all_commands(self) -> list[str]:
        """Merge script + commands into one list for rule evaluation."""
        return self.script + self.commands

    def __repr__(self) -> str:
        return f"Job(name={self.name!r}, image={self.image!r}, stage={self.stage!r})"
