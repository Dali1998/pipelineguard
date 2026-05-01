# PipelineGuard

Security scanner tool for CI/CD pipeline definitions and Docker images.  
Supports **GitLab CI**, **GitHub Actions**, and **Jenkinsfile** out of the box.

---

## Quick start

```bash
pip install pipelineguard          # or: pip install -e .[dev] for dev
pipelineguard scan .               # scan the current repo
pipelineguard scan .gitlab-ci.yml  # scan a single file
pipelineguard scan . --format json --output report.json
```

## Rule categories

| Prefix | Category       | Examples                                      |
|--------|----------------|-----------------------------------------------|
| SEC    | Secrets        | hardcoded AWS keys, GitHub tokens, PEM blocks |
| DOC    | Docker         | unpinned images, privileged containers, curl\|sh |
| PRM    | Permissions    | write-all scopes, sudo in CI                  |
| ISO    | Isolation      | mutable action refs, eval in scripts          |

## CLI flags

```
pipelineguard scan PATH
  --format   console|json           Output format (default: console)
  --output   FILE                   Write JSON report to file
  --severity critical,high,...      Filter which severities to report
  --fail-on  LEVEL                  Exit 1 if ≥ LEVEL found (default: critical)
  --no-remediation                  Hide fix hints
  -v / --verbose                    Debug logging

pipelineguard list-rules            Show all registered rules
```

## Adding a new rule

1. Create (or add to) a file in `pipelineguard/rules/`.
2. Subclass `BaseRule` and implement `check(pipeline) -> list[Issue]`.
3. Set `rule_id`, `title`, `severity`, `category` as class attributes.
4. Done — the registry auto-discovers it.

```python
from pipelineguard.rules.base_rule import BaseRule
from pipelineguard.models.issue import Issue, Severity, IssueCategory

class MyRule(BaseRule):
    rule_id  = "MY-001"
    title    = "Example custom rule"
    severity = Severity.MEDIUM

    def check(self, pipeline):
        issues = []
        for job in pipeline.jobs:
            if "bad-thing" in " ".join(job.all_commands()):
                issues.append(Issue(
                    rule_id=self.rule_id, title=self.title,
                    description="Found bad-thing.",
                    severity=self.severity,
                    category=IssueCategory.MISCONFIGURATION,
                    source_file=pipeline.source_file,
                    job_name=job.name,
                ))
        return issues
```

## Running tests

```bash
pytest                         # all tests
pytest --cov=pipelineguard     # with coverage
```
