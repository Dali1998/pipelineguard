"""
Compiled regex patterns used across rules.
Keep patterns here so they are compiled once and reused everywhere.
"""

import re

# ---------------------------------------------------------------------------
# Generic high-entropy / secret patterns
# ---------------------------------------------------------------------------

# AWS
AWS_ACCESS_KEY = re.compile(r"(?<![A-Z0-9])(AKIA|AIPA|ASIA|AROA)[A-Z0-9]{16}(?![A-Z0-9])")
AWS_SECRET_KEY = re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]")

# GitHub / GitLab tokens
GITHUB_TOKEN = re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}")
GITLAB_TOKEN = re.compile(r"glpat-[A-Za-z0-9\-_]{20,}")

# Generic API keys / passwords in assignments
GENERIC_SECRET = re.compile(
    r"""(?ix)
    (?:password|passwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key)
    \s*[=:]\s*
    ['"]([^'"]{8,})['"]\s*
    """,
)

# Private keys (PEM blocks)
PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE KEY-----")

# Generic high-entropy base64 string (≥ 32 chars)
HIGH_ENTROPY_B64 = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")

# ---------------------------------------------------------------------------
# Docker patterns
# ---------------------------------------------------------------------------

# Image without explicit digest or tag (bare name = :latest implied)
DOCKER_IMAGE_LATEST = re.compile(r"^([a-z0-9/.\-]+)(?::latest)?$")

# Image with SHA256 digest pinning
DOCKER_IMAGE_DIGEST = re.compile(r"@sha256:[a-f0-9]{64}")

# Privileged flag in RUN --mount or docker run
DOCKER_PRIVILEGED = re.compile(r"--privileged", re.IGNORECASE)

# Docker socket mount
DOCKER_SOCKET = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Shell / script patterns
# ---------------------------------------------------------------------------

# curl/wget piped directly to sh/bash
CURL_PIPE_SHELL = re.compile(
    r"(?:curl|wget)\s+.+\|\s*(?:ba)?sh",
    re.IGNORECASE | re.DOTALL,
)

# sudo usage in CI
SUDO_USAGE = re.compile(r"\bsudo\b")

# eval with variable expansion (code injection risk)
EVAL_EXPRESSION = re.compile(r"\beval\s+[\"'`$]")

# Hardcoded IP address
HARDCODED_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# ---------------------------------------------------------------------------
# Supply-chain patterns
# ---------------------------------------------------------------------------

# GitHub Actions using mutable ref (branch name instead of commit SHA)
GHA_MUTABLE_REF = re.compile(
    r"uses:\s+[a-zA-Z0-9_\-./]+@(?!([a-f0-9]{40})\b)([^\s#]+)",
)

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def has_high_entropy(value: str, threshold: float = 3.8) -> bool:
    """
    Shannon entropy check to catch random-looking secret values.
    Anything above ~3.8 bits/char is suspicious for short strings.
    """
    import math
    if not value or len(value) < 12:
        return False
    freq = {c: value.count(c) / len(value) for c in set(value)}
    entropy = -sum(p * math.log2(p) for p in freq.values())
    return entropy >= threshold
