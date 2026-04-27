"""
JSON reporter – writes a structured scan report to stdout or a file.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from pipelineguard.core.scanner import ScanResult


def write_report(
    result: ScanResult,
    output_path: str | Path | None = None,
    indent: int = 2,
) -> str:
    """
    Serialise the ScanResult to JSON.

    Args:
        result:      The scan result to serialise.
        output_path: If provided, write to this file. Otherwise returns the
                     JSON string (caller can pipe to stdout).
        indent:      JSON indentation level.

    Returns:
        The JSON string (regardless of whether it was written to a file).
    """
    payload = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "summary": result.summary(),
        "scanned_files": result.scanned_files,
        "skipped_files": result.skipped_files,
        "issues": [issue.to_dict() for issue in result.issues],
    }

    json_str = json.dumps(payload, indent=indent, default=str)

    if output_path:
        Path(output_path).write_text(json_str, encoding="utf-8")

    return json_str


def print_json(result: ScanResult) -> None:
    """Convenience: dump JSON report to stdout."""
    print(write_report(result))
