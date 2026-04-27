"""
Normalizer: dispatches a PipelineFile to the correct parser
and returns a unified Pipeline object.
"""

from __future__ import annotations
import logging

from pipelineguard.core.loader import PipelineFile
from pipelineguard.models.pipeline import Pipeline, PipelineType
from pipelineguard.parsers import parse_gitlab, parse_github, parse_jenkins

logger = logging.getLogger(__name__)

_PARSER_MAP = {
    PipelineType.GITLAB: parse_gitlab,
    PipelineType.GITHUB: parse_github,
    PipelineType.JENKINS: parse_jenkins,
}


def normalize(pipeline_file: PipelineFile) -> Pipeline | None:
    """
    Parse the file at `pipeline_file.path` using the appropriate parser.

    Returns None (and logs a warning) if parsing fails, so a single broken
    file does not abort the entire scan.
    """
    parser = _PARSER_MAP.get(pipeline_file.pipeline_type)
    if parser is None:
        logger.warning("No parser registered for type %s", pipeline_file.pipeline_type)
        return None

    try:
        return parser(pipeline_file.path)
    except Exception as exc:
        logger.warning(
            "Failed to parse %s (%s): %s",
            pipeline_file.path,
            pipeline_file.pipeline_type.value,
            exc,
        )
        return None
