"""
defa.ai package — Local AI Forensic Assistant Integration for DEFA
"""

from defa.ai.client import OllamaClient
from defa.ai.context import build_forensic_context, SYSTEM_PROMPT
from defa.ai.tools import (
    defa_search_evidence,
    defa_get_file_details,
    defa_get_scan_statistics,
    defa_get_duplicate_groups,
    defa_get_largest_files,
    defa_get_findings,
    defa_compare_baselines,
)

__all__ = [
    "OllamaClient",
    "build_forensic_context",
    "SYSTEM_PROMPT",
    "defa_search_evidence",
    "defa_get_file_details",
    "defa_get_scan_statistics",
    "defa_get_duplicate_groups",
    "defa_get_largest_files",
    "defa_get_findings",
    "defa_compare_baselines",
]
