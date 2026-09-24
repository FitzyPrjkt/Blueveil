"""Blueveil Python extension: deterministic IOC normalization and offline
indicator matching over contract-shaped telemetry (stdlib only).
"""

from .enrich import enrich_event
from .ioc import normalize_indicator, normalize_indicator_list
from .match import match_attributes, match_event

__version__ = "0.1.0"
__all__ = [
    "normalize_indicator",
    "normalize_indicator_list",
    "match_event",
    "match_attributes",
    "enrich_event",
]
