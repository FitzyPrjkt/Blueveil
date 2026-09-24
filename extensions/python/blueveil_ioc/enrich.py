"""Enrichment: attach observed-indicator matches to a copy of the event.

Added attribute keys (and only these):
  - blueveil.python.ioc_match: ";"-joined "list|indicator|field" records,
    sorted (match_event already sorts; attribute scanning appends after).
  - blueveil.python.ioc_match_count: decimal count of records.

Rules: the input event is never mutated (a copy is returned); existing keys
are never overwritten (conflict → ValueError); no match → the copy is
returned unchanged. Values are data about observation, not judgments.
"""

from .match import match_attributes, match_event

KEY_MATCH = "blueveil.python.ioc_match"
KEY_COUNT = "blueveil.python.ioc_match_count"
OWNED_KEYS = (KEY_MATCH, KEY_COUNT)


def enrich_event(event: dict, indicators: list) -> tuple:
    """Return (enriched_copy, matches). matches is [] on neutral outcome."""
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    enriched = {k: (dict(v) if isinstance(v, dict) else v) for k, v in event.items()}
    attrs = enriched.get("attributes")
    if attrs is not None and not isinstance(attrs, dict):
        raise ValueError("event.attributes must be an object")
    for key in OWNED_KEYS:
        if attrs is not None and key in attrs:
            raise ValueError(f"refusing to overwrite existing {key!r}")
    matches = match_event(event, indicators) + match_attributes(event, indicators)
    matches.sort(key=lambda m: (m["indicator"], m["matched_field"], m["list_source"]))
    if not matches:
        # No match → copy returned unchanged: no attributes invented.
        return enriched, []
    if attrs is None:
        attrs = {}
        enriched["attributes"] = attrs
    attrs[KEY_MATCH] = ";".join(
        f"{m['list_source']}|{m['indicator']}|{m['matched_field']}" for m in matches
    )
    attrs[KEY_COUNT] = str(len(matches))
    return enriched, matches
