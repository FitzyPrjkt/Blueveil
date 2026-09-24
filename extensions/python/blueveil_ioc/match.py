"""Offline indicator matching over a TelemetryEvent-shaped dict.

Matching is pure set membership against a caller-supplied local list: a
match reports THAT an indicator string was observed in a field, never WHAT
it means. No reputation, no classification, no verdict. Output records carry
the indicator, its kind, the list source, and the matched field — provenance
a consumer can audit. Empty inputs match nothing (explicit neutral result).
"""

SCANNED_FIELDS = ("raw", "event_type", "asset_id", "source")

_KINDS = ("domain", "ip", "sha256")


def _checked(item, i):
    """Validate one indicator item, raising ValueError naming the index.

    Library callers bypass the CLI's normalize_indicator_list, so malformed
    items must fail explicitly here — never as a raw KeyError/TypeError.
    Values are used verbatim (callers pass normalized lists); only the
    structure is checked.
    """
    if not isinstance(item, dict):
        raise ValueError(f"indicator {i}: not an object")
    try:
        kind, value, source = item["kind"], item["value"], item["source"]
    except KeyError as e:
        raise ValueError(f"indicator {i}: missing key {e}") from None
    if kind not in _KINDS:
        raise ValueError(f"indicator {i}: unknown kind {kind!r}")
    if not isinstance(value, str) or not value:
        raise ValueError(f"indicator {i}: empty value")
    if not isinstance(source, str) or not source:
        raise ValueError(f"indicator {i}: empty source")
    return kind, value, source


def _field_text(event: dict, field: str) -> str:
    value = event.get(field, "")
    return value if isinstance(value, str) else ""


def match_event(event: dict, indicators: list) -> list:
    """Return sorted match records for event against normalized indicators.

    Rules (documented, deterministic):
      - domain: case-insensitive substring of the field text.
      - ip, sha256: case-insensitive exact token match; the field text is
        split on any non-alphanumeric character and compared per token, so
        "1.2.3.4," still matches but "11.2.3.44" does not.
    Records sort by (indicator, field, source). Non-dict events and empty
    indicator lists yield [] instead of raising.
    """
    if not isinstance(event, dict) or not indicators:
        return []
    matches = []
    for i, item in enumerate(indicators):
        kind, value, source = _checked(item, i)
        needle = value.lower()
        for field in SCANNED_FIELDS:
            haystack = _field_text(event, field)
            if not haystack:
                continue
            if kind == "domain":
                hit = needle in haystack.lower()
            else:
                hit = needle in _tokens(haystack.lower())
            if hit:
                matches.append({
                    "indicator": value,
                    "kind": kind,
                    "list_source": source,
                    "matched_field": field,
                })
    matches.sort(key=lambda m: (m["indicator"], m["matched_field"], m["list_source"]))
    return matches


def _tokens(text: str) -> set:
    # Dots and colons stay inside tokens so IPv4/IPv6 literals survive;
    # everything else non-alphanumeric splits. "1.2.3.4," matches 1.2.3.4
    # while "11.2.3.44" does not.
    token, out = [], set()
    for ch in text:
        if ch.isalnum() or ch in ".:":
            token.append(ch)
        elif token:
            out.add("".join(token))
            token = []
    if token:
        out.add("".join(token))
    return out


def match_attributes(event: dict, indicators: list) -> list:
    """Match indicator values against the event's string attributes.

    Same rules as match_event, with matched_field reported as
    "attributes.<key>". Attribute keys sort for determinism.
    """
    if not isinstance(event, dict) or not indicators:
        return []
    attrs = event.get("attributes", {})
    if not isinstance(attrs, dict):
        return []
    matches = []
    for i, item in enumerate(indicators):
        kind, value, source = _checked(item, i)
        needle = value.lower()
        for key in sorted(attrs):
            val = attrs[key]
            if not isinstance(val, str) or not val:
                continue
            if kind == "domain":
                hit = needle in val.lower()
            else:
                hit = needle in _tokens(val.lower())
            if hit:
                matches.append({
                    "indicator": value,
                    "kind": kind,
                    "list_source": source,
                    "matched_field": f"attributes.{key}",
                })
    matches.sort(key=lambda m: (m["indicator"], m["matched_field"], m["list_source"]))
    return matches
