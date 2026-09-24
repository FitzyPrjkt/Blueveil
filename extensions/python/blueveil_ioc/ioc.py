"""Deterministic IOC normalization (stdlib only, no network).

An indicator is a typed string (domain, ip, sha256). Normalization makes
equivalent spellings byte-identical so offline matching is exact and
reproducible. Invalid input raises ValueError with a reason — never a
silent default, never a fabricated value.
"""

import ipaddress
import re

KINDS = ("domain", "ip", "sha256")

_DOMAIN_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def normalize_indicator(kind: str, value: str) -> str:
    """Return the canonical form of one indicator or raise ValueError."""
    if kind not in KINDS:
        raise ValueError(f"unknown indicator kind {kind!r}; want one of {KINDS}")
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{kind}: indicator value is empty")
    text = value.strip()
    if kind == "domain":
        return _normalize_domain(text)
    if kind == "ip":
        return _normalize_ip(text)
    return _normalize_sha256(text)


def _normalize_domain(text: str) -> str:
    lowered = text.lower().rstrip(".")
    if not lowered or len(lowered) > 253:
        raise ValueError(f"domain: bad length {text!r}")
    for label in lowered.split("."):
        if not _DOMAIN_LABEL.match(label):
            raise ValueError(f"domain: bad label in {text!r}")
    return lowered


def _normalize_ip(text: str) -> str:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise ValueError(f"ip: unparsable address {text!r}") from None


def _normalize_sha256(text: str) -> str:
    lowered = text.lower()
    if not _HEX64.match(lowered):
        raise ValueError(f"sha256: want 64 lowercase-hex chars, got {text!r}")
    return lowered


def normalize_indicator_list(indicators) -> list:
    """Normalize [{'kind':..,'value':..,'source':..}], preserving order.

    Each item keeps its 'source' (list provenance). Malformed items raise
    ValueError naming the index — the caller decides whether to skip or
    abort; nothing is silently dropped inside this function.
    """
    out = []
    for i, item in enumerate(indicators):
        if not isinstance(item, dict):
            raise ValueError(f"indicator {i}: not an object")
        try:
            kind, value, source = item["kind"], item["value"], item["source"]
        except KeyError as e:
            raise ValueError(f"indicator {i}: missing key {e}") from None
        if not isinstance(source, str) or not source:
            raise ValueError(f"indicator {i}: empty source")
        out.append({"kind": kind, "value": normalize_indicator(kind, value), "source": source})
    return out
