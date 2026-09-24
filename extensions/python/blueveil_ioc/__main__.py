"""CLI boundary: JSON in, JSON out, exit codes explicit.

Usage:
  python3 -m blueveil_ioc normalize --kind domain --value Example.COM.
  python3 -m blueveil_ioc match --indicators FILE < event.json
  python3 -m blueveil_ioc enrich --indicators FILE < event.json > enriched.json

match prints {"matches": [...]}; enrich prints the enriched event object.
Exit 0 on success, 2 on usage/validation errors. No network, no side
effects beyond stdout/stderr.
"""

import argparse
import json
import sys

from .enrich import enrich_event
from .ioc import normalize_indicator, normalize_indicator_list
from .match import match_event


def _load_json_file(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as e:
        raise SystemExit(f"error: cannot load {path}: {e}") from None


def _load_stdin():
    try:
        return json.load(sys.stdin)
    except ValueError as e:
        raise SystemExit(f"error: stdin is not valid JSON: {e}") from None


def cmd_normalize(args):
    try:
        print(normalize_indicator(args.kind, args.value))
    except ValueError as e:
        raise SystemExit(f"error: {e}") from None


def cmd_match(args):
    indicators = _load_indicators(args.indicators)
    event = _load_stdin()
    if not isinstance(event, dict):
        raise SystemExit("error: stdin must hold one JSON object")
    try:
        matches = match_event(event, indicators)
    except (ValueError, KeyError, TypeError) as e:
        raise SystemExit(f"error: {e}") from None
    print(json.dumps({"matches": matches}, sort_keys=True))


def cmd_enrich(args):
    indicators = _load_indicators(args.indicators)
    event = _load_stdin()
    if not isinstance(event, dict):
        raise SystemExit("error: stdin must hold one JSON object")
    try:
        enriched, _ = enrich_event(event, indicators)
    except (ValueError, KeyError, TypeError) as e:
        raise SystemExit(f"error: {e}") from None
    print(json.dumps(enriched, sort_keys=True))


def _load_indicators(path):
    raw = _load_json_file(path)
    if not isinstance(raw, list):
        raise SystemExit("error: indicators file must hold a JSON array")
    try:
        return normalize_indicator_list(raw)
    except ValueError as e:
        raise SystemExit(f"error: {e}") from None


def main(argv=None):
    parser = argparse.ArgumentParser(prog="blueveil_ioc")
    sub = parser.add_subparsers(dest="command", required=True)
    p_norm = sub.add_parser("normalize")
    p_norm.add_argument("--kind", required=True, choices=("domain", "ip", "sha256"))
    p_norm.add_argument("--value", required=True)
    p_norm.set_defaults(func=cmd_normalize)
    p_match = sub.add_parser("match")
    p_match.add_argument("--indicators", required=True)
    p_match.set_defaults(func=cmd_match)
    p_enrich = sub.add_parser("enrich")
    p_enrich.add_argument("--indicators", required=True)
    p_enrich.set_defaults(func=cmd_enrich)
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except SystemExit as e:
        if isinstance(e.code, int):
            return e.code
        print(e.code, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
