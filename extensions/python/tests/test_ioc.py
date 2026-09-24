"""unittest suite: stdlib only (no pytest dependency by design)."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blueveil_ioc import (
    enrich_event,
    match_attributes,
    match_event,
    normalize_indicator,
    normalize_indicator_list,
)

EVENT = {
    "id": "evt-test-001",
    "occurred_at": "2026-09-12T09:00:00Z",
    "source": "waf-sim-lab",
    "asset_id": "asset-test-web-01",
    "event_type": "waf.request_blocked",
    "severity": "SEVERITY_HIGH",
    "attributes": {"rule_id": "CRS-941100", "client_ip": "127.0.0.1"},
    "raw": "POST /search?q=Example.COM <script>alert(1)</script> -> 403",
}

INDICATORS = [
    {"kind": "domain", "value": "example.com", "source": "test-list"},
    {"kind": "ip", "value": "127.0.0.1", "source": "test-list"},
]


class NormalizeTest(unittest.TestCase):
    def test_valid_forms(self):
        self.assertEqual(normalize_indicator("domain", "Example.COM."), "example.com")
        self.assertEqual(normalize_indicator("domain", "  sub.EXAMPLE.com "), "sub.example.com")
        self.assertEqual(normalize_indicator("ip", "127.0.0.1"), "127.0.0.1")
        self.assertEqual(normalize_indicator("sha256", "E3B0" + "0" * 60), "e3b0" + "0" * 60)

    def test_deterministic(self):
        self.assertEqual(
            normalize_indicator("domain", "Example.COM."),
            normalize_indicator("domain", "example.com"),
        )

    def test_invalid(self):
        for kind, value in [
            ("domain", ""),
            ("domain", "-bad-.com"),
            ("domain", "has space.com"),
            ("ip", "999.1.1.1"),
            ("ip", "not-an-ip"),
            ("sha256", "xyz"),
            ("sha256", "ab" * 31),
            ("md5", "abc"),
        ]:
            with self.assertRaises(ValueError, msg=f"{kind}:{value}"):
                normalize_indicator(kind, value)

    def test_list_keeps_order_and_source(self):
        raw = [
            {"kind": "domain", "value": "B.COM.", "source": "s1"},
            {"kind": "ip", "value": "10.0.0.1", "source": "s2"},
        ]
        self.assertEqual(
            normalize_indicator_list(raw),
            [
                {"kind": "domain", "value": "b.com", "source": "s1"},
                {"kind": "ip", "value": "10.0.0.1", "source": "s2"},
            ],
        )

    def test_list_rejects_malformed(self):
        with self.assertRaises(ValueError):
            normalize_indicator_list([{"kind": "domain", "value": "x.com"}])
        with self.assertRaises(ValueError):
            normalize_indicator_list("not-a-list-items")


class MatchTest(unittest.TestCase):
    def test_positive(self):
        matches = match_event(EVENT, INDICATORS)
        fields = {(m["indicator"], m["matched_field"]) for m in matches}
        self.assertIn(("example.com", "raw"), fields)
        # 127.0.0.1 lives in attributes, not in scanned fields: no match here.
        self.assertNotIn(("127.0.0.1", "raw"), fields)

    def test_ip_token_boundary(self):
        event = dict(EVENT, raw="from 11.2.3.44 ok")
        self.assertEqual(match_event(event, INDICATORS), [])

    def test_negative(self):
        event = dict(EVENT, raw="benign traffic", attributes={})
        self.assertEqual(match_event(event, INDICATORS), [])

    def test_empty_inputs_neutral(self):
        self.assertEqual(match_event({}, INDICATORS), [])
        self.assertEqual(match_event(EVENT, []), [])
        self.assertEqual(match_attributes(EVENT, []), [])

    def test_attribute_match(self):
        matches = match_attributes(EVENT, INDICATORS)
        self.assertTrue(any(
            m["indicator"] == "127.0.0.1" and m["matched_field"] == "attributes.client_ip"
            for m in matches
        ))


class EnrichTest(unittest.TestCase):
    def test_enrich_adds_only_owned_keys(self):
        enriched, matches = enrich_event(EVENT, INDICATORS)
        self.assertTrue(matches)
        self.assertIn("blueveil.python.ioc_match", enriched["attributes"])
        self.assertIn("blueveil.python.ioc_match_count", enriched["attributes"])
        self.assertEqual(enriched["attributes"]["rule_id"], "CRS-941100")
        # Input untouched.
        self.assertNotIn("blueveil.python.ioc_match", EVENT["attributes"])

    def test_no_match_returns_unchanged_copy(self):
        event = dict(EVENT, raw="benign", attributes={})
        enriched, matches = enrich_event(event, INDICATORS)
        self.assertEqual(matches, [])
        self.assertEqual(enriched, event)
        self.assertIsNot(enriched, event)

    def test_no_match_without_attributes_adds_nothing(self):
        event = {"id": "evt-no-attrs-001"}
        enriched, matches = enrich_event(event, [])
        self.assertEqual(matches, [])
        self.assertEqual(enriched, event)
        self.assertNotIn("attributes", enriched)

    def test_conflict_refuses(self):
        event = dict(EVENT, attributes={"blueveil.python.ioc_match": "x"})
        with self.assertRaises(ValueError):
            enrich_event(event, INDICATORS)

    def test_bad_event(self):
        with self.assertRaises(ValueError):
            enrich_event("not-a-dict", INDICATORS)


class CLITest(unittest.TestCase):
    def run_cli(self, argv, stdin_text=None):
        root = Path(__file__).resolve().parent.parent
        return subprocess.run(
            [sys.executable, "-m", "blueveil_ioc", *argv],
            input=stdin_text,
            capture_output=True,
            text=True,
            cwd=root,
            timeout=60,
        )

    def test_normalize_cli(self):
        proc = self.run_cli(["normalize", "--kind", "domain", "--value", "Example.COM."])
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "example.com")

    def test_enrich_cli_end_to_end(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(
                [{"kind": "domain", "value": "example.com", "source": "cli-list"}], fh
            )
            path = fh.name
        proc = self.run_cli(["enrich", "--indicators", path], json.dumps(EVENT))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertIn("blueveil.python.ioc_match", out["attributes"])
        self.assertEqual(out["id"], "evt-test-001")

    def test_invalid_stdin_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump([], fh)
            path = fh.name
        proc = self.run_cli(["enrich", "--indicators", path], "{not json")
        self.assertNotEqual(proc.returncode, 0)


class BoundaryTest(unittest.TestCase):
    def test_no_match_returns_copy_unchanged_without_attributes(self):
        event = {"id": "evt-x"}
        enriched, matches = enrich_event(event, [])
        self.assertEqual(matches, [])
        self.assertEqual(enriched, event)
        self.assertNotIn("attributes", enriched)

    def test_no_match_preserves_existing_attributes(self):
        event = {"id": "evt-x", "attributes": {"a": "b"}}
        enriched, matches = enrich_event(event, [])
        self.assertEqual(matches, [])
        self.assertEqual(enriched, event)

    def test_malformed_indicator_is_value_error(self):
        event = {"id": "evt-x", "raw": "example.com"}
        for bad in (
            [{"value": "example.com", "source": "s"}],
            ["not-a-dict"],
            [{"kind": "bogus", "value": "x", "source": "s"}],
            [{"kind": "domain", "value": "", "source": "s"}],
            [{"kind": "domain", "value": "example.com", "source": ""}],
        ):
            for fn in (match_event, match_attributes):
                with self.assertRaises(ValueError, msg=f"{fn.__name__} {bad}"):
                    fn(event, bad)
            with self.assertRaises(ValueError, msg=f"enrich {bad}"):
                enrich_event(event, bad)


if __name__ == "__main__":
    unittest.main()
