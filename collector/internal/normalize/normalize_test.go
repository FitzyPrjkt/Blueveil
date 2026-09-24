package normalize

import (
	"errors"
	"testing"
	"time"

	"blueveil/collector/internal/source"
)

func validRaw() source.RawEvent {
	return source.RawEvent{
		ID:         "evt-test-001",
		Source:     "waf-sim-lab",
		AssetID:    "asset-test-web-01",
		IdentityID: "ident-test-collector-01",
		EventType:  "waf.request_blocked",
		Severity:   "SEVERITY_HIGH",
		Attributes: map[string]string{"rule_id": "CRS-941100"},
		Raw:        "POST /search -> 403",
		OccurredAt: time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC),
	}
}

func TestValidRawMapsExactly(t *testing.T) {
	e, err := New().Normalize(validRaw())
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	raw := validRaw()
	if e.GetId() != raw.ID || e.GetSource() != raw.Source || e.GetAssetId() != raw.AssetID ||
		e.GetIdentityId() != raw.IdentityID || e.GetEventType() != raw.EventType ||
		e.GetRaw() != raw.Raw {
		t.Fatalf("field mapping drift: %+v", e)
	}
	if e.GetSeverity().String() != raw.Severity {
		t.Fatalf("severity drift: %v", e.GetSeverity())
	}
	if e.GetAttributes()["rule_id"] != "CRS-941100" {
		t.Fatalf("attributes drift: %v", e.GetAttributes())
	}
	if e.GetOccurredAt().GetSeconds() != raw.OccurredAt.Unix() {
		t.Fatalf("timestamp drift: %v", e.GetOccurredAt())
	}
}

func TestMissingIdentityFailsSourceSanity(t *testing.T) {
	raw := validRaw()
	raw.ID = ""
	if _, err := New().Normalize(raw); !errors.Is(err, ErrInvalidSourceEvent) {
		t.Fatalf("want ErrInvalidSourceEvent, got %v", err)
	}
	raw = validRaw()
	raw.EventType = ""
	if _, err := New().Normalize(raw); !errors.Is(err, ErrInvalidSourceEvent) {
		t.Fatalf("want ErrInvalidSourceEvent, got %v", err)
	}
}

func TestUnknownSeverityFailsNormalization(t *testing.T) {
	raw := validRaw()
	raw.Severity = "SEVERITY_CRITICAL_PLUS"
	if _, err := New().Normalize(raw); !errors.Is(err, ErrNormalization) {
		t.Fatalf("want ErrNormalization, got %v", err)
	}
}

func TestUnsetSeverityAndTimestampReachContractBoundary(t *testing.T) {
	// Optional-by-source, required-by-contract: the normalizer passes them
	// through unset and the boundary rejects them. No invented data.
	raw := validRaw()
	raw.Severity = ""
	raw.OccurredAt = time.Time{}
	if _, err := New().Normalize(raw); !errors.Is(err, ErrContractValidation) {
		t.Fatalf("want ErrContractValidation, got %v", err)
	}
}
