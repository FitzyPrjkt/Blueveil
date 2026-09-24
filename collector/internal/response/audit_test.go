package response

import (
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "blueveil/collector/internal/contract/v1"
)

func TestAuditAppendsChronologically(t *testing.T) {
	log := &InMemoryAuditLog{}
	for _, d := range []AuditDecision{AuditRecommended, AuditApprovalRequired, AuditApproved} {
		log.Append(AuditEntry{
			DecidedAt: timestamppb.New(respClock()), Actor: "test-actor:x",
			Operation: v1.OperationType_OPERATION_TYPE_RECOMMEND, Risk: v1.RiskLevel_RISK_LEVEL_HIGH,
			Decision: d, Reason: "r", Result: "ok", ResponseID: "rec-1", Phase: "CONFIRM",
		})
	}
	entries := log.Entries()
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d", len(entries))
	}
	for i, want := range []AuditDecision{AuditRecommended, AuditApprovalRequired, AuditApproved} {
		if entries[i].Decision != want {
			t.Fatalf("order drift at %d: %v", i, entries[i].Decision)
		}
		if entries[i].ID == "" || entries[i].Actor != "test-actor:x" ||
			entries[i].Operation != v1.OperationType_OPERATION_TYPE_RECOMMEND ||
			entries[i].Risk != v1.RiskLevel_RISK_LEVEL_HIGH ||
			entries[i].ResponseID != "rec-1" || entries[i].DecidedAt == nil {
			t.Fatalf("field preservation drift: %+v", entries[i])
		}
	}
	// Returned slice is a copy: mutating it must not corrupt the log.
	entries[0].Decision = AuditDenied
	if log.Entries()[0].Decision != AuditRecommended {
		t.Fatal("entries must be copies")
	}
}
