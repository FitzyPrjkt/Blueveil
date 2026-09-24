// Audit: every response decision appended, in order, with actor, operation,
// risk, timestamp, reason, and result — mirroring Rust core audit.rs field
// for field, plus the response linkage (response id + safety phase) the
// response lifecycle requires. In-memory append-only for tests and runtime
// verification; explicitly NOT a tamper-proof persistent log.
package response

import (
	"fmt"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "blueveil/collector/internal/contract/v1"
)

// AuditDecision names what was decided. Distinct outcomes stay distinct:
// executed ≠ verified, failed ≠ unknown.
type AuditDecision string

const (
	AuditRecommended         AuditDecision = "recommended"
	AuditAllowed             AuditDecision = "allowed"
	AuditDenied              AuditDecision = "denied"
	AuditApprovalRequired    AuditDecision = "approval-required"
	AuditApproved            AuditDecision = "approved"
	AuditExecuted            AuditDecision = "executed"
	AuditExecutionFailed     AuditDecision = "execution-failed"
	AuditExecutorError       AuditDecision = "executor-error"
	AuditVerified            AuditDecision = "verified"
	AuditVerificationFailed  AuditDecision = "verification-failed"
	AuditVerificationUnknown AuditDecision = "verification-unknown"
)

// AuditEntry is one recorded decision.
type AuditEntry struct {
	ID         string
	DecidedAt  *timestamppb.Timestamp
	Actor      string
	Operation  v1.OperationType
	Risk       v1.RiskLevel
	Decision   AuditDecision
	Reason     string
	Result     string
	ResponseID string
	Phase      string
}

// AuditLog is the minimal append/read interface.
type AuditLog interface {
	Append(entry AuditEntry)
	Entries() []AuditEntry
}

// InMemoryAuditLog appends entries with deterministic sequential ids
// (audit-0001, …) reflecting append order.
type InMemoryAuditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
}

// Append records one entry, stamping a sequential id.
func (l *InMemoryAuditLog) Append(entry AuditEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry.ID = fmt.Sprintf("audit-%04d", len(l.entries)+1)
	l.entries = append(l.entries, entry)
}

// Entries returns a deep copy in append (chronological) order. Timestamps
// are cloned too: sharing DecidedAt pointers would let callers rewrite the
// log through a returned entry.
func (l *InMemoryAuditLog) Entries() []AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]AuditEntry, 0, len(l.entries))
	for _, e := range l.entries {
		if e.DecidedAt != nil {
			e.DecidedAt = proto.Clone(e.DecidedAt).(*timestamppb.Timestamp)
		}
		out = append(out, e)
	}
	return out
}
