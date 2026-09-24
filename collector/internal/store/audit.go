// Store-level audit record: plain serializable fields mirroring the Rust
// core audit.rs shape plus the response linkage (response id + phase) the
// response lifecycle requires. Timestamps are time.Time (UTC on write);
// operation/risk reuse the contract enums so no parallel vocabulary exists.
package store

import (
	"fmt"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/response"
)

// AuditEntry is one archived decision.
type AuditEntry struct {
	ID         string
	DecidedAt  time.Time
	Actor      string
	Operation  v1.OperationType
	Risk       v1.RiskLevel
	Decision   string
	Reason     string
	Result     string
	ResponseID string
	Phase      string
}

// Validate enforces archival rules: identity, timestamp, actor, explicit
// operation/risk, decision. Reason/result/response linkage may be empty
// only when the producer genuinely has none — callers decide, stores verify
// presence of the structural fields.
func (e AuditEntry) Validate() error {
	if e.ID == "" {
		return fmt.Errorf("%w: audit id empty", ErrInvalid)
	}
	if e.DecidedAt.IsZero() {
		return fmt.Errorf("%w: audit timestamp zero", ErrInvalid)
	}
	if e.Actor == "" {
		return fmt.Errorf("%w: audit actor empty", ErrInvalid)
	}
	if _, ok := v1.OperationType_name[int32(e.Operation)]; !ok ||
		e.Operation == v1.OperationType_OPERATION_TYPE_UNSPECIFIED {
		return fmt.Errorf("%w: audit operation %v", ErrInvalid, int32(e.Operation))
	}
	if _, ok := v1.RiskLevel_name[int32(e.Risk)]; !ok ||
		e.Risk == v1.RiskLevel_RISK_LEVEL_UNSPECIFIED {
		return fmt.Errorf("%w: audit risk %v", ErrInvalid, int32(e.Risk))
	}
	if e.Decision == "" {
		return fmt.Errorf("%w: audit decision empty", ErrInvalid)
	}
	return nil
}

// AuditFromResponse translates a response audit entry to the store shape.
// Nil timestamps fail instead of defaulting.
func AuditFromResponse(a response.AuditEntry) (AuditEntry, error) {
	if a.DecidedAt == nil {
		return AuditEntry{}, fmt.Errorf("%w: audit timestamp missing", ErrInvalid)
	}
	e := AuditEntry{
		ID: a.ID, DecidedAt: a.DecidedAt.AsTime().UTC(), Actor: a.Actor,
		Operation: a.Operation, Risk: a.Risk, Decision: string(a.Decision),
		Reason: a.Reason, Result: a.Result, ResponseID: a.ResponseID, Phase: a.Phase,
	}
	if err := e.Validate(); err != nil {
		return AuditEntry{}, err
	}
	return e, nil
}
