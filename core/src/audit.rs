//! Audit skeleton: records safety/policy decisions with context.
//!
//! Minimal record: decision, actor, operation, impact, timestamp, reason,
//! result. Storage is an in-memory append-only vec behind the `AuditLog`
//! trait. Explicitly NOT claimed: tamper-proofing, immutability,
//! distribution — none of those properties are implemented here.

use crate::contracts::utc_now;
use crate::policy::{Impact, Operation};

/// Outcome of a decided action, as recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditDecision {
    Allowed,
    Denied,
    ApprovalRequired,
    Approved,
}

/// One recorded decision. `id` is caller-assigned (UUID/ULID scheme arrives
/// with persistence, not here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub id: String,
    pub decided_at: prost_types::Timestamp,
    pub actor: String,
    pub operation: Operation,
    pub impact: Impact,
    pub decision: AuditDecision,
    pub reason: String,
    pub result: String,
}

impl AuditRecord {
    /// Convenience constructor stamping `decided_at` with the current time.
    pub fn now(
        id: impl Into<String>,
        actor: impl Into<String>,
        operation: Operation,
        impact: Impact,
        decision: AuditDecision,
        reason: impl Into<String>,
        result: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            decided_at: utc_now(),
            actor: actor.into(),
            operation,
            impact,
            decision,
            reason: reason.into(),
            result: result.into(),
        }
    }
}

/// Minimal audit-log interface.
pub trait AuditLog {
    fn append(&mut self, record: AuditRecord);
    fn entries(&self) -> &[AuditRecord];
}

/// In-memory log. Append-only by API (no remove/replace methods), but with
/// no integrity properties beyond that — see module docs.
#[derive(Default)]
pub struct InMemoryAuditLog {
    entries: Vec<AuditRecord>,
}

impl InMemoryAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl AuditLog for InMemoryAuditLog {
    fn append(&mut self, record: AuditRecord) {
        self.entries.push(record);
    }

    fn entries(&self) -> &[AuditRecord] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_preserves_order() {
        let mut log = InMemoryAuditLog::new();
        assert!(log.is_empty());
        for i in 0..3 {
            log.append(AuditRecord::now(
                format!("audit-{i}"),
                "analyst-test",
                Operation::Observe,
                Impact::Low,
                AuditDecision::Allowed,
                "skeleton",
                "ok",
            ));
        }
        assert_eq!(log.len(), 3);
        assert_eq!(log.entries()[0].id, "audit-0");
        assert_eq!(log.entries()[2].id, "audit-2");
    }
}
