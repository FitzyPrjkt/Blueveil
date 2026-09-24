//! Safety skeleton: state flow + operation/impact gating.
//!
//! States advance linearly OBSERVE → ANALYZE → RECOMMEND → CONFIRM → EXECUTE
//! → VERIFY → AUDIT. There is deliberately no "jump" API: illegal transitions
//! are unrepresentable, and entering EXECUTE additionally requires an
//! approval gate. No real BLOCK/ISOLATE/DELETE/EXECUTE exists here — this
//! module only proves transitions and gates can be represented correctly.
//!
//! Composition note: `required_gate` returns `Automatic` for low-impact
//! read-only work, but a `Policy` may still answer `RequireApproval`
//! (e.g. for MEDIUM impact). Policy and safety compose in the caller;
//! `tests/` shows the pattern.

use crate::domain::CoreError;
use crate::policy::{Impact, Operation};

/// Safety lifecycle states, in legal order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyState {
    Observe,
    Analyze,
    Recommend,
    Confirm,
    Execute,
    Verify,
    Audit,
}

/// What the gate demands before a transition may happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// No human needed for this step.
    Automatic,
    /// A human approval must be presented.
    Approved,
}

impl SafetyState {
    pub fn first() -> Self {
        Self::Observe
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Audit)
    }

    fn next(&self) -> Option<Self> {
        match self {
            Self::Observe => Some(Self::Analyze),
            Self::Analyze => Some(Self::Recommend),
            Self::Recommend => Some(Self::Confirm),
            Self::Confirm => Some(Self::Execute),
            Self::Execute => Some(Self::Verify),
            Self::Verify => Some(Self::Audit),
            Self::Audit => None,
        }
    }

    /// Advance one step. Entering EXECUTE requires `Gate::Approved`;
    /// AUDIT is terminal. Because there is no jump API, any other illegal
    /// transition is a compile-time impossibility, not a runtime check.
    pub fn advance(&self, gate: &Gate) -> Result<Self, CoreError> {
        match (self, gate) {
            (Self::Audit, _) => Err(CoreError::IllegalTransition(
                "AUDIT is terminal: no transition out".to_string(),
            )),
            (Self::Confirm, Gate::Automatic) => Err(CoreError::GateDenied(
                "entering EXECUTE requires an approval gate".to_string(),
            )),
            (state, _) => state
                .next()
                .ok_or_else(|| CoreError::IllegalTransition("no successor state".to_string())),
        }
    }
}

/// Skeleton gate policy: destructive operations always need approval, as does
/// HIGH/CRITICAL impact regardless of operation. Everything else is
/// `Automatic` — subject to the caller's `Policy`, which may still demand
/// approval.
pub struct SafetyEngine;

impl SafetyEngine {
    pub fn required_gate(operation: &Operation, impact: &Impact) -> Gate {
        match operation {
            Operation::Block | Operation::Isolate | Operation::Delete | Operation::Execute => {
                Gate::Approved
            }
            Operation::Read
            | Operation::Observe
            | Operation::Analyze
            | Operation::Recommend
            | Operation::Write
            | Operation::Modify => match impact {
                Impact::High | Impact::Critical => Gate::Approved,
                Impact::Low | Impact::Medium => Gate::Automatic,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_walk_with_approval_reaches_audit() {
        let mut state = SafetyState::first();
        let gates = [
            Gate::Automatic, // Observe -> Analyze
            Gate::Automatic, // Analyze -> Recommend
            Gate::Automatic, // Recommend -> Confirm
            Gate::Approved,  // Confirm -> Execute
            Gate::Automatic, // Execute -> Verify
            Gate::Automatic, // Verify -> Audit
        ];
        for gate in &gates {
            state = state.advance(gate).unwrap();
        }
        assert_eq!(state, SafetyState::Audit);
        assert!(state.is_terminal());
        assert!(state.advance(&Gate::Approved).is_err());
    }

    #[test]
    fn execute_without_approval_is_denied() {
        let mut state = SafetyState::first();
        for _ in 0..3 {
            state = state.advance(&Gate::Automatic).unwrap();
        }
        assert_eq!(state, SafetyState::Confirm);
        assert!(matches!(
            state.advance(&Gate::Automatic),
            Err(CoreError::GateDenied(_))
        ));
    }

    #[test]
    fn destructive_operations_always_require_approval() {
        for op in [
            Operation::Block,
            Operation::Isolate,
            Operation::Delete,
            Operation::Execute,
        ] {
            assert_eq!(
                SafetyEngine::required_gate(&op, &Impact::Low),
                Gate::Approved
            );
        }
        assert_eq!(
            SafetyEngine::required_gate(&Operation::Observe, &Impact::Critical),
            Gate::Approved
        );
        assert_eq!(
            SafetyEngine::required_gate(&Operation::Observe, &Impact::Low),
            Gate::Automatic
        );
    }
}
