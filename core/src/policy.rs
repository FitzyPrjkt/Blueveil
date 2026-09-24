//! Policy abstraction: answers "is this action allowed?" and nothing else.
//!
//! No policy language, no engine, no persistence. One trait (`Policy`), one
//! answer type (`PolicyDecision`), one test double (`StaticPolicy`). A real
//! engine arrives later behind the same trait.

use crate::domain::CoreError;

/// Operation type, deliberately separate from risk/impact (see `safety`).
/// Mirrors the approved Blueveil operation taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    Read,
    Observe,
    Analyze,
    Recommend,
    Write,
    Modify,
    Block,
    Isolate,
    Delete,
    Execute,
}

/// Impact (risk) level of an action, independent of its operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Impact {
    Low,
    Medium,
    High,
    Critical,
}

/// What is being decided about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRequest {
    pub actor: String,
    pub operation: Operation,
    pub impact: Impact,
}

/// The only three answers a policy may give.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
    RequireApproval { reason: String },
}

/// Minimal policy interface.
pub trait Policy {
    fn decide(&self, request: &ActionRequest) -> Result<PolicyDecision, CoreError>;
}

/// Fixed-answer policy: a test double and an explicit-default building block.
/// `deny_all` is the safe default for skeleton wiring; `allow_all` exists
/// only to make tests state what they assume.
#[derive(Debug, Clone)]
pub struct StaticPolicy {
    decision: PolicyDecision,
}

impl StaticPolicy {
    pub fn allow_all() -> Self {
        Self {
            decision: PolicyDecision::Allow,
        }
    }

    pub fn deny_all(reason: impl Into<String>) -> Self {
        Self {
            decision: PolicyDecision::Deny {
                reason: reason.into(),
            },
        }
    }

    pub fn require_approval(reason: impl Into<String>) -> Self {
        Self {
            decision: PolicyDecision::RequireApproval {
                reason: reason.into(),
            },
        }
    }
}

impl Policy for StaticPolicy {
    fn decide(&self, request: &ActionRequest) -> Result<PolicyDecision, CoreError> {
        if request.actor.is_empty() {
            return Err(CoreError::ContractViolation(
                "ActionRequest.actor: empty".to_string(),
            ));
        }
        Ok(self.decision.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> ActionRequest {
        ActionRequest {
            actor: "analyst-test".to_string(),
            operation: Operation::Observe,
            impact: Impact::Low,
        }
    }

    #[test]
    fn static_policies_answer_as_configured() {
        assert_eq!(
            StaticPolicy::allow_all().decide(&req()).unwrap(),
            PolicyDecision::Allow
        );
        assert!(matches!(
            StaticPolicy::deny_all("skeleton default")
                .decide(&req())
                .unwrap(),
            PolicyDecision::Deny { .. }
        ));
        assert!(matches!(
            StaticPolicy::require_approval("manual step")
                .decide(&req())
                .unwrap(),
            PolicyDecision::RequireApproval { .. }
        ));
    }

    #[test]
    fn anonymous_actor_is_rejected() {
        let mut r = req();
        r.actor.clear();
        assert!(StaticPolicy::allow_all().decide(&r).is_err());
    }
}
