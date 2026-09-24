//! Crate-level kernel: the shared failure vocabulary. No domain logic.

use std::fmt;

/// Failures the skeleton core can produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// A message violates the contract boundary (missing/invalid required data).
    ContractViolation(String),
    /// An illegal safety-state transition was attempted.
    IllegalTransition(String),
    /// A safety gate refused to open (e.g. Execute without approval).
    GateDenied(String),
    /// A provider name was registered twice with a conflicting definition.
    RegistryConflict(String),
    /// A provider failed to produce a contract-valid result.
    ValidationFailed(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContractViolation(m)
            | Self::IllegalTransition(m)
            | Self::GateDenied(m)
            | Self::RegistryConflict(m)
            | Self::ValidationFailed(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CoreError {}
