//! Extension registry skeleton + provider interfaces.
//!
//! Minimal lifecycle: register, get, list, health. Providers self-report a
//! contract version; the core never assumes it. No dynamic loading, no WASM,
//! no gRPC server — those arrive behind these same interfaces.
//!
//! `ValidationProvider` is the boundary through which external validators
//! (native checks, future scanners, a Redveil adapter) plug in. The core
//! only ever sees `ValidationRequest` in and `ValidationResult` out.

use std::collections::HashMap;

use crate::contracts::{
    check_validation_result, utc_now, ValidationRequest, ValidationResult, ValidationVerdict,
    CONTRACT_VERSION,
};
use crate::domain::CoreError;

/// Capability categories the registry can hold. A category, not a domain:
/// no per-domain (network/endpoint/cloud/…) implementation lives here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKind {
    TelemetrySource,
    DetectionRule,
    ThreatIntel,
    AssetProvider,
    ResponseProvider,
    ValidationProvider,
    ReportProvider,
}

/// Self-description every provider registers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderInfo {
    pub name: String,
    pub version: String,
    pub contract_version: String,
    pub kind: ProviderKind,
}

/// Minimal extension-registry interface.
pub trait ExtensionRegistry {
    fn register(&mut self, info: ProviderInfo) -> Result<(), CoreError>;
    fn get(&self, name: &str) -> Option<&ProviderInfo>;
    fn list(&self) -> Vec<&ProviderInfo>;
    fn set_health(&mut self, name: &str, healthy: bool) -> Result<(), CoreError>;
    fn health(&self, name: &str) -> Option<bool>;
}

/// In-memory registry. Health defaults to healthy until reported otherwise.
#[derive(Default)]
pub struct InMemoryRegistry {
    providers: HashMap<String, (ProviderInfo, bool)>,
}

impl InMemoryRegistry {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ExtensionRegistry for InMemoryRegistry {
    fn register(&mut self, info: ProviderInfo) -> Result<(), CoreError> {
        if info.name.is_empty() {
            return Err(CoreError::RegistryConflict(
                "provider name is empty".to_string(),
            ));
        }
        if self.providers.contains_key(&info.name) {
            return Err(CoreError::RegistryConflict(format!(
                "provider '{}' already registered",
                info.name
            )));
        }
        self.providers.insert(info.name.clone(), (info, true));
        Ok(())
    }

    fn get(&self, name: &str) -> Option<&ProviderInfo> {
        self.providers.get(name).map(|(info, _)| info)
    }

    fn list(&self) -> Vec<&ProviderInfo> {
        let mut out: Vec<&ProviderInfo> = self.providers.values().map(|(info, _)| info).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    fn set_health(&mut self, name: &str, healthy: bool) -> Result<(), CoreError> {
        match self.providers.get_mut(name) {
            Some((_, h)) => {
                *h = healthy;
                Ok(())
            }
            None => Err(CoreError::RegistryConflict(format!(
                "provider '{name}' unknown"
            ))),
        }
    }

    fn health(&self, name: &str) -> Option<bool> {
        self.providers.get(name).map(|(_, h)| *h)
    }
}

/// Boundary interface for control validation. Implementations live outside
/// the core (native validator, external scanner adapter, test mock).
pub trait ValidationProvider {
    fn info(&self) -> ProviderInfo;
    fn validate(&self, request: &ValidationRequest) -> Result<ValidationResult, CoreError>;
}

/// Test/standalone provider proving the core runs with NO external validator:
/// it answers every request with `NOT_TESTED` — an honest "no validation
/// performed", never a pass. A Redveil adapter would implement this same
/// trait in a separate crate and translate Redveil output into
/// `ValidationResult`; the core cannot tell the difference.
pub struct MockValidationProvider;

impl ValidationProvider for MockValidationProvider {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            name: "mock".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            contract_version: CONTRACT_VERSION.to_string(),
            kind: ProviderKind::ValidationProvider,
        }
    }

    fn validate(&self, request: &ValidationRequest) -> Result<ValidationResult, CoreError> {
        let result = ValidationResult {
            id: format!("vres-mock-{}", request.id),
            request_id: request.id.clone(),
            control_id: request.control_id.clone(),
            provider: "mock".to_string(),
            provider_version: env!("CARGO_PKG_VERSION").to_string(),
            contract_version: CONTRACT_VERSION.to_string(),
            verdict: ValidationVerdict::NotTested as i32,
            validated_at: Some(utc_now()),
            evidence_ids: Vec::new(),
            note: "no validator attached: NOT_TESTED, which is not a pass".to_string(),
        };
        // The core only emits contract-valid output.
        check_validation_result(&result).map(|()| result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(name: &str) -> ProviderInfo {
        ProviderInfo {
            name: name.to_string(),
            version: "0.0.0".to_string(),
            contract_version: CONTRACT_VERSION.to_string(),
            kind: ProviderKind::ValidationProvider,
        }
    }

    #[test]
    fn register_get_list_health_lifecycle() {
        let mut reg = InMemoryRegistry::new();
        reg.register(info("b")).unwrap();
        reg.register(info("a")).unwrap();
        assert_eq!(
            reg.list()
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(reg.health("a"), Some(true));
        reg.set_health("a", false).unwrap();
        assert_eq!(reg.health("a"), Some(false));
        assert_eq!(reg.health("ghost"), None);
    }

    #[test]
    fn duplicate_registration_conflicts() {
        let mut reg = InMemoryRegistry::new();
        reg.register(info("dup")).unwrap();
        assert!(matches!(
            reg.register(info("dup")),
            Err(CoreError::RegistryConflict(_))
        ));
    }

    #[test]
    fn mock_provider_returns_contract_valid_not_tested() {
        let provider = MockValidationProvider;
        let req = ValidationRequest {
            id: "vreq-x".to_string(),
            control_id: "ctrl-x".to_string(),
            target: "asset-x".to_string(),
            ..Default::default()
        };
        let res = provider.validate(&req).unwrap();
        assert_eq!(
            ValidationVerdict::try_from(res.verdict).unwrap(),
            ValidationVerdict::NotTested
        );
    }
}
