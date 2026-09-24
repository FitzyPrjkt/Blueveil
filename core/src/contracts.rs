//! Contract boundary.
//!
//! Types are generated from `../contracts/proto` by `build.rs` (prost
//! codegen) and re-exported here. Business logic NEVER re-models them.
//!
//! proto3 cannot express requiredness, ranges or patterns, so the explicit
//! `check_*` functions below enforce the boundary rules. Their required sets
//! mirror the `required` arrays of the JSON Schemas in
//! `../contracts/jsonschema`; any drift between the two is a bug in one of
//! them, caught by `tests/contract_boundary.rs`.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::CoreError;

pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/blueveil.contracts.v1.rs"));
}

pub use v1::{
    Alert, AlertStatus, Asset, AssetStatus, AssetType, Detection, Evidence, EvidenceType, Identity,
    IdentityType, Incident, IncidentStatus, OperationType, ResponseApproval, ResponseExecution,
    ResponseRecommendation, ResponseStatus, ResponseVerification, RiskLevel, Severity,
    TelemetryEvent, ValidationRequest, ValidationResult, ValidationVerdict, VerificationOutcome,
};

/// Contract package this core speaks. `ValidationResult.contract_version`
/// must equal this; anything else is rejected (no speculative negotiation).
pub const CONTRACT_VERSION: &str = "blueveil.contracts.v1";

/// Compiled `FileDescriptorSet` of the contracts, for reflection-based tests.
pub fn descriptor_bytes() -> &'static [u8] {
    include_bytes!(concat!(env!("OUT_DIR"), "/contracts_descriptor.bin"))
}

/// Current UTC time as a protobuf `Timestamp` (for audit/validation records).
pub fn utc_now() -> prost_types::Timestamp {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    prost_types::Timestamp {
        seconds: elapsed.as_secs() as i64,
        nanos: elapsed.subsec_nanos() as i32,
    }
}

fn req(value: &str, what: &'static str) -> Result<(), CoreError> {
    if value.is_empty() {
        return Err(CoreError::ContractViolation(format!("{what}: empty")));
    }
    Ok(())
}

fn check_severity(value: i32, what: &'static str) -> Result<(), CoreError> {
    let sev = Severity::try_from(value)
        .map_err(|_| CoreError::ContractViolation(format!("{what}: unknown severity {value}")))?;
    if sev == Severity::Unspecified {
        return Err(CoreError::ContractViolation(format!(
            "{what}: severity must be explicit, never UNSPECIFIED"
        )));
    }
    Ok(())
}

fn check_timestamp(
    ts: &Option<prost_types::Timestamp>,
    what: &'static str,
) -> Result<(), CoreError> {
    let t = ts
        .as_ref()
        .ok_or_else(|| CoreError::ContractViolation(format!("{what}: missing timestamp")))?;
    // Presence is not validity: native-constructed timestamps bypass the
    // RFC3339 parser, so range-check explicitly (parity with Go
    // requireTimestamp/CheckValid).
    if !(0..1_000_000_000).contains(&t.nanos) {
        return Err(CoreError::ContractViolation(format!(
            "{what}: invalid timestamp (nanos out of range)"
        )));
    }
    Ok(())
}

fn check_id_list(ids: &[String], what: &'static str) -> Result<(), CoreError> {
    if ids.is_empty() || ids.iter().any(String::is_empty) {
        return Err(CoreError::ContractViolation(format!(
            "{what}: requires at least one non-empty id"
        )));
    }
    Ok(())
}

macro_rules! check_enum {
    ($ty:ty, $value:expr, $what:expr) => {{
        let v = <$ty>::try_from($value).map_err(|_| {
            CoreError::ContractViolation(format!("{}: unknown value {}", $what, $value))
        })?;
        if v == <$ty>::Unspecified {
            return Err(CoreError::ContractViolation(format!(
                "{}: must be explicit, never UNSPECIFIED",
                $what
            )));
        }
    }};
}

/// Mirrors `asset.schema.json` required: id, type, name.
/// Step-13A fields (environment, status, first/last_seen, attributes) are
/// optional for backward compatibility; when present they must be explicit
/// (never UNSPECIFIED/empty timestamps).
pub fn check_asset(a: &Asset) -> Result<(), CoreError> {
    req(&a.id, "Asset.id")?;
    check_enum!(AssetType, a.r#type, "Asset.type");
    req(&a.name, "Asset.name")?;
    for id in &a.identifiers {
        req(&id.r#type, "Asset.identifiers[].type")?;
        req(&id.value, "Asset.identifiers[].value")?;
    }
    if a.criticality != 0 {
        check_severity(a.criticality, "Asset.criticality")?;
    }
    if a.status != 0 {
        check_enum!(AssetStatus, a.status, "Asset.status");
    }
    if a.first_seen.is_some() {
        check_timestamp(&a.first_seen, "Asset.first_seen")?;
    }
    if a.last_seen.is_some() {
        check_timestamp(&a.last_seen, "Asset.last_seen")?;
    }
    // Cross-field rule, parity with Go ValidateAsset: last_seen without
    // first_seen is not a lifecycle.
    if a.first_seen.is_none() && a.last_seen.is_some() {
        return Err(CoreError::ContractViolation(
            "Asset.last_seen without first_seen".to_string(),
        ));
    }
    Ok(())
}

/// Mirrors `identity.schema.json` required: id, type, name.
pub fn check_identity(i: &Identity) -> Result<(), CoreError> {
    req(&i.id, "Identity.id")?;
    check_enum!(IdentityType, i.r#type, "Identity.type");
    req(&i.name, "Identity.name")?;
    Ok(())
}

/// Mirrors `telemetry_event.schema.json` required:
/// id, occurred_at, source, asset_id, event_type, severity.
pub fn check_telemetry_event(e: &TelemetryEvent) -> Result<(), CoreError> {
    req(&e.id, "TelemetryEvent.id")?;
    check_timestamp(&e.occurred_at, "TelemetryEvent.occurred_at")?;
    req(&e.source, "TelemetryEvent.source")?;
    req(&e.asset_id, "TelemetryEvent.asset_id")?;
    if !e.identity_id.is_empty() {
        req(&e.identity_id, "TelemetryEvent.identity_id")?;
    }
    req(&e.event_type, "TelemetryEvent.event_type")?;
    check_severity(e.severity, "TelemetryEvent.severity")?;
    Ok(())
}

/// Mirrors `detection.schema.json` required: id, rule_id, rule_name,
/// telemetry_event_ids (non-empty), detected_at, severity, confidence [0,1], title.
pub fn check_detection(d: &Detection) -> Result<(), CoreError> {
    req(&d.id, "Detection.id")?;
    req(&d.rule_id, "Detection.rule_id")?;
    req(&d.rule_name, "Detection.rule_name")?;
    check_id_list(&d.telemetry_event_ids, "Detection.telemetry_event_ids")?;
    check_timestamp(&d.detected_at, "Detection.detected_at")?;
    check_severity(d.severity, "Detection.severity")?;
    if !(0.0..=1.0).contains(&d.confidence) {
        return Err(CoreError::ContractViolation(format!(
            "Detection.confidence: {} out of [0.0, 1.0]",
            d.confidence
        )));
    }
    req(&d.title, "Detection.title")?;
    Ok(())
}

/// Mirrors `alert.schema.json` required: id, detection_ids (non-empty),
/// status, severity, created_at, updated_at, title.
pub fn check_alert(a: &Alert) -> Result<(), CoreError> {
    req(&a.id, "Alert.id")?;
    check_id_list(&a.detection_ids, "Alert.detection_ids")?;
    check_enum!(AlertStatus, a.status, "Alert.status");
    check_severity(a.severity, "Alert.severity")?;
    check_timestamp(&a.created_at, "Alert.created_at")?;
    check_timestamp(&a.updated_at, "Alert.updated_at")?;
    req(&a.title, "Alert.title")?;
    Ok(())
}

/// Mirrors `incident.schema.json` required: id, alert_ids (non-empty),
/// status, severity, created_at, updated_at, title.
pub fn check_incident(i: &Incident) -> Result<(), CoreError> {
    req(&i.id, "Incident.id")?;
    check_id_list(&i.alert_ids, "Incident.alert_ids")?;
    check_enum!(IncidentStatus, i.status, "Incident.status");
    check_severity(i.severity, "Incident.severity")?;
    check_timestamp(&i.created_at, "Incident.created_at")?;
    check_timestamp(&i.updated_at, "Incident.updated_at")?;
    req(&i.title, "Incident.title")?;
    Ok(())
}

/// Mirrors `evidence.schema.json` required: id, incident_id, type,
/// collected_at, source, media_type, content. sha256, when present, must be
/// lowercase hex (64 chars).
pub fn check_evidence(e: &Evidence) -> Result<(), CoreError> {
    req(&e.id, "Evidence.id")?;
    req(&e.incident_id, "Evidence.incident_id")?;
    check_enum!(EvidenceType, e.r#type, "Evidence.type");
    check_timestamp(&e.collected_at, "Evidence.collected_at")?;
    req(&e.source, "Evidence.source")?;
    req(&e.media_type, "Evidence.media_type")?;
    if !e.sha256.is_empty()
        && !(e.sha256.len() == 64
            && e.sha256
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    {
        return Err(CoreError::ContractViolation(
            "Evidence.sha256: must be 64 lowercase-hex chars when present".to_string(),
        ));
    }
    req(&e.content, "Evidence.content")?;
    Ok(())
}

/// Mirrors `validation_request.schema.json` required:
/// id, control_id, target, requested_at.
pub fn check_validation_request(r: &ValidationRequest) -> Result<(), CoreError> {
    req(&r.id, "ValidationRequest.id")?;
    req(&r.control_id, "ValidationRequest.control_id")?;
    req(&r.target, "ValidationRequest.target")?;
    check_timestamp(&r.requested_at, "ValidationRequest.requested_at")?;
    Ok(())
}

/// Mirrors `validation_result.schema.json` required: id, request_id,
/// control_id, provider, contract_version, verdict, validated_at.
/// There is deliberately no SECURE verdict; NOT_TESTED is a valid,
/// non-passing outcome.
pub fn check_validation_result(r: &ValidationResult) -> Result<(), CoreError> {
    req(&r.id, "ValidationResult.id")?;
    req(&r.request_id, "ValidationResult.request_id")?;
    req(&r.control_id, "ValidationResult.control_id")?;
    req(&r.provider, "ValidationResult.provider")?;
    if r.contract_version != CONTRACT_VERSION {
        return Err(CoreError::ContractViolation(format!(
            "ValidationResult.contract_version: '{}' unsupported, core speaks '{CONTRACT_VERSION}'",
            r.contract_version
        )));
    }
    let verdict = ValidationVerdict::try_from(r.verdict).map_err(|_| {
        CoreError::ContractViolation(format!("ValidationResult.verdict: unknown {}", r.verdict))
    })?;
    if verdict == ValidationVerdict::Unspecified {
        return Err(CoreError::ContractViolation(
            "ValidationResult.verdict: must be explicit, never UNSPECIFIED".to_string(),
        ));
    }
    check_timestamp(&r.validated_at, "ValidationResult.validated_at")?;
    for id in &r.evidence_ids {
        req(id, "ValidationResult.evidence_ids[]")?;
    }
    Ok(())
}

fn check_operation(value: i32, what: &'static str) -> Result<(), CoreError> {
    let op = OperationType::try_from(value)
        .map_err(|_| CoreError::ContractViolation(format!("{what}: unknown operation {value}")))?;
    if op == OperationType::Unspecified {
        return Err(CoreError::ContractViolation(format!(
            "{what}: operation must be explicit, never UNSPECIFIED"
        )));
    }
    Ok(())
}

fn check_risk(value: i32, what: &'static str) -> Result<(), CoreError> {
    let risk = RiskLevel::try_from(value)
        .map_err(|_| CoreError::ContractViolation(format!("{what}: unknown risk {value}")))?;
    if risk == RiskLevel::Unspecified {
        return Err(CoreError::ContractViolation(format!(
            "{what}: risk must be explicit, never UNSPECIFIED"
        )));
    }
    Ok(())
}

fn check_response_status(value: i32, what: &'static str) -> Result<(), CoreError> {
    let st = ResponseStatus::try_from(value)
        .map_err(|_| CoreError::ContractViolation(format!("{what}: unknown status {value}")))?;
    if st == ResponseStatus::Unspecified {
        return Err(CoreError::ContractViolation(format!(
            "{what}: status must be explicit, never UNSPECIFIED"
        )));
    }
    Ok(())
}

/// Mirrors `response_recommendation.schema.json`.
pub fn check_response_recommendation(r: &ResponseRecommendation) -> Result<(), CoreError> {
    req(&r.id, "ResponseRecommendation.id")?;
    req(&r.incident_id, "ResponseRecommendation.incident_id")?;
    check_operation(r.operation, "ResponseRecommendation.operation")?;
    req(&r.target, "ResponseRecommendation.target")?;
    check_risk(r.risk, "ResponseRecommendation.risk")?;
    req(&r.reason, "ResponseRecommendation.reason")?;
    check_response_status(r.status, "ResponseRecommendation.status")?;
    check_timestamp(&r.recommended_at, "ResponseRecommendation.recommended_at")?;
    req(&r.recommended_by, "ResponseRecommendation.recommended_by")?;
    Ok(())
}

/// Mirrors `response_approval.schema.json`.
pub fn check_response_approval(a: &ResponseApproval) -> Result<(), CoreError> {
    req(&a.id, "ResponseApproval.id")?;
    req(&a.recommendation_id, "ResponseApproval.recommendation_id")?;
    check_operation(a.operation, "ResponseApproval.operation")?;
    req(&a.target, "ResponseApproval.target")?;
    check_risk(a.risk, "ResponseApproval.risk")?;
    req(&a.approver, "ResponseApproval.approver")?;
    check_timestamp(&a.approved_at, "ResponseApproval.approved_at")?;
    req(&a.reason, "ResponseApproval.reason")?;
    Ok(())
}

/// Mirrors `response_execution.schema.json`. `success` reports what the
/// executor did — never "secured".
pub fn check_response_execution(e: &ResponseExecution) -> Result<(), CoreError> {
    req(&e.id, "ResponseExecution.id")?;
    req(&e.recommendation_id, "ResponseExecution.recommendation_id")?;
    check_operation(e.operation, "ResponseExecution.operation")?;
    req(&e.target, "ResponseExecution.target")?;
    check_timestamp(&e.started_at, "ResponseExecution.started_at")?;
    check_timestamp(&e.finished_at, "ResponseExecution.finished_at")?;
    req(&e.detail, "ResponseExecution.detail")?;
    Ok(())
}

/// Mirrors `response_verification.schema.json`. UNKNOWN is valid and
/// non-passing.
pub fn check_response_verification(v: &ResponseVerification) -> Result<(), CoreError> {
    req(&v.id, "ResponseVerification.id")?;
    req(&v.execution_id, "ResponseVerification.execution_id")?;
    let outcome = VerificationOutcome::try_from(v.outcome).map_err(|_| {
        CoreError::ContractViolation(format!(
            "ResponseVerification.outcome: unknown {}",
            v.outcome
        ))
    })?;
    if outcome == VerificationOutcome::Unspecified {
        return Err(CoreError::ContractViolation(
            "ResponseVerification.outcome: must be explicit, never UNSPECIFIED".to_string(),
        ));
    }
    check_timestamp(&v.verified_at, "ResponseVerification.verified_at")?;
    req(&v.detail, "ResponseVerification.detail")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_version_is_v1() {
        assert_eq!(CONTRACT_VERSION, "blueveil.contracts.v1");
    }

    #[test]
    fn legacy_asset_without_step13a_fields_still_valid() {
        // Backward compatibility: pre-13A payloads (no status/timestamps)
        // must keep passing.
        let a = Asset {
            id: "asset-x".to_string(),
            r#type: AssetType::Host as i32,
            name: "h".to_string(),
            ..Default::default()
        };
        assert!(check_asset(&a).is_ok());
    }

    #[test]
    fn asset_lifecycle_fields_validated_when_present() {
        let mut a = Asset {
            id: "asset-x".to_string(),
            r#type: AssetType::Domain as i32,
            name: "example.com".to_string(),
            status: AssetStatus::Active as i32,
            first_seen: Some(utc_now()),
            last_seen: Some(utc_now()),
            ..Default::default()
        };
        assert!(check_asset(&a).is_ok());
        // Zero status stays lenient for legacy records (the JSON Schema
        // boundary rejects explicit UNSPECIFIED); unknown values fail here.
        a.status = 99;
        assert!(check_asset(&a).is_err());
    }

    #[test]
    fn empty_telemetry_event_is_rejected() {
        let e = TelemetryEvent::default();
        assert!(matches!(
            check_telemetry_event(&e),
            Err(CoreError::ContractViolation(_))
        ));
    }

    #[test]
    fn confidence_out_of_range_is_rejected() {
        let d = Detection {
            id: "det-x".to_string(),
            rule_id: "r".to_string(),
            rule_name: "r".to_string(),
            telemetry_event_ids: vec!["evt-x".to_string()],
            detected_at: Some(utc_now()),
            severity: Severity::High as i32,
            confidence: 1.5,
            title: "t".to_string(),
            ..Default::default()
        };
        assert!(check_detection(&d).is_err());
        // NaN defeats naive range checks (all comparisons false): it must
        // fail explicitly, in parity with Go ValidateDetection.
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let nan = Detection {
                confidence: bad,
                ..d.clone()
            };
            assert!(
                check_detection(&nan).is_err(),
                "confidence {bad} must be rejected"
            );
        }
    }

    #[test]
    fn uppercase_sha256_is_rejected() {
        // Parity with Go + JSON Schema: lowercase hex only.
        let e = Evidence {
            id: "ev-x".to_string(),
            incident_id: "inc-x".to_string(),
            r#type: EvidenceType::Note as i32,
            collected_at: Some(utc_now()),
            source: "s".to_string(),
            media_type: "text/plain".to_string(),
            sha256: "A".repeat(64),
            content: "c".to_string(),
        };
        assert!(check_evidence(&e).is_err());
        let ok = Evidence {
            sha256: "a".repeat(64),
            ..e
        };
        assert!(check_evidence(&ok).is_ok());
    }

    #[test]
    fn last_seen_without_first_seen_is_rejected() {
        // Parity with Go ValidateAsset.
        let a = Asset {
            id: "asset-x".to_string(),
            r#type: AssetType::Host as i32,
            name: "h".to_string(),
            last_seen: Some(utc_now()),
            ..Default::default()
        };
        assert!(check_asset(&a).is_err());
    }

    #[test]
    fn malformed_timestamps_are_rejected() {
        // Nanos out of range must fail even though a timestamp is present.
        let bad_nanos = prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: 1_000_000_000,
        };
        let d = Detection {
            id: "det-x".to_string(),
            rule_id: "r".to_string(),
            rule_name: "r".to_string(),
            telemetry_event_ids: vec!["evt-x".to_string()],
            detected_at: Some(bad_nanos),
            severity: Severity::High as i32,
            confidence: 0.5,
            title: "t".to_string(),
            ..Default::default()
        };
        assert!(check_detection(&d).is_err());
    }

    #[test]
    fn sha256_pattern_is_enforced() {
        let e = Evidence {
            id: "ev-x".to_string(),
            incident_id: "inc-x".to_string(),
            r#type: EvidenceType::Note as i32,
            collected_at: Some(utc_now()),
            source: "s".to_string(),
            media_type: "text/plain".to_string(),
            sha256: "NOT-A-HASH".to_string(),
            content: "c".to_string(),
        };
        assert!(check_evidence(&e).is_err());
        let e2 = Evidence {
            sha256: String::new(),
            ..e
        };
        assert!(check_evidence(&e2).is_ok());
    }

    fn valid_recommendation() -> ResponseRecommendation {
        ResponseRecommendation {
            id: "rec-x".to_string(),
            incident_id: "inc-x".to_string(),
            operation: OperationType::Recommend as i32,
            target: "asset-x".to_string(),
            risk: RiskLevel::High as i32,
            reason: "review".to_string(),
            status: ResponseStatus::Proposed as i32,
            recommended_at: Some(utc_now()),
            recommended_by: "blueveil-recommender/1".to_string(),
            approval_required: true,
        }
    }

    #[test]
    fn response_recommendation_boundary() {
        assert!(check_response_recommendation(&valid_recommendation()).is_ok());
        let mut r = valid_recommendation();
        r.operation = OperationType::Unspecified as i32;
        assert!(check_response_recommendation(&r).is_err());
        let mut r = valid_recommendation();
        r.status = ResponseStatus::Unspecified as i32;
        assert!(check_response_recommendation(&r).is_err());
    }

    #[test]
    fn response_approval_boundary() {
        let a = ResponseApproval {
            id: "appr-x".to_string(),
            recommendation_id: "rec-x".to_string(),
            operation: OperationType::Recommend as i32,
            target: "asset-x".to_string(),
            risk: RiskLevel::High as i32,
            approver: "test-actor:x".to_string(),
            approved_at: Some(utc_now()),
            expires_at: None,
            reason: "ok".to_string(),
        };
        assert!(check_response_approval(&a).is_ok());
        let mut bad = a;
        bad.risk = RiskLevel::Unspecified as i32;
        assert!(check_response_approval(&bad).is_err());
    }

    #[test]
    fn response_execution_and_verification_boundary() {
        let e = ResponseExecution {
            id: "exec-x".to_string(),
            recommendation_id: "rec-x".to_string(),
            approval_id: String::new(),
            operation: OperationType::Recommend as i32,
            target: "asset-x".to_string(),
            started_at: Some(utc_now()),
            finished_at: Some(utc_now()),
            success: true,
            detail: "simulated".to_string(),
        };
        assert!(check_response_execution(&e).is_ok());
        let v = ResponseVerification {
            id: "verif-x".to_string(),
            execution_id: "exec-x".to_string(),
            outcome: VerificationOutcome::Unknown as i32,
            verified_at: Some(utc_now()),
            detail: "no source".to_string(),
        };
        assert!(check_response_verification(&v).is_ok());
        let mut bad = v;
        bad.outcome = VerificationOutcome::Unspecified as i32;
        assert!(check_response_verification(&bad).is_err());
    }
}
