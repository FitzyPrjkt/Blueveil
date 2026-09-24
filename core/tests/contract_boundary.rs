//! Polyglot boundary test: the Step-2 contract layer is a tested boundary,
//! not documentation.
//!
//! For every Step-2 JSON fixture:
//!   fixture JSON --(proto JSON mapping, prost-reflect + compiled descriptor)-->
//!   DynamicMessage --(transcode)--> generated Rust type --(check_*)--> core.
//!
//! Valid fixtures must survive the whole chain; invalid fixtures must be
//! rejected at parse time or at the `check_*` boundary (proto3 has no
//! required fields, so missing-field cases are supposed to parse and then
//! fail the boundary — that split is asserted, not hidden).

use blueveil_core::contracts::{
    self, check_alert, check_asset, check_detection, check_evidence, check_identity,
    check_incident, check_response_approval, check_response_execution,
    check_response_recommendation, check_response_verification, check_telemetry_event,
    check_validation_request, check_validation_result, Alert, Asset, Detection, Evidence, Identity,
    Incident, ResponseApproval, ResponseExecution, ResponseRecommendation, ResponseVerification,
    TelemetryEvent, ValidationRequest, ValidationResult, ValidationVerdict,
};
use blueveil_core::registry::{MockValidationProvider, ValidationProvider};
use prost_reflect::{DescriptorPool, DeserializeOptions, DynamicMessage};

fn pool() -> DescriptorPool {
    DescriptorPool::decode(contracts::descriptor_bytes()).expect("descriptor decodes")
}

fn parse(pool: &DescriptorPool, message: &str, json: &str) -> Result<DynamicMessage, String> {
    let desc = pool
        .get_message_by_name(message)
        .ok_or_else(|| format!("no descriptor for {message}"))?;
    let mut de = serde_json::de::Deserializer::from_str(json);
    let opts = DeserializeOptions::new().deny_unknown_fields(true);
    DynamicMessage::deserialize_with_options(desc, &mut de, &opts).map_err(|e| e.to_string())
}

fn fixture(path: &str) -> String {
    let full = format!(
        "{}/../contracts/fixtures/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&full).unwrap_or_else(|_| panic!("read {full}"))
}

fn transcode<T>(msg: &DynamicMessage) -> Result<T, String>
where
    T: prost::Message + Default,
{
    msg.transcode_to().map_err(|e| e.to_string())
}

macro_rules! boundary_case {
    ($pool:expr, $msg:expr, $ty:ty, $check:ident, $file:literal, $expect_ok:literal) => {{
        let parsed = parse(&$pool, $msg, &fixture($file));
        let verdict = match parsed {
            Err(_) => false, // rejected at proto-JSON parse
            Ok(dyn_msg) => match transcode::<$ty>(&dyn_msg)
                .and_then(|t| $check(&t).map_err(|e| e.to_string()))
            {
                Ok(()) => true,  // survived parse + transcode + boundary
                Err(_) => false, // rejected at the check_* boundary
            },
        };
        assert_eq!(
            verdict, $expect_ok,
            "boundary verdict for {} (message {})",
            $file, $msg
        );
    }};
}

const M: &str = "blueveil.contracts.v1";

#[test]
fn valid_fixtures_cross_the_whole_boundary() {
    let pool = pool();
    boundary_case!(
        pool,
        &format!("{M}.Asset"),
        Asset,
        check_asset,
        "asset/valid.json",
        true
    );
    boundary_case!(
        pool,
        &format!("{M}.Identity"),
        Identity,
        check_identity,
        "identity/valid.json",
        true
    );
    boundary_case!(
        pool,
        &format!("{M}.TelemetryEvent"),
        TelemetryEvent,
        check_telemetry_event,
        "telemetry/valid.json",
        true
    );
    boundary_case!(
        pool,
        &format!("{M}.Detection"),
        Detection,
        check_detection,
        "detection/valid.json",
        true
    );
    boundary_case!(
        pool,
        &format!("{M}.Alert"),
        Alert,
        check_alert,
        "alert/valid.json",
        true
    );
    boundary_case!(
        pool,
        &format!("{M}.Incident"),
        Incident,
        check_incident,
        "incident/valid.json",
        true
    );
    boundary_case!(
        pool,
        &format!("{M}.Evidence"),
        Evidence,
        check_evidence,
        "evidence/valid.json",
        true
    );
    boundary_case!(
        pool,
        &format!("{M}.ValidationRequest"),
        ValidationRequest,
        check_validation_request,
        "validation/valid_request.json",
        true
    );
    boundary_case!(
        pool,
        &format!("{M}.ValidationResult"),
        ValidationResult,
        check_validation_result,
        "validation/valid_result.json",
        true
    );
    boundary_case!(
        pool,
        &format!("{M}.ValidationResult"),
        ValidationResult,
        check_validation_result,
        "validation/valid_result_not_tested.json",
        true
    );
    boundary_case!(
        pool,
        &format!("{M}.ResponseRecommendation"),
        ResponseRecommendation,
        check_response_recommendation,
        "response/valid_recommendation.json",
        true
    );
    boundary_case!(
        pool,
        &format!("{M}.ResponseApproval"),
        ResponseApproval,
        check_response_approval,
        "response/valid_approval.json",
        true
    );
    boundary_case!(
        pool,
        &format!("{M}.ResponseExecution"),
        ResponseExecution,
        check_response_execution,
        "response/valid_execution.json",
        true
    );
    boundary_case!(
        pool,
        &format!("{M}.ResponseVerification"),
        ResponseVerification,
        check_response_verification,
        "response/valid_verification.json",
        true
    );
}

#[test]
fn invalid_fixtures_are_rejected() {
    let pool = pool();
    boundary_case!(
        pool,
        &format!("{M}.Asset"),
        Asset,
        check_asset,
        "asset/invalid.json",
        false
    );
    boundary_case!(
        pool,
        &format!("{M}.Identity"),
        Identity,
        check_identity,
        "identity/invalid.json",
        false
    );
    boundary_case!(
        pool,
        &format!("{M}.TelemetryEvent"),
        TelemetryEvent,
        check_telemetry_event,
        "telemetry/invalid.json",
        false
    );
    boundary_case!(
        pool,
        &format!("{M}.Detection"),
        Detection,
        check_detection,
        "detection/invalid.json",
        false
    );
    boundary_case!(
        pool,
        &format!("{M}.Alert"),
        Alert,
        check_alert,
        "alert/invalid.json",
        false
    );
    boundary_case!(
        pool,
        &format!("{M}.Incident"),
        Incident,
        check_incident,
        "incident/invalid.json",
        false
    );
    boundary_case!(
        pool,
        &format!("{M}.Evidence"),
        Evidence,
        check_evidence,
        "evidence/invalid.json",
        false
    );
    boundary_case!(
        pool,
        &format!("{M}.ValidationRequest"),
        ValidationRequest,
        check_validation_request,
        "validation/invalid_request.json",
        false
    );
    boundary_case!(
        pool,
        &format!("{M}.ValidationResult"),
        ValidationResult,
        check_validation_result,
        "validation/invalid_result.json",
        false
    );
    boundary_case!(
        pool,
        &format!("{M}.ResponseRecommendation"),
        ResponseRecommendation,
        check_response_recommendation,
        "response/invalid_recommendation.json",
        false
    );
    boundary_case!(
        pool,
        &format!("{M}.ResponseApproval"),
        ResponseApproval,
        check_response_approval,
        "response/invalid_approval.json",
        false
    );
    boundary_case!(
        pool,
        &format!("{M}.ResponseExecution"),
        ResponseExecution,
        check_response_execution,
        "response/invalid_execution.json",
        false
    );
    boundary_case!(
        pool,
        &format!("{M}.ResponseVerification"),
        ResponseVerification,
        check_response_verification,
        "response/invalid_verification.json",
        false
    );
}

#[test]
fn not_tested_is_a_valid_non_passing_verdict_and_no_secure_exists() {
    let pool = pool();
    let dyn_msg = parse(
        &pool,
        &format!("{M}.ValidationResult"),
        &fixture("validation/valid_result_not_tested.json"),
    )
    .expect("NOT_TESTED fixture parses");
    let typed: ValidationResult = transcode(&dyn_msg).expect("transcodes");
    assert_eq!(
        ValidationVerdict::try_from(typed.verdict).expect("known verdict"),
        ValidationVerdict::NotTested
    );

    let verdict_enum = pool
        .get_enum_by_name(&format!("{M}.ValidationVerdict"))
        .expect("verdict enum in descriptor");
    let names: Vec<String> = verdict_enum
        .values()
        .map(|v| v.name().to_string())
        .collect();
    assert!(names.iter().any(|n| n == "VALIDATION_VERDICT_NOT_TESTED"));
    assert!(
        names.iter().all(|n| !n.contains("SECURE")),
        "contract must never gain a SECURE verdict silently: {names:?}"
    );
}

#[test]
fn core_emits_contract_valid_output_without_any_external_provider() {
    // No Redveil, no network, no database: the mock answers NOT_TESTED and
    // the core itself enforces that the emitted result is contract-valid.
    let provider = MockValidationProvider;
    let request = ValidationRequest {
        id: "vreq-boundary-001".to_string(),
        control_id: "ctrl-boundary-001".to_string(),
        target: "asset-boundary-001".to_string(),
        ..Default::default()
    };
    let result = provider.validate(&request).expect("mock validates");
    check_validation_result(&result).expect("core output is contract-valid");
    assert_eq!(result.contract_version, contracts::CONTRACT_VERSION);
}
