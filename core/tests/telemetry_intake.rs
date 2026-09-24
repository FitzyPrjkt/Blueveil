//! Cross-language intake proof: consumes canonical protojson-lines emitted
//! by the Go pipeline (Step 5) through the real contract boundary and the
//! existing `InProcessBus`.
//!
//! Wiring: run the Go self-test with `--emit-jsonl PATH`, then run this test
//! with `BLUEVEIL_TELEMETRY_JSONL=PATH`. When the variable is unset the test
//! passes with a loud skip notice — there is simply nothing to consume
//! (standalone `cargo test` stays green); the orchestrated verification in
//! the Step 5 report always sets it, so the real assertions execute there.
//!
//! This file is ADDITIVE: no existing core code was modified for Step 5.

use std::cell::RefCell;
use std::rc::Rc;

use blueveil_core::contracts::{self, check_telemetry_event, TelemetryEvent};
use blueveil_core::events::{EventConsumer, InProcessBus};
use prost_reflect::{DescriptorPool, DeserializeOptions, DynamicMessage};

struct Recorder {
    ids: Rc<RefCell<Vec<String>>>,
}

impl EventConsumer for Recorder {
    fn on_event(&mut self, event: &TelemetryEvent) {
        self.ids.borrow_mut().push(event.id.clone());
    }
}

#[test]
fn telemetry_intake_consumes_go_pipeline_output() {
    let path = match std::env::var("BLUEVEIL_TELEMETRY_JSONL") {
        Ok(p) => p,
        Err(_) => {
            eprintln!(
                "SKIPPED telemetry_intake: set BLUEVEIL_TELEMETRY_JSONL to Go-emitted \
                 protojson-lines (see collector --self-test --emit-jsonl) to run \
                 the cross-language intake proof"
            );
            return;
        }
    };

    let pool = DescriptorPool::decode(contracts::descriptor_bytes()).expect("descriptor decodes");
    let desc = pool
        .get_message_by_name("blueveil.contracts.v1.TelemetryEvent")
        .expect("TelemetryEvent in descriptor");
    let opts = DeserializeOptions::new().deny_unknown_fields(true);

    let text = std::fs::read_to_string(&path).expect("read intake file");
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "intake file must hold at least one event"
    );

    let seen: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let mut bus = InProcessBus::new();
    bus.subscribe(Recorder {
        ids: Rc::clone(&seen),
    });

    for line in &lines {
        let mut de = serde_json::de::Deserializer::from_str(line);
        let dyn_msg = DynamicMessage::deserialize_with_options(desc.clone(), &mut de, &opts)
            .expect("each emitted line parses under proto JSON mapping");
        let typed: TelemetryEvent = dyn_msg
            .transcode_to()
            .expect("transcodes to generated type");
        check_telemetry_event(&typed).expect("each emitted event is contract-valid");
        bus.publish(&typed);
    }

    let delivered = seen.borrow();
    assert_eq!(
        delivered.len(),
        lines.len(),
        "every consumed event must reach the bus consumer"
    );
    assert!(delivered.iter().all(|id| !id.is_empty()));
}
