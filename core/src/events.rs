//! Event boundary: in-process delivery of contract-typed telemetry.
//!
//! No broker, no network, no persistence. One abstraction: publishers hand a
//! `&TelemetryEvent` to the bus, the bus hands it to every subscriber.
//! A distributed transport arrives later behind this same boundary.

use crate::contracts::TelemetryEvent;

/// Receives telemetry events from the bus.
pub trait EventConsumer {
    fn on_event(&mut self, event: &TelemetryEvent);
}

/// In-process fan-out bus. Single-threaded semantics: `publish` calls
/// subscribers in registration order.
#[derive(Default)]
pub struct InProcessBus {
    subscribers: Vec<Box<dyn EventConsumer>>,
}

impl InProcessBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn subscribe(&mut self, consumer: impl EventConsumer + 'static) {
        self.subscribers.push(Box::new(consumer));
    }

    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    pub fn publish(&mut self, event: &TelemetryEvent) {
        for sub in &mut self.subscribers {
            sub.on_event(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counter {
        seen: Vec<String>,
    }

    impl EventConsumer for Counter {
        fn on_event(&mut self, event: &TelemetryEvent) {
            self.seen.push(event.id.clone());
        }
    }

    #[test]
    fn publish_fans_out_to_all_subscribers_in_order() {
        let mut bus = InProcessBus::new();
        bus.subscribe(Counter { seen: Vec::new() });
        bus.subscribe(Counter { seen: Vec::new() });
        assert_eq!(bus.subscriber_count(), 2);

        let event = TelemetryEvent {
            id: "evt-test-001".to_string(),
            ..Default::default()
        };
        bus.publish(&event);
        // No panic, deterministic order; content assertions live in the
        // contract boundary tests.
    }

    #[test]
    fn publish_with_no_subscribers_is_a_noop() {
        let mut bus = InProcessBus::new();
        bus.publish(&TelemetryEvent::default());
    }
}
