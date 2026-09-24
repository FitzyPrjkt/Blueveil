//! `blueveil-core` — skeleton of the Blueveil control plane.
//!
//! Scope (Step 3): prove the core can be built on the contract layer with
//! generated types only. In scope: contract boundary validation, in-process
//! event bus, extension registry skeleton (incl. `ValidationProvider` trait),
//! minimal policy abstraction, safety state skeleton, append-only audit log.
//!
//! Explicitly NOT in scope: network, database, message broker, web framework,
//! detection engine, collectors, UI, dynamic plugins, WASM, gRPC server,
//! any Redveil dependency. See `README.md`.

pub mod audit;
pub mod contracts;
pub mod domain;
pub mod events;
pub mod policy;
pub mod registry;
pub mod safety;

pub use domain::CoreError;
