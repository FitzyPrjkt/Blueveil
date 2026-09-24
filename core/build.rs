//! Build script: generates Rust contract types from the canonical `.proto`
//! files. Requires `PROTOC` (protoc binary) and `PROTOC_INCLUDE` (directory
//! containing `google/protobuf/*.proto`) in the environment, e.g.:
//!
//! ```sh
//! export PROTOC="$HOME/.local/protoc-36.1/bin/protoc"
//! export PROTOC_INCLUDE="$HOME/.local/protoc-36.1/include"
//! cargo build
//! ```
//!
//! The `.proto` files are the canonical contract. This script never edits
//! them; if codegen reveals a contract problem, the contract must be fixed
//! explicitly in `../contracts/proto`, never worked around here.

use std::env;
use std::path::PathBuf;

const PROTOS: [&str; 8] = [
    "blueveil/contracts/v1/common.proto",
    "blueveil/contracts/v1/asset.proto",
    "blueveil/contracts/v1/identity.proto",
    "blueveil/contracts/v1/telemetry.proto",
    "blueveil/contracts/v1/detection.proto",
    "blueveil/contracts/v1/evidence.proto",
    "blueveil/contracts/v1/validation.proto",
    "blueveil/contracts/v1/response.proto",
];

fn main() {
    let manifest =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"));
    let proto_root = manifest.join("../contracts/proto");
    let include_dir = PathBuf::from(
        env::var("PROTOC_INCLUDE").expect("PROTOC_INCLUDE must point at the protobuf include dir"),
    );
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));

    let inputs: Vec<PathBuf> = PROTOS.iter().map(|p| proto_root.join(p)).collect();
    let mut config = prost_build::Config::new();
    config.file_descriptor_set_path(out.join("contracts_descriptor.bin"));
    config
        .compile_protos(&inputs, &[&proto_root, &include_dir])
        .expect("prost codegen from ../contracts/proto failed");

    println!("cargo:rerun-if-changed=../contracts/proto");
    println!("cargo:rerun-if-env-changed=PROTOC_INCLUDE");
}
