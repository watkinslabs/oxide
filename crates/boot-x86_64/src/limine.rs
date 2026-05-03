// Limine protocol shim. All shared types live in `limine-proto`;
// this re-export keeps existing `boot_x86_64::limine::*` paths
// working while the crate sources types from one place.

pub use limine_proto::*;
