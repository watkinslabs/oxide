// Thin re-export shim per `52§8` migration. Implementation lives in
// `crates/pipe`. Existing `crate::dev_pipe::*` callers compile
// unchanged; shim disappears at Stage C. Not cfg-gated — the shim
// itself is body-free; the pipe crate keeps its own
// `#![cfg(target_os = "oxide-kernel")]` so the body only exists in
// kernel builds.

pub use pipe::*;
