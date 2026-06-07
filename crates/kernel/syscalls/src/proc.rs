// P3-08 process-shaped syscalls. Each handler now lives in its own
// per-file module (one syscall, one file) per `docs/53 §0`; this file
// retains only the cross-crate re-exports for handlers whose real impl
// lives in other crates/modules, kept here because callers reach them
// via `crate::proc::*`.

#![cfg(target_os = "oxide-kernel")]

// `sys_rseq` + rseq_writeback live in `sched::rseq` (F86).
pub use sched::rseq::{sys_rseq, rseq_writeback};

// `sys_clock_nanosleep` real impl in `crate::clock_nanosleep`.
pub use crate::clock_nanosleep::sys_clock_nanosleep;

// `sys_getpriority` / `sys_setpriority` real impl in `crate::priority`.
pub use crate::priority::{sys_getpriority, sys_setpriority};
