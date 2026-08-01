// Kernel usermode helper — the kernel -> userspace exec primitive.
//
// Module manifest:
//   uapi     UMH_* wait-mode flags, disable-depth enum, helper env/limits
//   info     `SubprocessInfo` request record + init/cleanup callback contract
//   gate     suspend/hibernate disable gate + running-helper accounting
//   backend  installable spawn backend (the piece that needs a live kernel)
//   exec     `call_usermodehelper{,_setup,_exec}` decision logic
//   pool     servicing-context growth rule (why one context is not enough)
//   spawn    the real backend: kworker hand-off, fork+exec, wait/reap
//
// Everything a caller's observable behavior depends on — gate answer, wait-mode
// return encoding, argv/env construction, exec-error propagation — lives in the
// UNGATED modules above `spawn`, so it is covered by hosted tests. `spawn` is
// the only target-gated module.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod uapi;
pub mod info;
pub mod gate;
pub mod backend;
pub mod exec;
pub mod env;
pub mod pool;

#[cfg(target_os = "oxide-kernel")]
pub mod spawn;

pub use uapi::{UMH_FREEZABLE, UMH_KILLABLE, UMH_NO_WAIT, UMH_WAIT_EXEC, UMH_WAIT_PROC,
               UmhDisableDepth};
pub use info::{CleanupFn, HelperCtx, InitFn, SubprocessInfo};
pub use exec::{call_usermodehelper, call_usermodehelper_exec, call_usermodehelper_setup};
pub use gate::{usermodehelper_disable, usermodehelper_enable, usermodehelper_disabled};

#[cfg(test)]
mod tests;
