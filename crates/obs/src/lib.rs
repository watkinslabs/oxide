// Observability — klog + tracing + perf per docs/37.
//
// `counter.rs` — software `Counter`s (atomic u64) + global registry
// for `/proc/stat`-style enumeration.
// `tracepoint.rs` — `TracePoint` enable bit + `Tracer` callback +
// global registry for `tracefs` listing.
//
// klog itself lives in `crates/klog/`. The hardware perf-event
// (`perf_event_open`) path needs HAL CpuOps and rides later.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod counter;
pub mod tracepoint;

pub use counter::Counter;
pub use tracepoint::{TracePoint, Tracer};

#[cfg(test)]
mod tests;

/// Subsystem-level error per `38`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NotImplemented,
    NoMem,
    Inval,
    Io,
}

#[allow(dead_code)]
pub(crate) type StubResult<T> = core::result::Result<T, Error>;

/// Initialization entry; called by the kernel boot phase per `00§3` /
/// `boot-flow.md`. v1 returns `NotImplemented`; bodies in P1-N.
///
/// # SAFETY: caller is the boot path, runs single-CPU with IRQs off
/// per `boot-flow.md`. Subsystem-specific preconditions documented at
/// the implementation site.
///
/// # C: O(N_pfn) once at boot
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> StubResult<()> {
    klog::kinfo!("obs: init stub");
    Err(Error::NotImplemented)
}

#[cfg(test)]
mod stub_tests {
    use super::*;

    #[test]
    fn init_returns_not_implemented() {
        // SAFETY: hosted-test entry; nothing else has touched the subsystem; init's preconditions trivially hold.
        let r = unsafe { init() };
        assert_eq!(r, Err(Error::NotImplemented));
    }
}
