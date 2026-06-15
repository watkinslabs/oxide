//! rt — POSIX realtime (docs/59§6 G17b): extra clocks, per-process timers,
//! unnamed semaphores, message queues. Thin ABI shims over the kernel; the one
//! piece of real logic (the semaphore value transition) is a pure, hosted-
//! tested state machine. Struct layouts are ABI-checked vs the libc crate.

/// time-spec pair, layout-identical to `struct timespec` (always built so the
/// rt structs are testable without the freestanding `time::clock` module).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timespec { pub tv_sec: i64, pub tv_nsec: i64 }

pub mod sem;
pub mod timer;
pub mod mqueue;
#[cfg(feature = "freestanding")]
pub mod clock_extra;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timespec_abi() { assert_eq!(core::mem::size_of::<Timespec>(), core::mem::size_of::<libc::timespec>()); }
}
