//! Low-distortion pathname-resolution attribution for the debug syscall
//! profile. Production builds compile none of this module.

#![cfg(feature = "debug-resolve-cost")]

use core::sync::atomic::{AtomicU64, Ordering};

const NS_PER_MS: u64 = 1_000_000;
const MAY_LOOKUP: usize = 0;
const CHILD_LOOKUP: usize = 1;
const SYMLINK: usize = 2;
const N: usize = 3;
static NS: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static CNT: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static NAME: [&[u8]; N] = [b"may-lookup", b"child-lookup", b"symlink"];

fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

pub(crate) struct Span(usize, u64);

impl Span {
    #[inline]
    pub(crate) fn start(which: usize) -> Self { Self(which, now_ns()) }
}

impl Drop for Span {
    fn drop(&mut self) {
        if self.0 >= N { return; }
        NS[self.0].fetch_add(now_ns().saturating_sub(self.1), Ordering::Relaxed);
        CNT[self.0].fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn may_lookup() -> Span { Span::start(MAY_LOOKUP) }
pub(crate) fn child_lookup() -> Span { Span::start(CHILD_LOOKUP) }
pub(crate) fn symlink() -> Span { Span::start(SYMLINK) }

/// Emit resolver sub-phase totals beside the syscall profile. # C: O(N)
pub fn dump_resolve_cost() {
    for i in 0..N {
        let count = CNT[i].load(Ordering::Relaxed);
        if count == 0 { continue; }
        let ns = NS[i].load(Ordering::Relaxed);
        klog::write_raw(b"  resolve-phase "); klog::write_raw(NAME[i]);
        klog::write_raw(b" cnt="); klog::write_dec_u64(count);
        klog::write_raw(b" ms="); klog::write_dec_u64(ns / NS_PER_MS);
        klog::write_raw(b" avg_ns="); klog::write_dec_u64(ns / count);
        klog::write_raw(b"\n");
    }
}
