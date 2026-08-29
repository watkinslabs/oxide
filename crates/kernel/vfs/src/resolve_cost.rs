//! Low-distortion pathname-resolution attribution for the debug syscall
//! profile. Production builds compile none of this module.

#![cfg(feature = "debug-resolve-cost")]

use core::sync::atomic::{AtomicU64, Ordering};

const NS_PER_MS: u64 = 1_000_000;
const MAY_LOOKUP: usize = 0;
const CHILD_LOOKUP: usize = 1;
const SYMLINK: usize = 2;
const DCACHE_PROBE: usize = 3;
const INODE_SNAPSHOT: usize = 4;
const HASH_WALK: usize = 5;
const REF_PIN: usize = 6;
const REVALIDATE: usize = 7;
const SLOW_LOOKUP: usize = 8;
const BACKEND_LOOKUP: usize = 9;
const DENTRY_INSTALL: usize = 10;
const PARENT_LOCK: usize = 11;
const WRITER_LOCK: usize = 12;
const WRITER_HOLD: usize = 13;
const ROOT_STATE: usize = 14;
const NAMEI_INIT: usize = 15;
const WALK_BODY: usize = 16;
const N: usize = 17;
static NS: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static CNT: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static DCACHE_HIT: AtomicU64 = AtomicU64::new(0);
static DCACHE_NEGATIVE: AtomicU64 = AtomicU64::new(0);
static DCACHE_MISS: AtomicU64 = AtomicU64::new(0);
static NAME: [&[u8]; N] = [
    b"may-lookup", b"child-lookup", b"symlink", b"dcache-probe", b"inode-snapshot",
    b"hash-walk", b"ref-pin", b"revalidate", b"slow-lookup",
    b"backend-lookup", b"dentry-install", b"parent-lock", b"writer-lock", b"writer-hold",
    b"root-state", b"namei-init", b"walk-body",
];

fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

pub struct Span(usize, u64);

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
pub(crate) fn dcache_probe() -> Span { Span::start(DCACHE_PROBE) }
pub(crate) fn inode_snapshot() -> Span { Span::start(INODE_SNAPSHOT) }
pub(crate) fn hash_walk() -> Span { Span::start(HASH_WALK) }
pub(crate) fn ref_pin() -> Span { Span::start(REF_PIN) }
pub(crate) fn revalidate() -> Span { Span::start(REVALIDATE) }
pub(crate) fn slow_lookup() -> Span { Span::start(SLOW_LOOKUP) }
pub(crate) fn backend_lookup() -> Span { Span::start(BACKEND_LOOKUP) }
pub(crate) fn dentry_install() -> Span { Span::start(DENTRY_INSTALL) }
pub(crate) fn parent_lock() -> Span { Span::start(PARENT_LOCK) }
pub(crate) fn writer_lock() -> Span { Span::start(WRITER_LOCK) }
pub(crate) fn writer_hold() -> Span { Span::start(WRITER_HOLD) }
pub fn root_state() -> Span { Span::start(ROOT_STATE) }
pub(crate) fn namei_init() -> Span { Span::start(NAMEI_INIT) }
pub(crate) fn walk_body() -> Span { Span::start(WALK_BODY) }

pub(crate) fn dcache_hit() { DCACHE_HIT.fetch_add(1, Ordering::Relaxed); }
pub(crate) fn dcache_negative() { DCACHE_NEGATIVE.fetch_add(1, Ordering::Relaxed); }
pub(crate) fn dcache_miss() { DCACHE_MISS.fetch_add(1, Ordering::Relaxed); }

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
    klog::write_raw(b"  resolve-count dcache-hit=");
    klog::write_dec_u64(DCACHE_HIT.load(Ordering::Relaxed));
    klog::write_raw(b" dcache-negative=");
    klog::write_dec_u64(DCACHE_NEGATIVE.load(Ordering::Relaxed));
    klog::write_raw(b" dcache-miss=");
    klog::write_dec_u64(DCACHE_MISS.load(Ordering::Relaxed));
    klog::write_raw(b"\n");
}
