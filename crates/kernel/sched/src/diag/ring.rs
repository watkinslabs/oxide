use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::Task;

use super::current_task;
#[cfg(feature = "debug-watchdog")]
use super::{emit::dump_tasks, format::emit_syscall};

static SWITCHES: AtomicU64 = AtomicU64::new(0);

pub fn note_switch() {
    SWITCHES.fetch_add(1, Ordering::Relaxed);
}

pub fn switches() -> u64 {
    SWITCHES.load(Ordering::Relaxed)
}

const RING_N: usize = 512;
static RING_TID: [AtomicU32; RING_N] = [const { AtomicU32::new(0) }; RING_N];
static RING_NR: [AtomicU32; RING_N] = [const { AtomicU32::new(u32::MAX) }; RING_N];
static RING_RET: [core::sync::atomic::AtomicI64; RING_N] =
    [const { core::sync::atomic::AtomicI64::new(0) }; RING_N];
static RING_POS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub fn record_syscall(nr: u32, ret: i64) {
    let tid = match current_task() {
        Some(t) => t.tid,
        None => return,
    };
    let i = RING_POS.fetch_add(1, Ordering::Relaxed) % RING_N;
    RING_TID[i].store(tid, Ordering::Relaxed);
    RING_NR[i].store(nr, Ordering::Relaxed);
    RING_RET[i].store(ret, Ordering::Relaxed);
}

#[cfg(feature = "debug-watchdog")]
pub(super) fn dump_recent_for(tid: u32) {
    klog::write_raw(b"  recent syscalls (newest first):\n");
    let pos = RING_POS.load(Ordering::Relaxed);
    let mut shown = 0u32;
    let mut k = 0usize;
    while k < RING_N && shown < 40 {
        let i = (pos + RING_N - 1 - k) % RING_N;
        k += 1;
        if RING_NR[i].load(Ordering::Relaxed) == u32::MAX {
            continue;
        }
        if RING_TID[i].load(Ordering::Relaxed) != tid {
            continue;
        }
        klog::write_raw(b"    ");
        emit_syscall(RING_NR[i].load(Ordering::Relaxed));
        klog::write_raw(b" = ");
        let r = RING_RET[i].load(Ordering::Relaxed);
        if r < 0 {
            klog::write_raw(b"-");
            klog::write_dec_u64((-r) as u64);
        } else {
            klog::write_dec_u64(r as u64);
        }
        klog::write_raw(b"\n");
        shown += 1;
    }
    if shown == 0 {
        klog::write_raw(b"    <none recorded>\n");
    }
}

#[cfg(feature = "debug-watchdog")]
pub fn dump_exit_recent(name: &str, code: u64) {
    if code == 0 {
        return;
    }
    klog::write_raw(b"[EXIT] name=");
    klog::write_raw(name.as_bytes());
    if let Some(t) = current_task() {
        if let Some(p) = unsafe { &*t.exe_path.get() } {
            klog::write_raw(b" exe=");
            klog::write_raw(p.as_bytes());
        }
    }
    klog::write_raw(b" code=");
    klog::write_dec_u64(code);
    klog::write_raw(b"\n");
    if let Some(t) = current_task() {
        dump_recent_for(t.tid);
    }
}

#[cfg(not(feature = "debug-watchdog"))]
pub fn dump_exit_recent(_name: &str, _code: u64) {}

impl Task {
    pub fn note_syscall(&self, nr: u32) {
        self.last_syscall_nr.store(nr, Ordering::Relaxed);
        self.nsyscalls.fetch_add(1, Ordering::Relaxed);
    }
}
