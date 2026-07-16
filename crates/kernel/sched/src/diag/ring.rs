use core::sync::atomic::{AtomicI32, AtomicU8, AtomicU32, AtomicU64, Ordering};

use crate::Task;

use super::current_task;
#[cfg(any(feature = "debug-watchdog", feature = "debug-brokerdump"))]
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

#[cfg(feature = "debug-brokerdump")]
const BROKER_WRITE_N: usize = 256;
#[cfg(feature = "debug-brokerdump")]
static BROKER_WRITE_FD: AtomicI32 = AtomicI32::new(-1);
#[cfg(feature = "debug-brokerdump")]
static BROKER_WRITE_LEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "debug-brokerdump")]
static BROKER_WRITE: [AtomicU8; BROKER_WRITE_N] = [const { AtomicU8::new(0) }; BROKER_WRITE_N];

pub fn record_syscall(nr: u32, ret: i64) {
    let t = match current_task() {
        Some(t) => t,
        None => return,
    };
    let tid = t.tid;
    let i = RING_POS.fetch_add(1, Ordering::Relaxed) % RING_N;
    RING_TID[i].store(tid, Ordering::Relaxed);
    RING_NR[i].store(nr, Ordering::Relaxed);
    RING_RET[i].store(ret, Ordering::Relaxed);
    // debug-polktrace: live per-syscall stream for polkitd only, to locate the
    // authority-init stall (never reaches RequestName). exe-filtered so overhead
    // is bounded to one process. # nr/ret only; args live in per-handler traces.
    #[cfg(feature = "debug-polktrace")]
    {
        let is_pol = unsafe { (*t.exe_path.get()).as_ref().map(|s| s.contains("polkit")).unwrap_or(false) };
        if is_pol {
            klog::write_raw(b"[POL tid="); klog::write_dec_u64(tid as u64);
            klog::write_raw(b" nr="); klog::write_dec_u64(nr as u64);
            klog::write_raw(b" ret="); if ret < 0 { klog::write_raw(b"-"); klog::write_dec_u64((-ret) as u64); } else { klog::write_dec_u64(ret as u64); }
            klog::write_raw(b"]\n");
        }
    }
}

#[cfg(feature = "debug-brokerdump")]
pub fn record_broker_write(fd: i32, bytes: &[u8]) {
    let broker = current_task().is_some_and(|t| {
        // SAFETY: current task is the sole exe_path mutator while executing write.
        unsafe { (*t.exe_path.get()).as_ref().is_some_and(|p| p.contains("dbus-broker")) }
    });
    if !broker { return; }
    let n = core::cmp::min(bytes.len(), BROKER_WRITE_N);
    for (dst, src) in BROKER_WRITE.iter().zip(bytes.iter()).take(n) {
        dst.store(*src, Ordering::Relaxed);
    }
    BROKER_WRITE_FD.store(fd, Ordering::Relaxed);
    BROKER_WRITE_LEN.store(n, Ordering::Release);
}

#[cfg(not(feature = "debug-brokerdump"))]
pub fn record_broker_write(_fd: i32, _bytes: &[u8]) {}

#[cfg(any(feature = "debug-watchdog", feature = "debug-brokerdump"))]
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

// Per-exit syscall-ring dump: gated on the OPT-IN `debug-taskdump`, NOT the
// default-on `debug-watchdog`. It fires on EVERY non-zero process exit (every
// /bin/false, probe, failed exec), each dumping ~30 lines to the slow serial
// console — steady-state noise that has no place in a normal boot (the
// soft-lockup watchdog, the actually-wanted default-on part, lives elsewhere).
#[cfg(any(feature = "debug-taskdump", feature = "debug-brokerdump"))]
pub fn dump_exit_recent(name: &str, code: u64) {
    if code == 0 {
        return;
    }
    let broker = current_task().is_some_and(|t| {
        // SAFETY: current task is the sole exe_path mutator while executing exit_group.
        unsafe { (*t.exe_path.get()).as_ref().is_some_and(|p| p.contains("dbus-broker")) }
    });
    if !broker { return; }
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
    #[cfg(feature = "debug-brokerdump")]
    {
        let n = BROKER_WRITE_LEN.load(Ordering::Acquire);
        if n != 0 {
            klog::write_raw(b"  last write fd=");
            let fd = BROKER_WRITE_FD.load(Ordering::Relaxed);
            if fd < 0 { klog::write_raw(b"-"); klog::write_dec_u64(fd.wrapping_neg() as u64); }
            else { klog::write_dec_u64(fd as u64); }
            klog::write_raw(b": ");
            for byte in BROKER_WRITE.iter().take(n) {
                klog::write_raw(&[byte.load(Ordering::Relaxed)]);
            }
            if BROKER_WRITE[n - 1].load(Ordering::Relaxed) != b'\n' { klog::write_raw(b"\n"); }
        }
    }
}

#[cfg(not(any(feature = "debug-taskdump", feature = "debug-brokerdump")))]
pub fn dump_exit_recent(_name: &str, _code: u64) {}

impl Task {
    pub fn note_syscall(&self, nr: u32) {
        self.last_syscall_nr.store(nr, Ordering::Relaxed);
        self.nsyscalls.fetch_add(1, Ordering::Relaxed);
    }
}
