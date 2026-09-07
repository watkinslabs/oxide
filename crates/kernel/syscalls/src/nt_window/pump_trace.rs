//! One line per retrieved message attributing the interval since the previous
//! retrieval: wall time, this thread's user and system CPU time, and the
//! kernel entries it made, busiest ordinal first.
//!
//! A pump interval is one of three things and the three demand different
//! repairs: off-CPU time (wall far above user+system) is a wait, user time is
//! work inside the application, and system time belongs to the ordinals named
//! here.

use core::sync::atomic::{AtomicU64, Ordering};
use ipc::win32_window::pump_profile::PumpProfile;

/// Kernel entries charged to the interval between two retrievals.
pub static PROFILE: PumpProfile = PumpProfile::new();

/// Lines the pump profile may emit before it goes quiet.
const TRACE_BUDGET: u32 = 400;
/// Nanoseconds per millisecond, the unit the line reports.
const NS_PER_MS: u64 = 1_000_000;
/// Ordinals named on the line.
const NAMED: usize = 6;
/// Nanoseconds per microsecond, the unit per-ordinal costs report.
const NS_PER_US: u64 = 1_000;

static LAST_WALL: AtomicU64 = AtomicU64::new(0);
static LAST_USER: AtomicU64 = AtomicU64::new(0);
static LAST_SYS: AtomicU64 = AtomicU64::new(0);
static BUDGET: AtomicU32 = AtomicU32::new(0);
use core::sync::atomic::AtomicU32;

/// # C: O(1)
fn delta(cell: &AtomicU64, now: u64) -> u64 {
    let previous = cell.swap(now, Ordering::Relaxed);
    if previous == 0 || now < previous { 0 } else { now - previous }
}

/// Report the interval that ended with this retrieval. # C: O(SLOTS log SLOTS)
pub(crate) fn note_retrieval() {
    let interval = PROFILE.take();
    if BUDGET.fetch_add(1, Ordering::Relaxed) >= TRACE_BUDGET { return; }
    let Some(cur) = sched::live::current() else { return; };
    let wall = delta(&LAST_WALL, timekeeper::monotonic_ns());
    let user = delta(&LAST_USER, cur.utime_ns.load(Ordering::Relaxed));
    let system = delta(&LAST_SYS, cur.stime_ns.load(Ordering::Relaxed));
    klog::write_raw(b"[WINDOWS-PUMP] wall_ms="); klog::write_hex_u64(wall / NS_PER_MS);
    klog::write_raw(b" user_ms="); klog::write_hex_u64(user / NS_PER_MS);
    klog::write_raw(b" sys_ms="); klog::write_hex_u64(system / NS_PER_MS);
    klog::write_raw(b" calls="); klog::write_hex_u64(interval.total);
    klog::write_raw(b" other="); klog::write_hex_u64(interval.other);
    klog::write_raw(b" incall_ms="); klog::write_hex_u64(interval.total_ns / NS_PER_MS);
    for entry in interval.top.iter().take(NAMED) {
        if entry.count == 0 { continue; }
        klog::write_raw(b" o="); klog::write_hex_u64(entry.ordinal);
        klog::write_raw(b":"); klog::write_hex_u64(entry.count);
        klog::write_raw(b":"); klog::write_hex_u64(entry.total_ns / NS_PER_US);
        klog::write_raw(b":"); klog::write_hex_u64(entry.max_ns / NS_PER_US);
    }
    klog::write_raw(b"\n");
}

/// Open the wall-time interval of one kernel entry, for an NT task only.
/// # C: O(1)
pub(crate) fn start() -> Option<u64> {
    if !sched::live::current().is_some_and(|task| task.is_nt_personality()) { return None; }
    Some(timekeeper::monotonic_ns())
}

/// Charge a kernel entry opened by `start` to the current pump interval.
/// # C: O(SLOTS)
pub(crate) fn charge(start: Option<u64>, nr: u64) {
    let Some(start) = start else { return; };
    let now = timekeeper::monotonic_ns();
    PROFILE.record(nr, now.saturating_sub(start));
}
