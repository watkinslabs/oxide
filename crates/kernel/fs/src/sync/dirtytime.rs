// `start_dirtytime_writeback` / `wakeup_dirtytime_writeback` (Linux
// fs/fs-writeback.c) — the periodic work that bounds how long a `lazytime`
// mount may hold a timestamp in memory. Without it the deferral is unbounded on
// an idle filesystem: nothing else ever visits an inode that is only READ.
//
// Re-armed from inside its own handler, exactly as Linux re-schedules
// `dirtytime_work` at the tail of every run.

#![cfg(target_os = "oxide-kernel")]

use vfs::writeback::{dirtytime_expire_pass, DIRTYTIME_EXPIRE_SECS, NSEC_PER_SEC};

/// Re-arm period. Linux runs the sweep every `dirtytime_expire_interval`, so an
/// individual deferral lives at most twice the interval — the sweep boundary is
/// not aligned to when the inode happened to be dirtied.
const PERIOD_NS: u64 = DIRTYTIME_EXPIRE_SECS * NSEC_PER_SEC;

/// The kworker body: force out every deferral older than the expire interval on
/// every mounted filesystem, then re-arm. Runs in PROCESS context (it writes
/// inodes through the backend and may sleep), which is why it is a workqueue
/// item and not a timer callback. # C: O(N_sb x N_wb)
fn dirtytime_work(_arg: usize) {
    dirtytime_expire_pass(vfs::inode_times::realtime_now_ns());
    arm();
}

/// Queue the next sweep one period out. # C: O(DELAYED_CAPACITY)
fn arm() {
    let now = timekeeper::monotonic_ns();
    sched::live::delayed_work::queue_delayed_work_on(0, dirtytime_work, 0, now, PERIOD_NS);
}

/// Start the periodic dirtytime sweep (Linux's `start_dirtytime_writeback`
/// initcall). Called once from kernel init, after the workqueue exists.
/// # C: O(1)
pub fn start_dirtytime_writeback() { arm(); }
