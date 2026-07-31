// Live-task binding for the `prctl` options whose decision logic lives in
// `sud` / `io_flusher` / `auxv` / `timer_ids`.
//
// Everything here reads the running task, its mm or its user memory, so it is
// the half that `cargo test` cannot reach; every rule it applies was decided
// in an ungated sibling module. Keeping it out of `dispatch.rs` leaves that
// file a pure fan-out.

use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use super::{auxv, io_flusher, sud, timer_ids};
use crate::task::Task;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `PR_SET_IO_FLUSHER`. The flag is read by the page allocator before it
/// enters direct reclaim, so setting it really does keep this task's
/// allocations out of the pageout -> swap -> block path.
/// # C: O(1)
pub fn set_io_flusher(cur: &Task, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let cap = cur.has_cap(crate::cap::SYS_RESOURCE);
    match io_flusher::set_decide(cap, a2, a3, a4, a5) {
        Ok(on) => { cur.io_flusher.set(on); 0 }
        Err(e) => err(e),
    }
}

/// `PR_GET_IO_FLUSHER` — the flag as the syscall VALUE. # C: O(1)
pub fn get_io_flusher(cur: &Task, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let cap = cur.has_cap(crate::cap::SYS_RESOURCE);
    match io_flusher::get_decide(cap, a2, a3, a4, a5) {
        Ok(()) => cur.io_flusher.get() as i64,
        Err(e) => err(e),
    }
}

/// `PR_SET_SYSCALL_USER_DISPATCH`.
///
/// Linux checks the selector with `access_ok` ONCE, here, and never again:
/// the per-syscall path uses `__get_user`, so a selector that was mapped at
/// registration time and unmapped later is a fatal SIGSEGV at the next
/// syscall, not an EFAULT from this call.
/// # C: O(1)
pub fn set_syscall_user_dispatch(cur: &Task, cfg: &sud::Config) -> i64 {
    if cfg.on && cfg.selector != 0 && !selector_addr_ok(cfg.selector) {
        return err(Errno::Efault);
    }
    cur.syscall_dispatch.install(cfg);
    0
}

/// Linux `access_ok(untagged_addr(selector), sizeof(*selector))` — a RANGE
/// test against the user half, not a mapping test. # C: O(1)
fn selector_addr_ok(p: u64) -> bool { p < hal::USER_VA_END }

/// `PR_GET_AUXV` — copy out of the mm's saved auxiliary vector.
///
/// The return value is the FULL saved size, never the copied size, so a
/// caller that probed with a short buffer learns what to allocate.
/// # C: O(SAVED_AUXV_BYTES)
pub fn get_auxv(cur: &Task, ptr: u64, len: u64) -> i64 {
    // SAFETY: syscall dispatch holds the calling task's mm slot stable for the duration of this read.
    let Some(mm) = (unsafe { cur.mm_ref() }) else { return err(Errno::Einval) };
    let (size, full) = auxv::copy_plan(len);
    if size == 0 { return full; }
    let mut blob = mm.auxv().unwrap_or_default();
    blob.resize(auxv::SAVED_AUXV_BYTES, 0);
    match uaccess::copy_to_user(ptr, &blob[..size]) { Ok(()) => full, Err(e) => err(e) }
}

/// `PR_TIMER_CREATE_RESTORE_IDS` — process-wide, on the thread group.
/// `timer_create` reads it back, which is what makes the option do something.
/// # C: O(1)
pub fn timer_create_restore_ids(cur: &Task, op: timer_ids::RestoreIds) -> i64 {
    let cell = &cur.thread_group.timer_create_restore_ids;
    match op {
        timer_ids::RestoreIds::Off => { cell.store(false, Ordering::Release); 0 }
        timer_ids::RestoreIds::On  => { cell.store(true, Ordering::Release); 0 }
        timer_ids::RestoreIds::Get => cell.load(Ordering::Acquire) as i64,
    }
}
