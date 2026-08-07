// `sys_rseq(2)` (slot 334) + the exit-to-user machinery restartable
// sequences actually require. Linux `kernel/rseq.c` +
// `include/linux/rseq_entry.h`.
//
// Module manifest:
//   `uaccess` — VMA-validated user reads/writes (this kernel has no
//               exception table, so every user access is pre-checked).
//   `exit`    — id writeback + critical-section abort/fixup run on the
//               exit-to-user paths.
// The argument ladders and the abort arithmetic live in `syscall::rseq` so
// they stay hosted-testable; this file only binds them to task state.

mod uaccess;
pub mod exit;

pub use exit::{rseq_preempt_return, rseq_writeback};

use syscall::SyscallArgs;
use syscall::rseq as abi;
use core::sync::atomic::Ordering;

const ENOTSUPP: i64 = 524;
/// Linux's initial `rseq_slice_ext_nsecs`: short enough that a grant is only
/// an interrupt-return fast path, not an alternate scheduling policy.
const SLICE_EXTENSION_NS: u64 = 5_000;

fn clear_slice_grant(cur: &crate::Task) {
    cur.rseq_slice_granted.store(false, Ordering::Release);
    cur.rseq_slice_expires_ns.store(0, Ordering::Release);
}

fn clear_slice_ctrl(cur: &crate::Task) {
    let ptr = cur.rseq_ptr.load(Ordering::Acquire);
    if ptr != 0 && uaccess::put_u32(ptr + abi::RSEQ_OFF_SLICE_CTRL, 0).is_err() {
        exit::registration_died(cur);
    }
}

/// Revoke an active grant before every syscall body.  In particular, the
/// slice-yield syscall observes the latch set here, after the grant is gone.
/// # C: O(1)
/// # Ctx: syscall entry
pub fn slice_syscall_enter(nr: u64) {
    let Some(cur) = crate::live::current() else { return };
    if !cur.rseq_slice_granted.load(Ordering::Acquire) { return; }
    clear_slice_grant(cur);
    clear_slice_ctrl(cur);
    if nr == syscall::nrs::NR_RSEQ_SLICE_YIELD {
        cur.rseq_slice_yielded.store(true, Ordering::Release);
    }
    crate::preempt::set_need_resched();
    crate::timers::reprogram_local();
}

/// This CPU's slice-extension timer event, or no event.  A grant is local to
/// the running task, so it needs no shared hrtimer queue or cross-CPU scan.
/// # C: O(1)
pub fn slice_deadline() -> u64 {
    let Some(cur) = crate::live::current() else { return u64::MAX };
    if cur.rseq_slice_granted.load(Ordering::Acquire) {
        cur.rseq_slice_expires_ns.load(Ordering::Acquire)
    } else { u64::MAX }
}

/// Timer-IRQ half of the expiry: request a return-to-user scheduling pass.
/// The grant itself is revoked by that pass before it can switch tasks.
/// # C: O(1)
/// # Ctx: timer IRQ
pub fn slice_timer_expired() {
    let Some(cur) = crate::live::current() else { return };
    if !cur.rseq_slice_granted.load(Ordering::Acquire) { return; }
    let expiry = cur.rseq_slice_expires_ns.load(Ordering::Acquire);
    if expiry != 0 && timekeeper::monotonic_ns() >= expiry {
        crate::preempt::set_need_resched();
    }
}

/// Consume a pending reschedule by granting a requested extension, but only
/// on an interrupt/exception return with no competing user-return work.
/// `true` means the caller must defer scheduling and return to userspace.
/// # C: O(1)
/// # Ctx: return-to-user
pub fn try_grant_slice(from_irq: bool, blocked: bool) -> bool {
    if !from_irq || blocked { return false; }
    let Some(cur) = crate::live::current() else { return false };
    // Any reschedule that reaches this point consumes a prior grant.  It must
    // not survive a context switch (nor a same-task schedule decision).
    if cur.rseq_slice_granted.load(Ordering::Acquire) {
        clear_slice_grant(cur);
        clear_slice_ctrl(cur);
        crate::timers::reprogram_local();
        return false;
    }
    if !cur.rseq_slice_enabled.load(Ordering::Acquire)
        || !abi::is_v2(cur.rseq_len.load(Ordering::Acquire))
    { return false; }
    let ptr = cur.rseq_ptr.load(Ordering::Acquire);
    if ptr == 0 { return false; }
    let ctrl = match uaccess::get_u32(ptr + abi::RSEQ_OFF_SLICE_CTRL) {
        Ok(ctrl) => ctrl,
        Err(_) => exit::registration_died(cur),
    };
    let Some(next) = abi::take_slice_request(ctrl) else { return false };
    if uaccess::put_u32(ptr + abi::RSEQ_OFF_SLICE_CTRL, next).is_err() {
        exit::registration_died(cur);
    }
    cur.rseq_slice_granted.store(true, Ordering::Release);
    cur.rseq_slice_expires_ns.store(
        timekeeper::monotonic_ns().saturating_add(SLICE_EXTENSION_NS), Ordering::Release);
    crate::timers::reprogram_local();
    true
}

/// Linux `rseq_slice_extension_prctl` state transition. # C: O(1)
pub fn slice_extension_prctl(cur: &crate::Task, req: crate::prctl::rseq_slice::Request) -> i64 {
    match req {
        crate::prctl::rseq_slice::Request::Get =>
            cur.rseq_slice_enabled.load(Ordering::Acquire) as i64,
        crate::prctl::rseq_slice::Request::Set(enable) => {
            let ptr = cur.rseq_ptr.load(Ordering::Acquire);
            if ptr == 0 { return -(syscall::errno::Errno::Enxio.as_i32() as i64); }
            if !abi::is_v2(cur.rseq_len.load(Ordering::Acquire)) { return -ENOTSUPP; }
            if enable == cur.rseq_slice_enabled.load(Ordering::Acquire) { return 0; }
            let old = match uaccess::get_u32(ptr + abi::RSEQ_OFF_FLAGS) {
                Ok(v) => v,
                Err(_) => exit::registration_died(cur),
            };
            let required = abi::RSEQ_CS_FLAG_SLICE_EXT_AVAILABLE
                | if cur.rseq_slice_enabled.load(Ordering::Acquire) {
                    abi::RSEQ_CS_FLAG_SLICE_EXT_ENABLED
                } else { 0 };
            if old & required != required { exit::registration_died(cur); }
            let next = abi::RSEQ_CS_FLAG_SLICE_EXT_AVAILABLE
                | if enable { abi::RSEQ_CS_FLAG_SLICE_EXT_ENABLED } else { 0 };
            if uaccess::put_u32(ptr + abi::RSEQ_OFF_FLAGS, next).is_err() {
                exit::registration_died(cur);
            }
            cur.rseq_slice_enabled.store(enable, Ordering::Release);
            0
        }
    }
}

/// This thread's live registration as `syscall::rseq::decide` sees it.
/// `None` once the ptr slot is clear. # C: O(1)
fn registration(cur: &crate::Task) -> Option<abi::Registration> {
    let ptr = cur.rseq_ptr.load(Ordering::Acquire);
    if ptr == 0 { return None; }
    Some(abi::Registration {
        ptr,
        len: cur.rseq_len.load(Ordering::Acquire),
        sig: cur.rseq_sig.load(Ordering::Acquire),
    })
}

/// `sys_rseq(rseq, rseq_len, flags, sig)` — slot 334. Registration is
/// per-THREAD (Linux keeps it in `task_struct`, not `signal_struct`), so a
/// `clone(2)` child starts unregistered and glibc re-registers on every
/// thread start.
///
/// The errno ladder is `syscall::rseq::decide` (EINVAL/EPERM/EBUSY ordering
/// straight out of `kernel/rseq.c:547`); the two uaccess steps Linux folds
/// into `rseq_register`/`rseq_unregister` (initialise the user area, reset
/// the ids) live here because they touch the caller's address space.
///
/// Registration is NOT cosmetic: `exit::rseq_preempt_return` performs the
/// real `rseq_cs` abort on every preemption-driven return to user, so the
/// per-cpu fast paths glibc/jemalloc/tcmalloc build on this are protected.
/// # C: O(1)
/// # Ctx: syscall
pub fn sys_rseq(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let ptr   = args.a0;
    let len   = args.a1 as u32;
    let flags = args.a2 as u32;
    let sig   = args.a3 as u32;
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    let action = match abi::decide(registration(cur), ptr, len, flags, sig) {
        Ok(a)  => a,
        Err(e) => return -(e.as_i32() as i64),
    };
    match action {
        abi::RseqAction::Unregister => {
            // Linux `rseq_reset_ids`: the area goes back to the
            // "uninitialised" sentinel before the slot is dropped, so a
            // thread still reading its stale TLS copy sees a value it must
            // treat as invalid rather than a plausible cpu number.
            if !uaccess::reset_ids(ptr) { return -(Errno::Efault.as_i32() as i64); }
            cur.rseq_ptr.store(0, Ordering::Release);
            cur.rseq_len.store(0, Ordering::Release);
            cur.rseq_sig.store(0, Ordering::Release);
            cur.rseq_ids.store(exit::IDS_UNSET, Ordering::Release);
            cur.rseq_slice_enabled.store(false, Ordering::Release);
            cur.rseq_slice_granted.store(false, Ordering::Release);
            cur.rseq_slice_expires_ns.store(0, Ordering::Release);
            cur.rseq_slice_yielded.store(false, Ordering::Release);
            0
        }
        abi::RseqAction::Register => {
            // Linux `access_ok(rseq, rseq_len)` — a pure range check.
            if !uaccess::user_range_ok(ptr, len as u64) {
                return -(Errno::Efault.as_i32() as i64);
            }
            // The kernel only ever writes the first `ORIG_RSEQ_SIZE` bytes,
            // so that is the span that must be mapped and writable.
            if !uaccess::init_area(ptr, len, flags) { return -(Errno::Efault.as_i32() as i64); }
            cur.rseq_ptr.store(ptr, Ordering::Release);
            cur.rseq_len.store(len, Ordering::Release);
            cur.rseq_sig.store(sig, Ordering::Release);
            cur.rseq_ids.store(exit::IDS_UNSET, Ordering::Release);
            cur.rseq_slice_enabled.store(
                abi::is_v2(len) && flags & abi::RSEQ_FLAG_SLICE_EXT_DEFAULT_ON != 0,
                Ordering::Release);
            cur.rseq_slice_granted.store(false, Ordering::Release);
            cur.rseq_slice_expires_ns.store(0, Ordering::Release);
            cur.rseq_slice_yielded.store(false, Ordering::Release);
            // Linux `rseq_force_update()`: publish the real ids before the
            // syscall returns so the first critical section already sees a
            // usable `cpu_id`.
            exit::rseq_writeback();
            0
        }
    }
}
