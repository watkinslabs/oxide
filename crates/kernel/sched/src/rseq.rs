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
            0
        }
        abi::RseqAction::Register => {
            // Linux `access_ok(rseq, rseq_len)` — a pure range check.
            if !uaccess::user_range_ok(ptr, len as u64) {
                return -(Errno::Efault.as_i32() as i64);
            }
            // The kernel only ever writes the first `ORIG_RSEQ_SIZE` bytes,
            // so that is the span that must be mapped and writable.
            if !uaccess::init_area(ptr) { return -(Errno::Efault.as_i32() as i64); }
            cur.rseq_ptr.store(ptr, Ordering::Release);
            cur.rseq_len.store(len, Ordering::Release);
            cur.rseq_sig.store(sig, Ordering::Release);
            cur.rseq_ids.store(exit::IDS_UNSET, Ordering::Release);
            // Linux `rseq_force_update()`: publish the real ids before the
            // syscall returns so the first critical section already sees a
            // usable `cpu_id`.
            exit::rseq_writeback();
            0
        }
    }
}
