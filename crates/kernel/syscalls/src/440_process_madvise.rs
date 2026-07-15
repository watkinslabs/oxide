// 440 process_madvise — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

// process_madvise-valid advice subset (Linux `madvise_behavior_valid`
// restricted by `process_madvise` to reclaim/hint operations).
const MADV_WILLNEED: u64 = 3; // reclaim hint — no LRU/swap ⇒ no-op
const MADV_DONTNEED: u64 = 4; // drop pages, refault as zero
const MADV_FREE:     u64 = 8; // lazy-free anon pages
const MADV_COLD:     u64 = 20; // deactivate hint — no-op
const MADV_PAGEOUT:  u64 = 21; // reclaim hint — no LRU/swap ⇒ no-op

/// process_madvise(pidfd, iov, iovcnt, advice, flags). Applies `advice`
/// to the iovec ranges in the TARGET task's address space (resolved via
/// the pidfd). DONTNEED/FREE drop the caller's own pages; COLD/PAGEOUT/
/// WILLNEED are genuine no-ops (oxide has no LRU/swap). Returns the total
/// bytes advised (sum of iovec lengths), matching Linux.
/// # C: O(sum(iov_len)/4096)
pub fn sys_process_madvise(args: &SyscallArgs) -> i64 {
    let pidfd  = args.a0 as i32;
    let iov    = args.a1;
    let iovcnt = args.a2 as usize;
    let advice = args.a3;
    let flags  = args.a4;

    // Linux: flags must be 0.
    if flags != 0 { return errno(Errno::Einval); }
    // Reject any advice outside the process_madvise subset.
    match advice {
        MADV_WILLNEED | MADV_DONTNEED | MADV_FREE | MADV_COLD | MADV_PAGEOUT => {}
        _ => return errno(Errno::Einval),
    }

    let cur = match sched::live::current() { Some(c) => c, None => return errno(Errno::Ebadf) };
    // Resolve pidfd → target task. EBADF if fd not open, EINVAL if not a pidfd.
    // SAFETY: running task on this CPU; sole reader of its fd_table slot per `13§5`; clone Arc.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return errno(Errno::Ebadf) };
    let file = match fdt.get(pidfd) { Ok(f) => f, Err(_) => return errno(Errno::Ebadf) };
    let identity = match pidfd::identity_from_inode(&file.inode()) {
        Some(identity) => identity,
        None => return errno(Errno::Einval),
    };
    let target = match identity.task() {
        Some(target) => target,
        None => return errno(Errno::Esrch),
    };

    // iovec array lives in the CALLER's AS; validates + caps n>1024 → EINVAL.
    let iovs = match crate::pvmrw::pvmrw_common::read_iovs(iov, iovcnt) { Ok(v) => v, Err(e) => return e };

    let self_target = target.tid == cur.tid;
    if !self_target {
        match advice {
            MADV_COLD | MADV_PAGEOUT | MADV_WILLNEED => {}
            _ => return errno(Errno::Einval),
        }
        if !cur.has_cap(sched::cap::SYS_NICE) { return errno(Errno::Eperm); }
    }
    let drop_pages = self_target && (advice == MADV_DONTNEED || advice == MADV_FREE);

    let mut total: u64 = 0;
    for (base, len) in iovs {
        total = total.wrapping_add(len);
        if !drop_pages || len == 0 { continue; }
        // evict_* validate page-alignment/bounds internally (EINVAL, ignored
        // here) and no-op over holes — same contract as madvise slot 28.
        if self_target {
            // Self pidfd: target root == active root — reuse the active-root
            // evictor (fully correct, no new PT-walk primitive).
            let _ = pmm::user_as::evict_pages_in_range(base, len);
        }
    }
    total as i64
}
