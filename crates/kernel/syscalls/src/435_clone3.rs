// 435 clone3 — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_clone3(cl_args, size)` — slot 435. Reads the user
/// `struct clone_args` (Linux ABI; size is the user's view of the
/// struct so future fields can be detected via short-write probe)
/// and routes through the unified clone path. Returns the child
/// tid in the parent, 0 in the child (the spawn machinery wires
/// the child's rax via `ArchCtx::new_user_for_fork`).
///
/// `struct clone_args` layout (Linux v5.5+):
///   u64 flags          — CLONE_* bits, low byte = exit_signal.
///                        clone3 places exit_signal in `exit_signal`
///                        instead of the bottom byte (kernel ANDs it
///                        in at entry); we OR them back together.
///   u64 pidfd          — pidfd writeback (we currently no-op).
///   u64 child_tid      — *ctid (CLONE_CHILD_SETTID/CLEARTID).
///   u64 parent_tid     — *ptid (CLONE_PARENT_SETTID).
///   u64 exit_signal
///   u64 stack          — child stack base.
///   u64 stack_size     — for stacks-grow-down archs we use top = stack+size.
///   u64 tls            — CLONE_SETTLS payload.
///   u64 set_tid        — pid namespace tid array (ignored v1).
///   u64 set_tid_size
///   u64 cgroup         — cgroup fd (ignored v1).
///
/// # C: O(parent VMAs) | O(1) for CLONE_VM
pub fn sys_clone3(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let cl_args = args.a0;
    let size    = args.a1 as usize;
    if size < 64 || size > 256 { return -(Errno::Einval.as_i32() as i64); }
    if cl_args == 0 || cl_args >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if cl_args.checked_add(size as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: cl_args range validated < USER_VA_END; CPL=0 reads
    // through caller's AS; struct fields are u64-aligned per ABI.
    const CLONE_PIDFD: u64 = 0x1000;
    // SAFETY: cl_args+size validated above; clone_args struct fields are 8-byte aligned per Linux ABI; CPL=0 reads via caller's AS.
    let (rv, flags, pidfd_uptr) = unsafe {
        let p = cl_args as *const u64;
        let flags        = core::ptr::read_volatile(p.add(0));
        let pidfd_uptr   = core::ptr::read_volatile(p.add(1));
        let child_tid    = core::ptr::read_volatile(p.add(2));
        let parent_tid   = core::ptr::read_volatile(p.add(3));
        let exit_signal  = core::ptr::read_volatile(p.add(4));
        let stack        = core::ptr::read_volatile(p.add(5));
        let stack_size   = core::ptr::read_volatile(p.add(6));
        let tls          = core::ptr::read_volatile(p.add(7));
        let user_sp = stack.saturating_add(stack_size);
        let merged_flags = flags | (exit_signal & 0xff);
        let rv = crate::clone::sys_clone_dispatch(
            args, merged_flags, user_sp, parent_tid, child_tid, tls,
        );
        (rv, flags, pidfd_uptr)
    };
    // CLONE_PIDFD: open a pidfd bound to the child and write the fd
    // number to *pidfd_uptr in caller's AS.
    if rv > 0 && (flags & CLONE_PIDFD) != 0
        && pidfd_uptr != 0 && pidfd_uptr + 4 <= hal::USER_VA_END {
        let mut sa = *args;
        sa.a0 = rv as u64;
        sa.a1 = 0;
        let pidfd = crate::pidfd::sys_pidfd_open(&sa);
        if pidfd >= 0 {
            // SAFETY: pidfd_uptr+4 validated < USER_VA_END; CPL=0 4-byte int write in caller AS.
            unsafe { core::ptr::write_volatile(pidfd_uptr as *mut i32, pidfd as i32); }
        }
    }
    rv
}
