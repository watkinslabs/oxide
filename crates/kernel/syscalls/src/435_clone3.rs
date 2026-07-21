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
///   u64 pidfd          — pidfd writeback.
///   u64 child_tid      — *ctid (CLONE_CHILD_SETTID/CLEARTID).
///   u64 parent_tid     — *ptid (CLONE_PARENT_SETTID).
///   u64 exit_signal
///   u64 stack          — child stack base.
///   u64 stack_size     — for stacks-grow-down archs we use top = stack+size.
///   u64 tls            — CLONE_SETTLS payload.
///   u64 set_tid        — pid namespace tid array.
///   u64 set_tid_size
///   u64 cgroup         — cgroup fd.
///
/// # C: O(parent VMAs) | O(1) for CLONE_VM
pub fn sys_clone3(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    const CLONE3_KNOWN_HIGH: u64 = crate::clone::CLONE_CLEAR_SIGHAND | crate::clone::CLONE_INTO_CGROUP;
    const CLONE3_KNOWN_FLAGS: u64 = crate::clone::CLONE_LEGACY_FLAGS | CLONE3_KNOWN_HIGH;
    const PAGE_SIZE: usize = 4096;
    let cl_args = args.a0;
    let size    = args.a1 as usize;
    if size < 64 { return -(Errno::Einval.as_i32() as i64); }
    if size > PAGE_SIZE { return -(Errno::E2big.as_i32() as i64); }
    if cl_args == 0 || cl_args >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if cl_args.checked_add(size as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return -(Errno::Efault.as_i32() as i64);
    }
    if size > 88 {
        let mut off = 88usize;
        while off < size {
            // SAFETY: cl_args+size validated above; byte tail is within the user-supplied clone_args extension area.
            if unsafe { core::ptr::read_volatile((cl_args + off as u64) as *const u8) } != 0 {
                return -(Errno::E2big.as_i32() as i64);
            }
            off += 1;
        }
    }
    // SAFETY: cl_args+size validated above; clone_args struct fields are 8-byte aligned per Linux ABI; CPL=0 reads via caller's AS.
    let (flags, pidfd_uptr, child_tid, parent_tid, exit_signal, stack, stack_size, tls) = unsafe {
        let p = cl_args as *const u64;
        (
            core::ptr::read_volatile(p.add(0)),
            core::ptr::read_volatile(p.add(1)),
            core::ptr::read_volatile(p.add(2)),
            core::ptr::read_volatile(p.add(3)),
            core::ptr::read_volatile(p.add(4)),
            core::ptr::read_volatile(p.add(5)),
            core::ptr::read_volatile(p.add(6)),
            core::ptr::read_volatile(p.add(7)),
        )
    };
    if (flags & !CLONE3_KNOWN_FLAGS) != 0 { return -(Errno::Einval.as_i32() as i64); }
    if (flags & crate::clone::CSIGNAL) != 0 { return -(Errno::Einval.as_i32() as i64); }
    // clone3 keeps exit_signal out of flags; reject values which cannot be
    // represented in clone(2)'s low-byte CSIGNAL field before merging.
    if exit_signal > crate::clone::CSIGNAL { return -(Errno::Einval.as_i32() as i64); }
    if (flags & (crate::clone::CLONE_PIDFD | crate::clone::CLONE_PARENT_SETTID))
        == (crate::clone::CLONE_PIDFD | crate::clone::CLONE_PARENT_SETTID) && pidfd_uptr == parent_tid {
        return -(Errno::Einval.as_i32() as i64);
    }
    if let Err(e) = crate::clone::validate_clone_core(flags) {
        return -(e.as_i32() as i64);
    }
    if stack == 0 {
        if stack_size != 0 { return -(Errno::Einval.as_i32() as i64); }
    } else if stack_size == 0 {
        return -(Errno::Einval.as_i32() as i64);
    } else if stack.checked_add(stack_size).map_or(true, |e| e > hal::USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    if (flags & crate::clone::CLONE_PIDFD) != 0
        && (pidfd_uptr == 0 || pidfd_uptr.checked_add(4).map_or(true, |e| e > hal::USER_VA_END)) {
        return -(Errno::Efault.as_i32() as i64);
    }
    if size >= 80 {
        // SAFETY: cl_args+size validated >=80; u64 #9 (offset 72) is in range
        // and 8-byte aligned; CPL=0 read via caller's AS.
        let set_tid_size = unsafe { core::ptr::read_volatile((cl_args as *const u64).add(9)) };
        if set_tid_size != 0 { return -(Errno::Einval.as_i32() as i64); }
    }
    // CLONE_INTO_CGROUP (Linux 5.7+): clone_args.cgroup is an fd to a cgroup v2
    // directory; the child is created directly inside it. systemd's pidfd_spawn
    // uses this to place service executors in the right cgroup — ignoring it
    // left children in PID1's cgroup and desynced systemd's cgroup bookkeeping
    // (the executor's later cg_attach then raced the empty-cgroup cleanup). The
    // cgroup field is at struct offset 80 (u64 #10); present only when the
    // caller's `size` covers it.
    let into_cgid = if (flags & crate::clone::CLONE_INTO_CGROUP) != 0 {
        if size < 88 { return -(Errno::Einval.as_i32() as i64); }
        // SAFETY: cl_args+size validated ≥88 above; u64 #10 (offset 80) is in
        // range and 8-byte aligned; CPL=0 read via caller's AS.
        let cg_fd = unsafe { core::ptr::read_volatile((cl_args as *const u64).add(10)) } as i32;
        if cg_fd < 0 { return -(Errno::Ebadf.as_i32() as i64); }
        let cur = match sched::live::current() {
            Some(c) => c,
            None => return -(Errno::Esrch.as_i32() as i64),
        };
        // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
        let fdt = match unsafe { cur.fd_table_ref() } {
            Some(f) => f,
            None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let file = match fdt.get(cg_fd) {
            Ok(f) => f,
            Err(_) => return -(Errno::Ebadf.as_i32() as i64),
        };
        let inode = file.inode();
        if inode.file_type() != vfs::FileType::Directory { return -(Errno::Einval.as_i32() as i64); }
        match cgroup::cgid_from_dir_inode(inode.ino(), inode.fsid()) {
            Some(id) => Some(id),
            None => return -(Errno::Einval.as_i32() as i64),
        }
    } else {
        None
    };
    let user_sp = stack + stack_size;
    let merged_flags = flags | exit_signal;
    crate::clone::sys_clone_dispatch(
        args, merged_flags, user_sp, parent_tid, pidfd_uptr, child_tid, tls, into_cgid,
    )
}
