// 438 pidfd_getfd — one syscall, one file (docs/53 §0). Moved verbatim from pidfd.rs.
#![cfg(target_os = "oxide-kernel")]

/// `sys_pidfd_getfd(pidfd, targetfd, flags)` — slot 438. Clones the
/// target task's fd into the calling task's fd table. Used by sandbox
/// programs (e.g. systemd-machined) that need to manipulate fds in
/// another process.
///
/// Linux semantics:
///   * `flags` must be 0 (any non-zero is EINVAL).
///   * pidfd must be a valid pidfd inode.
///   * Target task's targetfd must be open.
///   * Returns a new fd referring to the same Arc<File> (shared open
///     file description, so cursor + flock state are shared with the
///     target task — exactly what callers expect for fd-passing).
/// # C: O(N_fds)
pub fn sys_pidfd_getfd(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let pidfd     = args.a0 as i32;
    let target_fd = args.a1 as i32;
    let flags     = args.a2 as u32;
    if flags != 0 { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot for cur.
    let cur_fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let pidfd_file = match cur_fdt.get(pidfd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let identity = match pidfd::identity_from_inode(&pidfd_file.inode()) {
        Some(identity) => identity,
        None => return -(Errno::Einval.as_i32() as i64),
    };
    let target = match identity.task() {
        Some(target) => target,
        None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !pidfd_getfd_access(&cur, &target) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    if target.state() == sched::task::TaskState::Zombie {
        return -(Errno::Esrch.as_i32() as i64);
    }
    // target task may be running (or exiting) on another CPU: clone_fd_table
    // pins against a concurrent replace_fd_table(None) at exit so this
    // Arc<FdTable> snapshot can't race a UAF.
    let target_fdt = match target.clone_fd_table() {
        Some(t) => t, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let cloned = match target_fdt.get(target_fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    match cur_fdt.alloc_limit(cloned, cur.nofile_soft()) {
        Ok(fd) => {
            let _ = cur_fdt.set_cloexec(fd, true);
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}

/// Linux `pidfd_getfd` gates on `ptrace_may_access(PTRACE_MODE_ATTACH_REALCREDS)`.
/// This is the non-LSM core: same thread-group, real uid/gid matching the
/// target's real/effective/saved ids, or `CAP_SYS_PTRACE` in the target userns.
/// # C: O(userns-depth)
fn pidfd_getfd_access(cur: &sched::Task, target: &sched::Task) -> bool {
    use core::sync::atomic::Ordering;
    if cur.vtgid.load(Ordering::Acquire) == target.vtgid.load(Ordering::Acquire) { return true; }
    let cruid = cur.creds.ruid.load(Ordering::Acquire);
    let crgid = cur.creds.rgid.load(Ordering::Acquire);
    let tcred = &target.creds;
    let uid_ok = cruid == tcred.euid.load(Ordering::Acquire)
        && cruid == tcred.suid.load(Ordering::Acquire)
        && cruid == tcred.ruid.load(Ordering::Acquire);
    let gid_ok = crgid == tcred.egid.load(Ordering::Acquire)
        && crgid == tcred.sgid.load(Ordering::Acquire)
        && crgid == tcred.rgid.load(Ordering::Acquire);
    if uid_ok && gid_ok { return true; }
    let Some(target_ns) = target.namespace_owner(namespace_identity::NamespaceKind::User) else {
        return false;
    };
    nscg::proc_ns::has_cap_for(cur, &target_ns.pin(), sched::cap::SYS_PTRACE)
}
