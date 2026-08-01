// Shared execve/execveat machinery split out of execve.rs per
// docs/53§0 (per-syscall-file modules). Holds the non-pub helpers
// used by both 059_execve.rs and 322_execveat.rs: caught-signal
// reset, per-execve state reset, user-path read, file-cap apply,
// and shebang-chain resolution.
//
// SvcFrame note (aarch64): the aarch64 execve_inner patches the
// saved SVC frame via `hal_aarch64::current_svc_frame()` so the
// eret epilogue restores ELR_EL1 / SP_EL0 / SPSR_EL1 / x0 from the
// live saved tail — see the per-arch `execve_inner` in
// 059_execve.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

/// Linux `bprm_execve`'s deferred `RLIMIT_NPROC` failure:
///
/// ```text
/// if ((current->flags & PF_NPROC_EXCEEDED) &&
///     is_rlimit_overlimit(current_ucounts(), UCOUNT_RLIMIT_NPROC, rlimit(RLIMIT_NPROC)))
///         return -EAGAIN;
/// current->flags &= ~PF_NPROC_EXCEEDED;
/// ```
///
/// The failure `setuid(2)` could not report — because too much software
/// ignores its return value — lands here instead, on the first `execve` the
/// task attempts while its new account is over quota. A task that came back
/// under the limit in the meantime is let through and disarmed, so a
/// transient overrun does not poison every later exec.
///
/// Returns `Some(-EAGAIN)` when the exec must be refused, before ANY of the
/// image is opened or committed.
/// # C: O(user namespace depth)
pub(crate) fn nproc_admits(cur: &sched::Task) -> Option<i64> {
    if sched::ucounts::execve_admits(cur) { return None; }
    Some(-(Errno::Eagain.as_i32() as i64))
}

/// B46: reset caught signal handlers to SIG_DFL per execve(2) ABI.
/// "All signals that were being caught by the calling thread (set
/// to a value other than SIG_DFL and SIG_IGN) are reset to the
/// default disposition." Without this, a SIGCHLD handler installed
/// by init at e.g. 0x4925f9 leaks into every execve'd
/// child — when the child later forks its own grandchild and the
/// grandchild exits, SIGCHLD fires with handler=0x4925f9, but that
/// address is in init's text not the child's, so iretq lands
/// on an unmapped page and the child silently SIGSEGVs in its
/// waitpid path.
/// # C: O(1) — 64-slot scan.
pub(crate) fn reset_caught_signals(cur: &sched::Task) {
    cur.sigactions_ref().reset_caught();
    // Linux `flush_ptrace_hw_breakpoint(current)` on exec: a breakpoint set
    // against the old image names an address that now belongs to different
    // code, so leaving it armed traps the new program at an arbitrary point.
    sched::debugreg::clear(cur);
    #[cfg(target_arch = "aarch64")]
    sched::debugreg::arm::clear(cur);
}

/// F129: sweep all other per-task state Linux execve(2) resets:
///   * sigaltstack → SS_DISABLE (per sigaltstack(2): "The alternate
///     signal stack is reset on each call to execve(2)")
///   * robust futex list → null (per set_robust_list(2): "On exec
///     the head is set to NULL.")
///   * pdeath_sig → 0 (per prctl(PR_SET_PDEATHSIG): "is cleared upon
///     a call to execve")
///   * POSIX timers → all disarmed and cleared (per timer_create(2):
///     "Timers are not preserved across an execve(2)")
///   * RT signal queues → drained (per signal(7) sigqueue semantics:
///     queued info is task-private and dies with the program image)
/// Signal mask (sigprocmask) and pending bitmap are PRESERVED per
/// execve(2) "the set of signals pending is preserved across execve".
/// # SAFETY: running task on this CPU, preempt-off; sole writer to
/// every slot per `13§5` single-mutator invariant.
/// # C: O(N_timers) — bounded by `PosixTimer::SLOTS` (32).
pub(crate) fn reset_per_execve_state(cur: &sched::Task) {
    use core::sync::atomic::Ordering;
    // Linux `begin_new_exec`: `me->flags &= ~PF_FORKNOEXEC`. A parent may only
    // `setpgid` a child that has not yet exec'd (POSIX EACCES otherwise), so
    // this bit is what closes the job-control window.
    cur.forknoexec.store(false, Ordering::Release);
    // sigaltstack disabled (Linux `sas_ss_reset` in `begin_new_exec`).
    cur.set_altstack(sched::sigaltstack::reset());
    // robust futex list dropped — stale user-VA into the old AS.
    cur.robust_list_head.store(0, Ordering::Release);
    cur.robust_list_len.store(0, Ordering::Release);
    // rseq registration points into the old userspace image.
    cur.rseq_ptr.store(0, Ordering::Release);
    cur.rseq_len.store(0, Ordering::Release);
    cur.rseq_sig.store(0, Ordering::Release);
    // parent-death signal cleared — handler would be in the old text.
    cur.pdeathsig.store(0, Ordering::Release);
    // Linux `begin_new_exec`: `clear_syscall_work_syscall_user_dispatch(me)`.
    // The registration names a code range and a selector byte in the OLD
    // image; carrying it across execve would test the new program's PC
    // against the old dispatcher's window and SIGSYS it at random.
    cur.syscall_dispatch.clear();
    // Linux `exec_task_namespaces`/`begin_new_exec` path resets
    // `signal->timer_create_restore_ids`: the option exists to restore a
    // checkpoint's timer ids, and the new image is not that checkpoint.
    cur.thread_group.timer_create_restore_ids.store(false, Ordering::Release);
    // `PR_SET_KEEPCAPS` is the SECBIT_KEEP_CAPS compatibility interface;
    // Linux clears that setting on every successful execve.
    cur.clear_keep_caps_after_exec();
    // alarm(2)/setitimer(2) interval timers survive execve; fork creates a
    // fresh Task with disarmed timer fields, matching Linux's lifetime rule.
    // POSIX timers do not survive execve. Remove their ordered deadline
    // entries before clearing process-owned timer state.
    sched::timers::clear_process_timers(cur);
    // RT signal queues — drain. The siginfos hold sigval_t.ptr values
    // that would point into the old AS. SAFETY: spinlock locks here,
    // single-CPU UP; the lock guards the per-task queue array.
    {
        let mut g = cur.sigqueue.lock();
        for q in g.iter_mut() { q.clear(); }
    }
}

/// Linux `begin_new_exec`'s tail: `ptrace_event(PTRACE_EVENT_EXEC, old_vpid)`.
/// A tracer that set `PTRACE_O_TRACEEXEC` stops here with the pre-exec pid as
/// the event message; a classically-attached tracee whose tracer did not set
/// it gets the legacy bare `SIGTRAP` instead. Runs at the very end of the
/// arch execve so the tracer inspects the FULLY installed image.
/// # Sleeps: yes when the tracer is listening.
/// # C: O(N_schedule) when the event is reported
pub(crate) fn ptrace_exec_event(cur: &sched::Task) {
    use core::sync::atomic::Ordering;
    let old_vpid = cur.vtgid.load(Ordering::Acquire) as u64;
    crate::ptrace::stop::ptrace_event(crate::s101_ptrace_uapi::EVENT_EXEC, old_vpid);
}

/// Linux `PATH_MAX` (`limits.h`): the largest pathname execve accepts,
/// NUL included. A pathname whose length reaches this bound without a
/// terminating NUL is rejected with `ENAMETOOLONG`, exactly as Linux's
/// `strndup_user(..., PATH_MAX)` in `getname_flags`/`do_execveat_common`.
const PATH_MAX: u64 = 4096;

/// Read a NUL-terminated path (up to `PATH_MAX` bytes incl. NUL) from a
/// userspace pointer into an owned Vec. Empty Vec ↔ NULL/empty user
/// pointer. Errors come back negated for the caller to forward:
///   * `EFAULT` — pointer at/above `USER_VA_END`, incl. a path that runs
///     into the non-canonical/kernel half before terminating.
///   * `ENAMETOOLONG` — no NUL within `PATH_MAX` bytes.
/// Previously capped at 64 bytes, silently truncating any longer path
/// (e.g. `/usr/lib/systemd/user-environment-generators/30-systemd-\
/// environment-d-generator`, 79 bytes) into a garbage prefix that then
/// failed to resolve — every systemd generator/helper with a >64-byte
/// absolute path spuriously `execve`-ENOENT'd, breaking the PID1 and
/// `systemd --user` generator passes. Linux's cap is `PATH_MAX`.
/// # C: O(PATH_MAX)
pub(crate) fn read_user_exec_path(path_ptr: u64) -> Result<alloc::vec::Vec<u8>, i64> {
    if path_ptr == 0 { return Ok(alloc::vec::Vec::new()); }
    // Length/bounds policy lives in `syscall::scan_user_cstr` (pure,
    // hosted-tested). We supply the per-byte user read.
    syscall::scan_user_cstr(path_ptr, PATH_MAX, |va|
        // SAFETY: `va` proven < USER_VA_END by scan_user_cstr each iteration; CPL=0 / EL1 reads through caller's AS pre-activate.
        unsafe { core::ptr::read_volatile(va as *const u8) }
    ).map_err(|e| -(e.as_i32() as i64))
}

/// Read the exec image, falling back to the raw rootfs reader ONLY when the
/// pathname could not be resolved at all — during early boot the VFS root is
/// not mounted yet and `/init` has to come straight off the image. A permission
/// denial (`EACCES` from `may_open(..., MAY_EXEC)`, a `noexec` mount, a
/// directory) must never be papered over by the fallback: that is the whole
/// point of the check.
///
/// `None` for the resolved path means "no inode behind this image", which the
/// credential transition reads as no setuid bits, no file caps and no
/// `mnt_may_suid`.
/// # C: O(components) + O(size/PAGE)
pub(crate) fn open_exec_image(path: &[u8])
    -> Result<(alloc::vec::Vec<u8>, Option<vfs::VfsPath>), i64>
{
    match crate::pathresolve::open_exec(path) {
        Ok((blob, vp)) => Ok((blob, Some(vp))),
        Err(rc) => {
            let unresolved = rc == -(Errno::Enoent.as_i32() as i64)
                || rc == -(Errno::Enotdir.as_i32() as i64);
            if !unresolved { return Err(rc); }
            match ext4::rootfs::read_file(path) {
                Some(blob) => Ok((blob, None)),
                None => Err(rc),
            }
        }
    }
}

/// Resolve a `#!`-script chain per Linux `fs/binfmt_script.c`.
///
/// On entry:
///   * `blob_owned` holds the file content the user asked execve to load
///   * `path_owned` holds the path the user named
///   * `argv_vec` holds the original argv (argv[0] is the user's choice)
///
/// On every iteration where `blob_owned` begins with `#!`:
///   1. Parse `#!<interp>[ <opt-arg>]\n` from the first line (max 128 bytes).
///   2. Splice argv: new argv = [interp, opt-arg?, original_path] ++ argv[1..].
///      argv[0] of the original program is dropped, exactly as Linux does.
///   3. Update `path_owned` to `interp`, re-read it from ext4 into
///      `blob_owned`, and loop. Bail with ENOENT if interp missing.
///
/// Every interpreter is re-opened through the same `do_open_execat` gate the
/// original file went through (Linux loops `search_binary_handler`, and each
/// pass re-opens), so `mode 0000` or a `noexec` mount on `/bin/sh` denies the
/// script too. `exec_path` tracks the resolved path of the file the credential
/// transition must be computed from — Linux's `bprm->file` after the rewrite
/// loop, which is the INTERPRETER, never the script. That is why a setuid shell
/// script confers nothing.
///
/// Recursion cap = 4 (matches Linux `BINPRM_MAX_RECURSION`).
/// Returns `Ok(())` when the chain terminates on a non-script blob.
/// # C: O(N_chain × file_size)
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn resolve_shebang_chain(
    blob_owned: &mut alloc::vec::Vec<u8>,
    path_owned: &mut alloc::vec::Vec<u8>,
    argv_vec: &mut alloc::vec::Vec<alloc::vec::Vec<u8>>,
    exec_path: &mut Option<vfs::VfsPath>,
) -> Result<(), i64> {
    for _ in 0..4 {
        if blob_owned.len() < 2 || &blob_owned[..2] != b"#!" {
            return Ok(());
        }
        let head_end = blob_owned.iter().take(128).position(|&b| b == b'\n')
            .unwrap_or_else(|| blob_owned.len().min(128));
        let line = &blob_owned[2..head_end];
        let mut i = 0usize;
        while i < line.len() && (line[i] == b' ' || line[i] == b'\t') { i += 1; }
        let interp_start = i;
        while i < line.len() && line[i] != b' ' && line[i] != b'\t' { i += 1; }
        let interp_end = i;
        if interp_end == interp_start { return Err(-(Errno::Enoexec.as_i32() as i64)); }
        let interp: alloc::vec::Vec<u8> = line[interp_start..interp_end].to_vec();
        while i < line.len() && (line[i] == b' ' || line[i] == b'\t') { i += 1; }
        let mut j = line.len();
        while j > i && (line[j-1] == b' ' || line[j-1] == b'\t' || line[j-1] == b'\r') { j -= 1; }
        let opt_arg: Option<alloc::vec::Vec<u8>> =
            if j > i { Some(line[i..j].to_vec()) } else { None };
        let cur_path: alloc::vec::Vec<u8> = path_owned.clone();
        // Splice argv per Linux: drop original argv[0] (if any), prepend
        // [interp, opt-arg?, original_path] in front of argv[1..].
        let original_tail: alloc::vec::Vec<alloc::vec::Vec<u8>> =
            if argv_vec.is_empty() {
                alloc::vec::Vec::new()
            } else {
                argv_vec.drain(..).skip(1).collect()
            };
        argv_vec.push(interp.clone());
        if let Some(a) = opt_arg { argv_vec.push(a); }
        argv_vec.push(cur_path);
        argv_vec.extend(original_tail);
        // Update path → interp, re-open it through the full exec gate.
        *path_owned = interp.clone();
        let (blob, vp) = open_exec_image(&interp)?;
        *blob_owned = blob;
        *exec_path = vp;
    }
    // Recursion cap exceeded (Linux `exec_binprm`: `if (depth > 5) return -ELOOP`).
    Err(-(Errno::Eloop.as_i32() as i64))
}

/// The file an exec image was read from, as the ELF loader wants it: Linux
/// `bprm->file`, which becomes `vma->vm_file` on every PT_LOAD the loader maps
/// out of it, so the program's own text and data are file-backed mappings
/// rather than private memory with nothing behind them.
/// # C: O(1)
pub(crate) fn image_backing(vp: &vfs::VfsPath) -> alloc::sync::Arc<dyn vmm::FileBacking> {
    crate::mmap_file::InodeFileBacking::new(vp.inode.clone())
}

/// Open the pathname a PT_INTERP names through the same `do_open_execat` gate
/// the exec image went through, and hand back its bytes together with its file.
/// `None` leaves the loader on its boot-time rootfs reader, which resolves no
/// inode and therefore yields no file.
/// # C: O(components) + O(size/PAGE)
pub(crate) fn open_interp(path: &[u8])
    -> Option<(alloc::vec::Vec<u8>, Option<alloc::sync::Arc<dyn vmm::FileBacking>>)>
{
    let (blob, vp) = crate::pathresolve::open_exec(path).ok()?;
    Some((blob, Some(image_backing(&vp))))
}
