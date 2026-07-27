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

/// Decode the `security.capability` xattr on `inode` (Linux's
/// `struct vfs_cap_data` v2/v3 layout) and apply file capabilities
/// to `task.creds` per `capabilities(7)` semantics.
///
/// Layout (`linux/capability.h`):
///   magic_etc:  u32 (low 24 bits version, top 8 = flags;
///                    VFS_CAP_FLAGS_EFFECTIVE = 0x01)
///   permitted:  [u32; 2]
///   inheritable: [u32; 2]
///   v3 adds rootid: u32 at the tail (24 bytes total). v2 = 20 bytes.
///
/// Effect on the task post-execve (simplified Linux rule):
///   new_perm  = (file.perm  | (cap_inheritable & file.inh)) & cap_bounding
///   new_eff   = if VFS_CAP_FLAGS_EFFECTIVE then new_perm else 0
///   inh stays unchanged.
/// # C: O(1)
/// Capability transition every execve must apply, regardless of whether the
/// exec'd file's inode resolves for file-caps. Privileged-root path (Linux
/// `cap_bprm_creds_from_file`): a process exec'ing with euid 0 regains the
/// full bounding set as permitted AND effective. systemd's executor lowers
/// its *effective* set before execve and relies on the kernel restoring
/// effective=permitted for root on exec; without this, systemd-networkd
/// (root, then drops privs deliberately) can't acquire CAP_SETPCAP and aborts
/// ("Failed to drop privileges: Operation not permitted"). # C: O(1)
pub(crate) fn regain_root_caps_at_execve(cur: &sched::Task) {
    use core::sync::atomic::Ordering;
    let euid = cur.creds.euid.load(Ordering::Acquire);
    if euid == 0 {
        let bounding = cur.creds.cap_bounding.load(Ordering::Acquire);
        cur.creds.cap_permitted.store(bounding, Ordering::Release);
        cur.creds.cap_effective.store(bounding, Ordering::Release);
    }
}

/// Apply the exec'd file's `security.capability` xattr to the task's caps
/// (non-root file-cap path; root is handled by `regain_root_caps_at_execve`).
/// # C: O(1)
pub(crate) fn apply_file_caps_at_execve(inode: &vfs::InodeRef, cur: &sched::Task) {
    use core::sync::atomic::Ordering;
    const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x01;
    // First probe the value length via getxattr-len (buf=0).
    let s = "security.capability";
    let want = ::fs::xattr::query_len(inode, s);
    if want < 12 { return; }
    let mut buf = alloc::vec![0u8; want.min(24)];
    if !::fs::xattr::query_into(inode, s, &mut buf) { return; }
    if buf.len() < 12 { return; }
    let read_u32 = |off: usize| -> u32 {
        u32::from_le_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]])
    };
    let magic_etc = read_u32(0);
    let perm = ((read_u32(4) as u64) | ((read_u32(8) as u64) << 32)) & ((1u64 << 40) - 1);
    let inh  = if buf.len() >= 20 {
        ((read_u32(12) as u64) | ((read_u32(16) as u64) << 32)) & ((1u64 << 40) - 1)
    } else { 0 };
    let task_inh = cur.creds.cap_inheritable.load(Ordering::Acquire);
    let bounding = cur.creds.cap_bounding.load(Ordering::Acquire);
    let new_perm = (perm | (task_inh & inh)) & bounding;
    let new_eff  = if magic_etc & VFS_CAP_FLAGS_EFFECTIVE != 0 { new_perm } else { 0 };
    cur.creds.cap_permitted.store(new_perm, Ordering::Release);
    cur.creds.cap_effective.store(new_eff,  Ordering::Release);
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
/// Recursion cap = 4 (matches Linux `BINPRM_MAX_RECURSION`).
/// Returns `Ok(())` when the chain terminates on a non-script blob.
/// # C: O(N_chain × file_size)
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn resolve_shebang_chain(
    blob_owned: &mut alloc::vec::Vec<u8>,
    path_owned: &mut alloc::vec::Vec<u8>,
    argv_vec: &mut alloc::vec::Vec<alloc::vec::Vec<u8>>,
) -> Result<(), Errno> {
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
        if interp_end == interp_start { return Err(Errno::Enoexec); }
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
        // Update path → interp, refresh blob from ext4.
        *path_owned = interp.clone();
        match crate::pathresolve::read_exec(&interp)
            .or_else(|| ext4::rootfs::read_file(&interp)) {
            Some(v) => *blob_owned = v,
            None    => return Err(Errno::Enoent),
        }
    }
    // Recursion cap exceeded: Linux returns ELOOP; we lack ELOOP in
    // our errno table so map to ENOEXEC (closest valid v1 code).
    Err(Errno::Enoexec)
}
