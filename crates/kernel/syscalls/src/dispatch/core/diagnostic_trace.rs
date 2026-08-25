use syscall::SyscallArgs;

/// Retained executable-scoped syscall trace for the OpenSSH daemon. The
/// startup path uses this instead of the global SSH trace so generator fanout
/// keeps production timing while a no-banner daemon remains diagnosable.
/// # C: O(executable-path length)
#[cfg(feature = "debug-sshd-detail")]
pub(super) fn trace_sshd_syscall(nr: u64, rv: i64) {
    let Some(task) = sched::current() else { return; };
    let is_sshd = task.with_exe_path(|path| path.is_some_and(|path| path.ends_with("/sshd")));
    if !is_sshd { return; }
    klog::write_raw(b"[SSHD] tid=");
    klog::write_dec_u64(task.tid as u64);
    klog::write_raw(b" nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" rv=");
    klog::write_hex_u64(rv as u64);
    klog::write_raw(b"\n");
}

/// Retained feature-gated listener lifecycle trace for the OpenSSH daemon.
/// # C: O(executable-path length)
#[cfg(feature = "debug-sshd")]
pub(super) fn trace_sshd_listener_enter(nr: u64, args: &SyscallArgs) {
    if !is_sshd_listener_syscall(nr) { return; }
    let Some(tid) = sshd_tid() else { return; };
    klog::write_raw(b"[SSHD-LISTEN] enter tid=");
    klog::write_dec_u64(tid as u64);
    klog::write_raw(b" nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" a0=");
    klog::write_hex_u64(args.a0);
    klog::write_raw(b" a1=");
    klog::write_hex_u64(args.a1);
    klog::write_raw(b" a2=");
    klog::write_hex_u64(args.a2);
    klog::write_raw(b" a3=");
    klog::write_hex_u64(args.a3);
    klog::write_raw(b"\n");
}

/// Retained feature-gated listener lifecycle return trace for OpenSSH.
/// # C: O(executable-path length)
#[cfg(feature = "debug-sshd")]
pub(super) fn trace_sshd_listener_exit(nr: u64, rv: i64) {
    if !is_sshd_listener_syscall(nr) { return; }
    let Some(tid) = sshd_tid() else { return; };
    klog::write_raw(b"[SSHD-LISTEN] exit tid=");
    klog::write_dec_u64(tid as u64);
    klog::write_raw(b" nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" rv=");
    klog::write_hex_u64(rv as u64);
    klog::write_raw(b"\n");
}

#[cfg(feature = "debug-sshd")]
fn is_sshd_listener_syscall(nr: u64) -> bool {
    matches!(nr,
        syscall::nrs::NR_SOCKET |
        syscall::nrs::NR_BIND |
        syscall::nrs::NR_LISTEN |
        syscall::nrs::NR_ACCEPT4)
}

#[cfg(feature = "debug-sshd")]
fn sshd_tid() -> Option<u32> {
    let task = sched::current()?;
    task.with_exe_path(|path| path.is_some_and(|path| path.ends_with("/sshd"))).then_some(task.tid)
}

/// Retained, feature-gated syscall trace for systemd's random-seed helper.
/// It locates an early-boot entropy or persistence stall without changing the
/// production path or flooding the serial console with unrelated service I/O.
/// # C: O(executable-path length)
#[cfg(feature = "debug-random-seed")]
pub(super) fn trace_random_seed_syscall(nr: u64, rv: i64) {
    let Some(task) = sched::current() else { return; };
    let is_random_seed = task.with_exe_path(|path| path.is_some_and(|path| path.ends_with("/systemd-random-seed")));
    if !is_random_seed { return; }
    klog::write_raw(b"[RSEED] nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" rv=");
    klog::write_hex_u64(rv as u64);
    klog::write_raw(b"\n");
}

/// Retained, feature-gated syscall boundary trace for `/sbin/swapon` only.
/// It identifies an ABI failure before the final `swapon(2)` request without
/// perturbing any other userspace process.
/// # C: O(executable-path length)
#[cfg(feature = "debug-swap")]
pub(super) fn trace_swapon_process(phase: &[u8], nr: u64, result: Option<i64>) {
    let Some(task) = sched::current() else { return; };
    let is_swapon = task.with_exe_path(|path| path.is_some_and(|path| path.ends_with("/swapon")));
    if !is_swapon { return; }
    klog::write_raw(b"[SWAPON] ");
    klog::write_raw(phase);
    klog::write_raw(b" nr=");
    klog::write_dec_u64(nr);
    if let Some(result) = result {
        klog::write_raw(b" rv=");
        klog::write_hex_u64(result as u64);
    }
    klog::write_raw(b"\n");
}

/// Bounded ledger of every syscall that returns `EINVAL`, with the task that
/// received it. A userspace event loop whose dispatch callback fails with
/// "Invalid argument" gives no clue WHICH call failed — this names it instead
/// of guessing at the library's internals. Capped so a chatty-but-correct
/// EINVAL (e.g. `readlink` on a directory, which Linux also rejects) cannot
/// flood the console. # C: O(1) until the budget is spent, then a no-op
#[cfg(feature = "debug-boot")]
static EINVAL_LEDGER_REMAINING: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(4000);

#[cfg(feature = "debug-boot")]
pub(super) fn trace_einval(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, rv: i64) {
    use core::sync::atomic::Ordering as O;
    if rv != -(syscall::errno::Errno::Einval.as_i32() as i64) { return; }
    // Drop the two EINVALs that are CORRECT and high-volume, or they spend the
    // budget during early boot and the interesting one — which arrives with the
    // desktop, ~35s in — never prints. Both are probes whose EINVAL IS the
    // answer, and Linux returns it too:
    //   readlink(2) on a directory (libdrm/udev walking /sys), and
    //   prctl(PR_CAPBSET_READ, cap) above CAP_LAST_CAP, which is how
    //   `cap_last_cap` is discovered.
    const PR_CAPBSET_READ: u64 = 23;
    if nr == syscall::nrs::NR_READLINK || nr == syscall::nrs::NR_READLINKAT { return; }
    if nr == syscall::nrs::NR_PRCTL && a0 == PR_CAPBSET_READ { return; }
    if EINVAL_LEDGER_REMAINING.fetch_update(O::Relaxed, O::Relaxed,
        |remaining| remaining.checked_sub(1)).is_err() { return; }
    let Some(cur) = sched::live::current() else { return };
    klog::write_raw(b"[EINVAL nr=");
    klog::write_dec_u64(nr);
    klog::write_raw(b" tid=");
    klog::write_dec_u64(cur.tid as u64);
    klog::write_raw(b" a0=");
    klog::write_hex_u64(a0);
    klog::write_raw(b" a1=");
    klog::write_hex_u64(a1);
    klog::write_raw(b" a2=");
    klog::write_hex_u64(a2);
    klog::write_raw(b" a3=");
    klog::write_hex_u64(a3);
    klog::write_raw(b" a4=");
    klog::write_hex_u64(a4);
    klog::write_raw(b" a5=");
    klog::write_hex_u64(a5);
    // `a0` is an fd for most of the syscalls that land here; rendering its path
    // is what turns "write(33) failed" into "write to /run/... failed". Silent
    // when a0 is not a live fd, which is the common case for non-fd syscalls.
    // SAFETY: syscall-exit on the running task; the fd table has no concurrent
    // writer here, the same contract every other dispatch-path reader uses.
    if let Some(fdt) = unsafe { cur.fd_table_ref() } {
        if let Ok(file) = fdt.get(a0 as i32) {
            klog::write_raw(b" fdpath=");
            let path = file.dentry().dentry_path(None);
            klog::write_raw(path.as_bytes());
        }
    }
    klog::write_raw(b" comm=");
    if let Some(name) = cur.try_comm_bytes() {
        let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
        klog::write_raw(&name[..end]);
    }
    klog::write_raw(b"]\n");
}

