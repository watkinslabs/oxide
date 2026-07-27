// `do_notify_parent` (Linux `kernel/signal.c`): the child-exit `siginfo` the
// real parent reads, and the `exit_notify` decision resolved against that
// parent's live SIGCHLD disposition. Split out of `zombies.rs` to keep the
// registry file inside the `08§7` cutoff.

use core::sync::atomic::Ordering;

use crate::Task;

/// Build the child-exit `SigInfo` for SIGCHLD or a real-time clone exit
/// signal. `si_pid`
/// is the child's VPID (vtgid — the value waitpid/fork return, NOT
/// the opaque internal tid); `si_uid` is the child's real uid;
/// `si_status` + `si_code` are decoded from the child's wait4-encoded
/// `exit_status` per siginfo(7): bit 8 (0x100) set ⇒ killed by signal
/// (CLD_KILLED / CLD_DUMPED if the core bit 0x80 is set on the signo),
/// else exited (CLD_EXITED, si_status = exit code).
/// # C: O(1)
pub(super) fn child_exit_info(child: &Task, signo: u32) -> crate::task::SigInfo {
    // CLD_* si_code values (siginfo(7) / asm-generic/siginfo.h).
    const CLD_EXITED: i32 = 1;
    const CLD_KILLED: i32 = 2;
    const CLD_DUMPED: i32 = 3;
    let raw = crate::exit::wait_status(child);
    let (code, status) = if crate::exit::status::is_signaled(raw) {
        let cld = if crate::exit::status::core_dumped(raw) { CLD_DUMPED } else { CLD_KILLED };
        (cld, crate::exit::status::term_sig(raw))
    } else {
        (CLD_EXITED, crate::exit::status::exit_code(raw))
    };
    crate::task::SigInfo {
        signo,
        code,
        pid:   child.vtgid.load(Ordering::Acquire),
        uid:   child.creds.ruid.load(Ordering::Acquire),
        value: status as u64,
    }
}

/// Queue a reparented child as SIGCHLD for init. Linux reparenting changes the
/// wait parent and uses the reaper's SIGCHLD notification contract. # C: O(1)
pub(super) fn push_child_event(child: &Task, parent: &Task) {
    parent.child_sigq_push(child_exit_info(child, crate::live::sigpend::Signum::Sigchld.as_u8() as u32));
}

/// Roll the dying child's CPU time into the parent's cumulative-children
/// counters for `getrusage(RUSAGE_CHILDREN)` / `times().tms_c[us]time`:
/// the child's tick-sampled user/kernel time (`utime_ns`/`stime_ns`) and,
/// for back-compat, its wall-clock elapsed into `cumulative_child_ns`.
/// Called once per child from `signal_child_exit` (the live exit path).
/// # C: O(1)
pub(super) fn accrue_child_time(child: &Task, parent: &Task) {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let elapsed = now.saturating_sub(child.spawn_ns.load(Ordering::Acquire));
    parent.cumulative_child_ns.fetch_add(elapsed, Ordering::AcqRel);
    parent.cumulative_child_utime_ns
        .fetch_add(child.utime_ns.load(Ordering::Acquire), Ordering::AcqRel);
    parent.cumulative_child_stime_ns
        .fetch_add(child.stime_ns.load(Ordering::Acquire), Ordering::AcqRel);
}

/// Linux `exit_notify` for `task`, resolved against its real parent's live
/// `SIGCHLD` disposition. A missing parent is treated as taking the default
/// action, which leaves the zombie for `reap_orphans` to re-home.
/// # C: O(1)
pub(super) fn exit_notify_decision(task: &Task, parent: Option<&Task>) -> crate::exit::notify::ExitNotify {
    use crate::exit::notify::{exit_notify, ParentSigchld};
    let disposition = parent.map_or(ParentSigchld::default_action(), |p| {
        let act = p.sigactions_ref().get(crate::live::sigpend::Signum::Sigchld.as_u8() as u32);
        ParentSigchld { handler: act.handler, flags: act.flags }
    });
    // `finish_exit` has already retired this task, so `live_count() == 0` is
    // Linux's `thread_group_empty(tsk)` at `exit_notify` time.
    exit_notify(
        task.pid.is_group_leader(),
        task.thread_group.live_count() == 0,
        crate::clone_exit_signal(task.exit_signal.load(Ordering::Acquire)),
        disposition,
    )
}
