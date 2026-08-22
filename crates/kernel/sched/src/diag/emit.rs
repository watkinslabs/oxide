#[cfg(feature = "debug-watchdog")]
use core::sync::atomic::Ordering;

#[cfg(feature = "debug-watchdog")]
use crate::Task;

#[cfg(feature = "debug-watchdog")]
use super::current_task;
#[cfg(feature = "debug-watchdog")]
use super::format::{col_dec, col_str, col_syscall, emit_syscall};
#[cfg(feature = "debug-watchdog")]
use super::ring::{dump_exit_recent, switches};

#[cfg(feature = "debug-watchdog")]
pub fn report_lockup(secs: u64, tid: u32, cur: Option<&Task>) {
    klog::write_raw(b"\n[WATCHDOG] soft lockup: no reschedule for ");
    klog::write_dec_u64(secs);
    klog::write_raw(b"s on tid=");
    klog::write_dec_u64(tid as u64);
    if let Some(t) = cur {
        klog::write_raw(b" (");
        let comm = t.comm_irq_safe();
        klog::write_raw(comm.as_bytes());
        klog::write_raw(b") last_syscall=");
        emit_syscall(t.last_syscall_nr.load(Ordering::Relaxed));
        #[cfg(feature = "debug-getdents")]
        super::getdents::emit_getdents(t);
        #[cfg(feature = "debug-syscall-return")]
        super::syscall_return::emit_syscall_return(t);
    }
    emit_lockup_context();
    emit_hibernate_softirq();
    emit_timer_state();
    klog::write_raw(b"\n");
    dump_tasks();
}

#[cfg(feature = "debug-watchdog")]
fn emit_hibernate_softirq() {
    let witness = softirq::hibernate_witness();
    if !witness.active { return; }
    klog::write_raw(b" hibernate_softirq_stage=");
    klog::write_dec_u64(witness.stage as u64);
    klog::write_raw(b" local=0x");
    klog::write_hex_u64(witness.local_bits as u64);
    klog::write_raw(b" process=0x");
    klog::write_hex_u64(witness.process_bits as u64);
    if witness.slot != u32::MAX {
        klog::write_raw(b" slot=");
        klog::write_dec_u64(witness.slot as u64);
    }
}

/// Emit the live scheduler gates that decide whether this CPU can take a
/// pending reschedule. Kept in the first watchdog line so a hard stall retains
/// the evidence even when the task snapshot cannot acquire its registry lock.
#[cfg(feature = "debug-watchdog")]
fn emit_lockup_context() {
    klog::write_raw(b" preempt_count=0x");
    klog::write_hex_u64(crate::preempt::preempt_count() as u64);
    klog::write_raw(b" resched=");
    klog::write_raw(if crate::preempt::need_resched() { b"y" } else { b"n" });
    klog::write_raw(b" irqs_off=");
    klog::write_raw(if crate::preempt::irqs_disabled() { b"y" } else { b"n" });
    klog::write_raw(b" interrupt=");
    klog::write_raw(if crate::preempt::in_interrupt() { b"y" } else { b"n" });
    let pc = super::watchdog::interrupted_kernel_pc();
    if pc != 0 {
        klog::write_raw(b" kernel_pc=0x");
        klog::write_hex_u64(pc);
    }
    #[cfg(feature = "debug-preempt")]
    {
        let (rank, depth, overflow) = sync::preempt_gate::held_trace();
        klog::write_raw(b" held_lock_rank=");
        klog::write_dec_u64(rank as u64);
        klog::write_raw(b" held_lock_depth=");
        klog::write_dec_u64(depth as u64);
        if overflow != 0 {
            klog::write_raw(b" held_lock_overflow=");
            klog::write_dec_u64(overflow as u64);
        }
    }
}

/// A task dump names the KTHREAD, which for a timer wedge is always `ktimers` —
/// never the callback that actually hung. `timer::run_state` closes that gap:
/// the phase says whether `run_due` was scanning or firing, and the address
/// names the exact callback. `addr2line` it against the booted ELF.
#[cfg(feature = "debug-watchdog")]
fn emit_timer_state() {
    let (phase, f) = timer::run_state();
    klog::write_raw(b" timer_phase=");
    klog::write_raw(match phase {
        timer::PHASE_IDLE => b"idle" as &[u8],
        timer::PHASE_SCAN_PERIODIC => b"scan-periodic",
        timer::PHASE_SCAN_ONESHOT => b"scan-oneshot",
        timer::PHASE_FIRE_PERIODIC => b"fire-periodic",
        timer::PHASE_FIRE_ONESHOT => b"fire-oneshot",
        _ => b"?",
    });
    if f != 0 {
        klog::write_raw(b" timer_fn=0x");
        klog::write_hex_u64(f as u64);
    }
}

pub fn dump_tasks() {
    #[cfg(feature = "debug-watchdog")]
    dump_tasks_emit();
}

#[cfg(feature = "debug-watchdog")]
fn dump_tasks_emit() {
    klog::write_raw(b"[sysrq] task dump  switches=");
    klog::write_dec_u64(switches());
    if let Some(t) = current_task() {
        klog::write_raw(b" current=tid:");
        klog::write_dec_u64(t.tid as u64);
    }
    klog::write_raw(b"\n  PID   TID name             ST onrq oncpu onwl cpu  last-sysc  nsysc      cputime_ms\n");

    let tasks = match crate::registry::try_snapshot() {
        Some(v) => v,
        None => {
            klog::write_raw(b"  <registry busy - lock held; cannot snapshot>\n");
            return;
        }
    };
    for t in tasks.iter() {
        let vpid = t.vtgid.load(Ordering::Relaxed);
        col_dec(if vpid != 0 { vpid as u64 } else { t.tid as u64 }, 5);
        klog::write_raw(b" ");
        col_dec(t.tid as u64, 6);
        klog::write_raw(b" ");
        // Hard-IRQ context (serial sysrq): never spin on a task's exe_path.
        let comm = t.comm_irq_safe();
        col_str(&comm, 16);
        klog::write_raw(b" ");
        klog::write_raw(&[t.linux_state_char()]);
        // Mark reaped-but-pidfd-pinned tasks (release_task done; gone from /proc)
        // so the dump distinguishes them from genuinely-unreaped zombies.
        if t.reaped.load(Ordering::Relaxed) { klog::write_raw(b"* "); } else { klog::write_raw(b"  "); }
        klog::write_raw(if t.on_rq.load(Ordering::Relaxed) { b"y  " } else { b"n  " });
        klog::write_raw(if t.on_cpu.load(Ordering::Relaxed) { b"y    " } else { b"n    " });
        klog::write_raw(if t.on_wake_list.load(Ordering::Relaxed) { b"y   " } else { b"n   " });
        let cpu = t.cpu.load(Ordering::Relaxed);
        if cpu == u16::MAX { klog::write_raw(b"  -"); } else { col_dec(cpu as u64, 3); }
        if matches!(t.state(), crate::TaskState::Waking) {
            let phase = crate::task::WakeDiagPhase::from_u8(t.wake_diag_phase.load(Ordering::Acquire));
            let marked = t.wake_diag_ns.load(Ordering::Acquire);
            let age = if marked == 0 { 0 } else { timekeeper::monotonic_ns().saturating_sub(marked) / 1_000_000 };
            klog::write_raw(b" wake="); klog::write_raw(phase.label());
            klog::write_raw(b" wake_age_ms="); klog::write_dec_u64(age);
        }
        klog::write_raw(b"  ");
        col_syscall(t.last_syscall_nr.load(Ordering::Relaxed));
        klog::write_raw(b" ");
        col_dec(t.nsyscalls.load(Ordering::Relaxed), 10);
        klog::write_raw(b" ");
        col_dec(t.sum_exec_runtime_ns.load(Ordering::Relaxed) / 1_000_000, 10);
        klog::write_raw(b" tgid="); col_dec(t.tgid.load(Ordering::Relaxed) as u64, 6);
        klog::write_raw(b" vtid="); col_dec(t.vtid.load(Ordering::Relaxed) as u64, 6);
        klog::write_raw(b" ptid="); col_dec(t.parent_tid.load(Ordering::Relaxed) as u64, 6);
        let fux = t.futex_uaddr.load(Ordering::Relaxed);
        if fux != 0 { klog::write_raw(b" fux="); klog::write_hex_u64(fux); }
        let wake_dl = t.wakeup_deadline_ns.load(Ordering::Relaxed);
        if wake_dl != 0 { klog::write_raw(b" wake_dl_ns="); klog::write_dec_u64(wake_dl); }
        emit_wchan(t);
        // Non-blocking: a held exe_path lock must not wedge the dump's CPU.
        let shown = t.try_with_exe_path(|p| if let Some(p) = p {
            klog::write_raw(b" exe="); klog::write_raw(p.as_bytes());
        });
        if shown.is_none() { klog::write_raw(b" exe=<locked>"); }
        #[cfg(feature = "debug-getdents")]
        super::getdents::emit_getdents(t);
        #[cfg(feature = "debug-syscall-return")]
        super::syscall_return::emit_syscall_return(t);
        klog::write_raw(b"\n");
    }
}

/// `/proc/<pid>/wchan` for the task dump: the source position of the wait a
/// blocked task is sitting in. Printed only where the reference's `get_wchan`
/// would answer — a task that is off-CPU, off every runqueue and blocked —
/// because the recorded site is stale for anything else.
/// # C: O(path length)
#[cfg(feature = "debug-watchdog")]
fn emit_wchan(t: &Task) {
    if !crate::park_site::reportable(t.state(), t.on_rq.load(Ordering::Relaxed),
                                     t.on_cpu.load(Ordering::Relaxed)) {
        return;
    }
    let Some(site) = t.park_site.get() else { return };
    klog::write_raw(b" wchan=");
    klog::write_raw(site.file().as_bytes());
    klog::write_raw(b":");
    klog::write_dec_u64(site.line() as u64);
}

pub fn note_init_exit(code: i32) {
    #[cfg(feature = "debug-watchdog")]
    {
        klog::write_raw(b"\n[INIT-DEATH] PID 1 (init) exited code=");
        klog::write_dec_u64(code as u64);
        klog::write_raw(b" - no init, system will hang (Linux would panic)\n");
        dump_exit_recent("init", code as u64);
        dump_tasks();
    }
    #[cfg(not(feature = "debug-watchdog"))]
    let _ = code;
}

/// The serial line's byte sink. Decoding lives in `super::sysrq`, which the
/// `/proc/sysrq-trigger` write path shares — a second private key table here
/// is how `c` came to print a table on a machine an operator meant to crash.
/// # C: see `sysrq::perform`
pub fn sysrq_rx(armed_until_ns: &core::sync::atomic::AtomicU64, b: u8) -> bool {
    super::sysrq::rx(armed_until_ns, b)
}
