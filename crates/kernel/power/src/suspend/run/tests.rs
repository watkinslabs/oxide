use super::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::suspend::ops::{PlatformS2idleOps, PlatformSuspendOps};

// A recording backend. Each call appends a marker; the test reads the sequence
// back and compares it against `sequence::forward_steps` / `unwind_from`
// rendered through the same marker vocabulary, so the orchestrator and the
// table are checked against each other rather than against a hand-written list.

const M_SYNC: u32 = 1; const M_FREEZE_U: u32 = 2; const M_FREEZE_K: u32 = 3;
const M_PBEGIN: u32 = 4; const M_CON_SUSP: u32 = 5; const M_DPREP: u32 = 6;
const M_DSUSP: u32 = 7; const M_PPREP: u32 = 8; const M_DLATE: u32 = 9;
const M_PPREP_LATE: u32 = 10; const M_DNOIRQ: u32 = 11; const M_PPREP_NOIRQ: u32 = 12;
const M_CPUS_OFF: u32 = 13; const M_IRQS_OFF: u32 = 14; const M_SYSCORE_S: u32 = 15;
const M_PENTER: u32 = 16; const M_S2IDLE: u32 = 17;

const M_SYSCORE_R: u32 = 101; const M_IRQS_ON: u32 = 102; const M_CPUS_ON: u32 = 103;
const M_PWAKE: u32 = 104; const M_DR_NOIRQ: u32 = 105; const M_PRESTORE: u32 = 106;
const M_DR_EARLY: u32 = 107; const M_PFINISH: u32 = 108; const M_DRESUME: u32 = 109;
const M_DCOMPLETE: u32 = 110; const M_CON_RES: u32 = 111; const M_PEND: u32 = 112;
const M_THAW: u32 = 113;
const M_PRECOVER: u32 = 120;

static TRACE: [AtomicU32; 128] = [const { AtomicU32::new(0) }; 128];
static N: AtomicUsize = AtomicUsize::new(0);
/// Marker of the forward call that must fail, or zero for none.
static FAIL_AT: AtomicU32 = AtomicU32::new(0);
/// Whether the wakeup check reports pending at the pre-enter probe.
static WAKEUP: AtomicU32 = AtomicU32::new(0);
/// Remaining platform repeat requests.
static AGAIN: AtomicU32 = AtomicU32::new(0);

fn push(m: u32) {
    let i = N.fetch_add(1, Ordering::SeqCst);
    if i < TRACE.len() { TRACE[i].store(m, Ordering::SeqCst); }
}
fn trace() -> Vec<u32> {
    (0..N.load(Ordering::SeqCst).min(TRACE.len()))
        .map(|i| TRACE[i].load(Ordering::SeqCst)).collect()
}
fn reset() {
    N.store(0, Ordering::SeqCst);
    FAIL_AT.store(0, Ordering::SeqCst);
    WAKEUP.store(0, Ordering::SeqCst);
    AGAIN.store(0, Ordering::SeqCst);
    crate::suspend::tunables::release_transition();
    crate::suspend::tunables::set_sync_on_suspend(true);
}
fn step_call(m: u32) -> KResult<()> {
    push(m);
    if FAIL_AT.load(Ordering::SeqCst) == m { Err(Error::Io) } else { Ok(()) }
}

fn sync_fs() -> KResult<()> { step_call(M_SYNC) }
fn freeze_u() -> KResult<()> { step_call(M_FREEZE_U) }
fn freeze_k() -> KResult<()> { step_call(M_FREEZE_K) }
fn thaw() { push(M_THAW); }
fn con_susp() { push(M_CON_SUSP); }
fn con_res() { push(M_CON_RES); }
fn dprep() -> KResult<()> { step_call(M_DPREP) }
fn dsusp() -> KResult<()> { step_call(M_DSUSP) }
fn dlate() -> KResult<()> { step_call(M_DLATE) }
fn dnoirq() -> KResult<()> { step_call(M_DNOIRQ) }
fn dr_noirq() { push(M_DR_NOIRQ); }
fn dr_early() { push(M_DR_EARLY); }
fn dresume() { push(M_DRESUME); }
fn dcomplete() { push(M_DCOMPLETE); }
fn cpus_off() -> KResult<()> { step_call(M_CPUS_OFF) }
fn cpus_on() { push(M_CPUS_ON); }
fn irqs_off() -> u64 { push(M_IRQS_OFF); 0x1234 }
fn irqs_on(v: u64) { assert_eq!(v, 0x1234, "interrupt state not round-tripped"); push(M_IRQS_ON); }
fn syscore_s() -> KResult<()> { step_call(M_SYSCORE_S) }
fn syscore_r() { push(M_SYSCORE_R); }
fn s2idle() { push(M_S2IDLE); }
fn wakeup() -> bool { WAKEUP.load(Ordering::SeqCst) != 0 }

fn backend() -> SuspendBackend {
    SuspendBackend {
        sync_filesystems: sync_fs, freeze_processes: freeze_u,
        freeze_kernel_threads: freeze_k, thaw_processes: thaw,
        console_suspend: con_susp, console_resume: con_res,
        dpm_prepare: dprep, dpm_suspend: dsusp, dpm_suspend_late: dlate,
        dpm_suspend_noirq: dnoirq, dpm_resume_noirq: dr_noirq, dpm_resume_early: dr_early,
        dpm_resume: dresume, dpm_complete: dcomplete,
        disable_secondary_cpus: cpus_off, enable_secondary_cpus: cpus_on,
        irqs_off, irqs_on, syscore_suspend: syscore_s, syscore_resume: syscore_r,
        s2idle_loop: s2idle, wakeup_pending: wakeup,
    }
}

// Platform tables that record every hook.
fn p_valid(_s: SuspendState) -> bool { true }
fn p_begin(_s: SuspendState) -> KResult<()> { step_call(M_PBEGIN) }
fn p_prepare() -> KResult<()> { step_call(M_PPREP) }
fn p_prepare_late() -> KResult<()> { step_call(M_PPREP_NOIRQ) }
fn p_enter(_s: SuspendState) -> KResult<()> { step_call(M_PENTER) }
fn p_wake() { push(M_PWAKE); }
fn p_finish() { push(M_PFINISH); }
fn p_end() { push(M_PEND); }
fn p_recover() { push(M_PRECOVER); }
fn p_again() -> bool {
    AGAIN.fetch_update(Ordering::SeqCst, Ordering::SeqCst,
        |v| if v > 0 { Some(v - 1) } else { None }).is_ok()
}
static DEEP: PlatformSuspendOps = PlatformSuspendOps {
    valid: Some(p_valid), begin: Some(p_begin), prepare: Some(p_prepare),
    prepare_late: Some(p_prepare_late), enter: Some(p_enter), wake: Some(p_wake),
    finish: Some(p_finish), suspend_again: Some(p_again), end: Some(p_end),
    recover: Some(p_recover),
};

fn i_begin() -> KResult<()> { step_call(M_PBEGIN) }
fn i_prepare() -> KResult<()> { step_call(M_PPREP_LATE) }
fn i_prepare_late() -> KResult<()> { step_call(M_PPREP_NOIRQ) }
fn i_restore_early() { push(M_PWAKE); }
fn i_restore() { push(M_PRESTORE); }
fn i_end() { push(M_PEND); }
static IDLE: PlatformS2idleOps = PlatformS2idleOps {
    begin: Some(i_begin), prepare: Some(i_prepare), prepare_late: Some(i_prepare_late),
    wake: None, check: None, restore_early: Some(i_restore_early),
    restore: Some(i_restore), end: Some(i_end),
};

fn tables() -> Tables<'static> { Tables { suspend: Some(&DEEP), s2idle: Some(&IDLE) } }

/// The marker a forward step produces, or `None` when the step has no call in
/// this backend (the console suspend is a bare hook, not a step call).
fn forward_marker(s: Step) -> u32 {
    match s {
        Step::Sync => M_SYNC, Step::FreezeUser => M_FREEZE_U,
        Step::FreezeKernelThreads => M_FREEZE_K, Step::PlatformBegin => M_PBEGIN,
        Step::ConsoleSuspend => M_CON_SUSP, Step::DevPrepare => M_DPREP,
        Step::DevSuspend => M_DSUSP, Step::PlatformPrepare => M_PPREP,
        Step::DevSuspendLate => M_DLATE, Step::PlatformPrepareLate => M_PPREP_LATE,
        Step::DevSuspendNoirq => M_DNOIRQ, Step::PlatformPrepareNoirq => M_PPREP_NOIRQ,
        Step::CpusOff => M_CPUS_OFF, Step::IrqsOff => M_IRQS_OFF,
        Step::SyscoreSuspend => M_SYSCORE_S, Step::PlatformEnter => M_PENTER,
        Step::S2idleLoop => M_S2IDLE,
    }
}

fn undo_marker(u: Undo) -> u32 {
    match u {
        Undo::SyscoreResume => M_SYSCORE_R, Undo::IrqsOn => M_IRQS_ON,
        Undo::CpusOn => M_CPUS_ON, Undo::PlatformWake => M_PWAKE,
        Undo::DevResumeNoirq => M_DR_NOIRQ, Undo::PlatformRestore => M_PRESTORE,
        Undo::DevResumeEarly => M_DR_EARLY, Undo::PlatformFinish => M_PFINISH,
        Undo::DevResume => M_DRESUME, Undo::DevComplete => M_DCOMPLETE,
        Undo::ConsoleResume => M_CON_RES, Undo::PlatformEnd => M_PEND,
        Undo::ThawProcesses => M_THAW,
    }
}

/// The trace a cycle for `state` must produce when it fails at `fail`, derived
/// from the sequence table rather than written out by hand.
fn expected(state: SuspendState, fail: Option<Step>) -> Vec<u32> {
    let steps = sequence::forward_steps(state);
    let mut out = Vec::new();
    let mut reached = *steps.last().unwrap();
    for s in steps {
        // The platform hooks the tables leave absent produce no marker.
        let skip = match (state, s) {
            (SuspendState::ToIdle, Step::PlatformPrepare) => true,
            (SuspendState::Mem | SuspendState::Standby, Step::PlatformPrepareLate) => true,
            _ => false,
        };
        if !skip { out.push(forward_marker(*s)); }
        if Some(*s) == fail { reached = *s; break; }
    }
    // The kernel-thread pass leaves userspace frozen for its caller to thaw.
    if fail == Some(Step::FreezeKernelThreads) { out.push(M_THAW); }
    // The recover hook is deep-only, so suspend-to-idle never reaches it.
    if fail.is_some() && state != SuspendState::ToIdle
        && sequence::runs_platform_recover(reached) { out.push(M_PRECOVER); }
    for u in sequence::unwind_from(reached) {
        let u = *u;
        // The deep tables have no `restore`; the idle table has no `finish`.
        let skip = match (state, u) {
            (SuspendState::Mem | SuspendState::Standby, Undo::PlatformRestore) => true,
            (SuspendState::ToIdle, Undo::PlatformFinish) => true,
            _ => false,
        };
        if !skip { out.push(undo_marker(u)); }
    }
    out
}

fn run(state: SuspendState, fail: Option<Step>) -> KResult<()> {
    reset();
    if let Some(f) = fail { FAIL_AT.store(forward_marker(f), Ordering::SeqCst); }
    pm_suspend(state, &backend(), tables())
}

#[test]
fn a_complete_deep_cycle_runs_the_table_forward_then_backward() {
    let _g = crate::suspend::test_lock();
    assert!(run(SuspendState::Mem, None).is_ok());
    assert_eq!(trace(), expected(SuspendState::Mem, None));
}

#[test]
fn a_complete_freeze_cycle_runs_the_idle_table() {
    let _g = crate::suspend::test_lock();
    assert!(run(SuspendState::ToIdle, None).is_ok());
    assert_eq!(trace(), expected(SuspendState::ToIdle, None));
    // The deep-only steps never appear.
    for m in [M_CPUS_OFF, M_IRQS_OFF, M_SYSCORE_S, M_PENTER] {
        assert!(!trace().contains(&m), "freeze reached marker {m}");
    }
}

#[test]
fn hibernation_suspend_mode_reuses_only_the_device_half() {
    let _g = crate::suspend::test_lock();
    reset();
    let claim = crate::transition::try_claim().unwrap();
    assert_eq!(suspend_devices_and_enter(SuspendState::Mem, &backend(), tables()), Ok(()));
    let events = trace();
    for outer in [M_SYNC, M_FREEZE_U, M_FREEZE_K, M_THAW] {
        assert!(!events.contains(&outer), "device-only cycle repeated outer step {outer}");
    }
    assert!(events.contains(&M_DPREP) && events.contains(&M_PENTER));
    drop(claim);
}

#[test]
fn every_failure_point_unwinds_exactly_what_the_table_says() {
    let _g = crate::suspend::test_lock();
    for state in [SuspendState::Mem, SuspendState::ToIdle] {
        for step in sequence::forward_steps(state) {
            // Steps with no fallible call in this backend cannot be failed.
            if matches!(step, Step::ConsoleSuspend | Step::IrqsOff | Step::S2idleLoop) { continue; }
            // A core-callback or platform-enter failure does not change the
            // unwind; those two have their own tests.
            if matches!(step, Step::SyscoreSuspend | Step::PlatformEnter) { continue; }
            // The platform hooks absent for this state have no call to fail.
            if state == SuspendState::ToIdle && *step == Step::PlatformPrepare { continue; }
            if state != SuspendState::ToIdle && *step == Step::PlatformPrepareLate { continue; }
            let r = run(state, Some(*step));
            assert!(r.is_err(), "{state:?}/{step:?} succeeded despite a forced failure");
            assert_eq!(trace(), expected(state, Some(*step)),
                "{state:?} failing at {step:?} unwound the wrong steps");
        }
    }
}

#[test]
fn the_freezer_failing_unwinds_nothing_above_it() {
    let _g = crate::suspend::test_lock();
    assert!(run(SuspendState::Mem, Some(Step::FreezeUser)).is_err());
    assert_eq!(trace(), [M_SYNC, M_FREEZE_U]);
}

#[test]
fn the_kernel_thread_pass_failing_thaws_userspace_and_stops() {
    let _g = crate::suspend::test_lock();
    assert!(run(SuspendState::Mem, Some(Step::FreezeKernelThreads)).is_err());
    assert_eq!(trace(), [M_SYNC, M_FREEZE_U, M_FREEZE_K, M_THAW]);
}

#[test]
fn the_sync_can_be_turned_off() {
    let _g = crate::suspend::test_lock();
    reset();
    crate::suspend::tunables::set_sync_on_suspend(false);
    assert!(pm_suspend(SuspendState::ToIdle, &backend(), tables()).is_ok());
    assert!(!trace().contains(&M_SYNC));
    crate::suspend::tunables::set_sync_on_suspend(true);
}

#[test]
fn a_wakeup_before_the_enter_skips_the_platform_and_unwinds_normally() {
    let _g = crate::suspend::test_lock();
    reset();
    WAKEUP.store(1, Ordering::SeqCst);
    // The reference reports the abort to userspace rather than silently
    // returning success from a suspend that never happened.
    assert_eq!(pm_suspend(SuspendState::Mem, &backend(), tables()), Err(Error::Busy));
    let t = trace();
    assert!(!t.contains(&M_PENTER), "the machine slept with a wakeup pending");
    // Everything else is unchanged: the sequence still unwinds in full.
    assert!(t.contains(&M_SYSCORE_R) && t.contains(&M_IRQS_ON) && t.contains(&M_THAW));
}

#[test]
fn the_core_callbacks_refusing_skips_the_enter_but_still_restores_irqs_and_cpus() {
    let _g = crate::suspend::test_lock();
    assert_eq!(run(SuspendState::Mem, Some(Step::SyscoreSuspend)), Err(Error::Io));
    let t = trace();
    assert!(!t.contains(&M_PENTER));
    // The core callbacks unwound themselves, so no resume here...
    assert!(!t.contains(&M_SYSCORE_R), "the core callbacks were resumed twice");
    // ...but interrupts and the secondary CPUs are still this layer's debt.
    assert!(t.contains(&M_IRQS_ON) && t.contains(&M_CPUS_ON));
}

#[test]
fn the_platform_enter_failing_still_unwinds_in_full() {
    let _g = crate::suspend::test_lock();
    assert_eq!(run(SuspendState::Mem, Some(Step::PlatformEnter)), Err(Error::Io));
    assert_eq!(trace(), expected(SuspendState::Mem, None));
}

#[test]
fn a_platform_repeat_re_runs_only_the_inner_half() {
    let _g = crate::suspend::test_lock();
    reset();
    AGAIN.store(1, Ordering::SeqCst);
    assert!(pm_suspend(SuspendState::Mem, &backend(), tables()).is_ok());
    let t = trace();
    let count = |m: u32| t.iter().filter(|x| **x == m).count();
    assert_eq!(count(M_PENTER), 2, "the platform repeat did not re-enter");
    assert_eq!(count(M_PPREP), 2, "the inner half did not repeat");
    assert_eq!(count(M_DSUSP), 1, "the outer half repeated");
    assert_eq!(count(M_THAW), 1, "tasks thawed more than once");
    assert_eq!(count(M_PEND), 1, "the platform transition closed twice");
}

#[test]
fn a_repeat_is_not_requested_once_something_woke_the_machine() {
    let _g = crate::suspend::test_lock();
    reset();
    AGAIN.store(3, Ordering::SeqCst);
    WAKEUP.store(1, Ordering::SeqCst);
    assert_eq!(pm_suspend(SuspendState::Mem, &backend(), tables()), Err(Error::Busy));
    let t = trace();
    assert_eq!(t.iter().filter(|x| **x == M_PPREP).count(), 1,
        "the platform kept re-entering after a wakeup");
}

#[test]
fn an_unavailable_state_is_refused_before_anything_runs() {
    let _g = crate::suspend::test_lock();
    reset();
    let bare = Tables::none();
    assert_eq!(pm_suspend(SuspendState::Mem, &backend(), bare), Err(Error::Inval));
    assert_eq!(pm_suspend(SuspendState::Standby, &backend(), bare), Err(Error::Inval));
    assert_eq!(pm_suspend(SuspendState::On, &backend(), bare), Err(Error::Inval));
    assert!(trace().is_empty(), "a refused state still ran part of the sequence");
    // Suspend-to-idle needs no platform support and is never refused.
    assert!(pm_suspend(SuspendState::ToIdle, &backend(), bare).is_ok());
}

#[test]
fn a_second_transition_is_refused_while_one_is_claimed() {
    let _g = crate::suspend::test_lock();
    reset();
    assert!(crate::suspend::tunables::try_claim_transition());
    assert_eq!(pm_suspend(SuspendState::ToIdle, &backend(), tables()), Err(Error::Busy));
    assert!(trace().is_empty());
    crate::suspend::tunables::release_transition();
}

#[test]
fn the_statistics_record_the_outcome_of_every_attempt() {
    let _g = crate::suspend::test_lock();
    let before_ok = crate::suspend::stats::STATS.success();
    let before_bad = crate::suspend::stats::STATS.fail();
    assert!(run(SuspendState::ToIdle, None).is_ok());
    assert_eq!(crate::suspend::stats::STATS.success(), before_ok + 1);
    assert!(run(SuspendState::ToIdle, Some(Step::DevSuspendNoirq)).is_err());
    assert_eq!(crate::suspend::stats::STATS.fail(), before_bad + 1);
    assert_eq!(crate::suspend::stats::STATS.last_failed_step(),
        crate::suspend::stats::StatStep::SuspendNoirq);
    assert_eq!(crate::suspend::stats::STATS.last_failed_errno(), errno_of(Error::Io));
}

#[test]
fn the_transition_claim_is_released_however_the_attempt_ends() {
    let _g = crate::suspend::test_lock();
    assert!(run(SuspendState::Mem, Some(Step::DevSuspend)).is_err());
    assert!(!crate::suspend::tunables::transition_in_progress(),
        "a failed attempt left the transition claimed, so nothing can suspend again");
}

#[test]
fn errnos_are_the_linux_values() {
    assert_eq!(errno_of(Error::Inval), -22);
    assert_eq!(errno_of(Error::Busy), -16);
    assert_eq!(errno_of(Error::Nosys), -38);
    // Firmware declining a call it does not implement, kept distinct from the
    // kernel declining a state it does not offer.
    assert_eq!(errno_of(Error::Opnotsupp), -95);
    assert_eq!(errno_of(Error::Intr), -4);
    assert_eq!(errno_of(Error::Perm), -1);
    assert_eq!(errno_of(Error::Io), -5);
    assert_eq!(errno_of(Error::Again), -11);
    assert_eq!(errno_of(Error::Nomem), -12);
    assert_eq!(errno_of(Error::Nodata), -61);
    assert_eq!(errno_of(Error::Nospc), -28);
}
