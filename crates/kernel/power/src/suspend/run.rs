// The suspend orchestrator: walks `32a§5` forward, then unwinds by replaying
// `sequence::unwind_from` for the furthest step it reached.
//
// The unwind is driven from the table rather than written out as a ladder of
// gotos. That is the point: the table is checkable and the ladder is not, and a
// ladder that drifts from the table unwinds the wrong steps in a situation
// nobody exercises until a laptop fails to wake.
//
// Everything the sequence touches arrives as a function pointer in
// [`SuspendBackend`], so this module runs hosted against a recording backend.
// The machine's real backend is assembled in `wire.rs`.

use crate::decide::{Error, KResult};
use super::platform::{self, Tables};
use super::sequence::{self, Step, Undo, UNWIND_ORDER};
use super::state::SuspendState;
use super::stats::STATS;
use super::tunables;

/// Everything the sequence calls that lives above this crate.
///
/// Failure contracts worth stating, because the sequence relies on them:
/// `freeze_processes` thaws what it froze before reporting failure, and
/// `freeze_kernel_threads` thaws the kernel threads but leaves userspace frozen
/// for the caller to thaw. Each `dpm_suspend_*` resumes its own partial state
/// before reporting failure.
pub struct SuspendBackend {
    pub sync_filesystems: fn() -> KResult<()>,
    pub freeze_processes: fn() -> KResult<()>,
    pub freeze_kernel_threads: fn() -> KResult<()>,
    pub thaw_processes: fn(),
    pub console_suspend: fn(),
    pub console_resume: fn(),
    pub dpm_prepare: fn() -> KResult<()>,
    pub dpm_suspend: fn() -> KResult<()>,
    pub dpm_suspend_late: fn() -> KResult<()>,
    pub dpm_suspend_noirq: fn() -> KResult<()>,
    pub dpm_resume_noirq: fn(),
    pub dpm_resume_early: fn(),
    pub dpm_resume: fn(),
    pub dpm_complete: fn(),
    pub disable_secondary_cpus: fn() -> KResult<()>,
    pub enable_secondary_cpus: fn(),
    /// Returns the saved interrupt state the matching enable restores.
    pub irqs_off: fn() -> u64,
    pub irqs_on: fn(u64),
    pub syscore_suspend: fn() -> KResult<()>,
    pub syscore_resume: fn(),
    pub s2idle_loop: fn(),
    pub wakeup_pending: fn() -> bool,
}

/// Index in [`UNWIND_ORDER`] one past the innermost frame's last undo. The
/// inner frame (steps 7-15) owns undo indices 0..8; the outer frame owns the
/// rest, so a platform repeat re-runs only the inner half.
const INNER_UNWIND_END: usize = 8;

/// State carried across the forward walk into the unwind.
struct Cycle { irq_state: u64 }

fn apply(u: Undo, state: SuspendState, be: &SuspendBackend, t: Tables, c: &mut Cycle) {
    match u {
        Undo::SyscoreResume   => (be.syscore_resume)(),
        Undo::IrqsOn          => (be.irqs_on)(c.irq_state),
        Undo::CpusOn          => (be.enable_secondary_cpus)(),
        Undo::PlatformWake    => platform::resume_noirq(t, state),
        Undo::DevResumeNoirq  => (be.dpm_resume_noirq)(),
        Undo::PlatformRestore => platform::resume_early(t, state),
        Undo::DevResumeEarly  => (be.dpm_resume_early)(),
        Undo::PlatformFinish  => platform::resume_finish(t, state),
        Undo::DevResume       => (be.dpm_resume)(),
        Undo::DevComplete     => (be.dpm_complete)(),
        Undo::ConsoleResume   => (be.console_resume)(),
        Undo::PlatformEnd     => platform::resume_end(t, state),
        Undo::ThawProcesses   => (be.thaw_processes)(),
    }
}

fn replay(undos: &[Undo], state: SuspendState, be: &SuspendBackend, t: Tables, c: &mut Cycle) {
    for u in undos { apply(*u, state, be, t, c); }
}

/// Record a failure against the step group that produced it.
fn record(step: Step) {
    if let Some(s) = sequence::stat_step(step) { STATS.save_failed_step(s); }
}

/// Whether the sleep ended, and any error the platform enter reported. An
/// enter error does not change the unwind — the machine is awake either way —
/// so it travels beside the outcome rather than as a failure.
struct Slept { woke: bool, enter_err: Option<Error> }

/// Steps 7-15 (or 7-11 plus the idle loop). Reaching the sleep unwinds this
/// frame's own half of the table; failing before it unwinds nothing and names
/// the step, leaving the whole unwind to the caller.
fn inner(state: SuspendState, be: &SuspendBackend, t: Tables,
         c: &mut Cycle) -> Result<Slept, (Step, Error)> {
    macro_rules! step { ($call:expr, $s:expr) => {
        if let Err(e) = $call { return Err(($s, e)); }
    }; }

    step!(platform::prepare(t, state), Step::PlatformPrepare);
    step!((be.dpm_suspend_late)(), Step::DevSuspendLate);
    step!(platform::prepare_late(t, state), Step::PlatformPrepareLate);
    step!((be.dpm_suspend_noirq)(), Step::DevSuspendNoirq);
    step!(platform::prepare_noirq(t, state), Step::PlatformPrepareNoirq);

    if state == SuspendState::ToIdle {
        (be.s2idle_loop)();
        let start = sequence::unwind_start(Step::S2idleLoop).unwrap_or(0);
        replay(&UNWIND_ORDER[start..INNER_UNWIND_END], state, be, t, c);
        return Ok(Slept { woke: true, enter_err: None });
    }

    step!((be.disable_secondary_cpus)(), Step::CpusOff);
    c.irq_state = (be.irqs_off)();

    // Core callbacks, then the last wakeup check before the machine stops
    // executing: an event arriving after this point has nothing left to abort,
    // so noticing it here is the difference between an aborted suspend and a
    // machine asleep with its wakeup already spent.
    let mut woke = false;
    let mut enter_err = None;
    match (be.syscore_suspend)() {
        // The core callbacks resumed the entries they had suspended; the
        // sequence still owes interrupts and the secondary CPUs.
        Err(e) => enter_err = Some(e),
        Ok(()) => {
            woke = (be.wakeup_pending)();
            if woke { enter_err = Some(Error::Busy); }
            else if let Err(e) = platform::enter(t, state) { enter_err = Some(e); }
            (be.syscore_resume)();
        }
    }
    (be.irqs_on)(c.irq_state);
    (be.enable_secondary_cpus)();
    let start = sequence::unwind_start(Step::PlatformPrepareNoirq).unwrap_or(0);
    replay(&UNWIND_ORDER[start..INNER_UNWIND_END], state, be, t, c);
    Ok(Slept { woke, enter_err })
}

/// Steps 0-6 plus the platform repeat loop and the outer unwind.
/// # C: O(N_devices + N_tasks)
/// # Sleeps: yes — the freezer and the device phases both block.
pub fn enter_state(state: SuspendState, be: &SuspendBackend, t: Tables) -> KResult<()> {
    let mut c = Cycle { irq_state: 0 };

    if state == SuspendState::ToIdle { super::s2idle::s2idle_begin(); }

    // Step 0: nothing above it has happened, so nothing unwinds.
    if tunables::sync_on_suspend() { (be.sync_filesystems)()?; }

    // Steps 1-2 unwind below this layer. Step 2 leaves userspace frozen,
    // because only this frame knows the pass order.
    if let Err(e) = (be.freeze_processes)() { record(Step::FreezeUser); return Err(e); }
    if let Err(e) = (be.freeze_kernel_threads)() {
        record(Step::FreezeKernelThreads);
        (be.thaw_processes)();
        return Err(e);
    }

    let outcome = devices_and_enter(state, be, t, &mut c);
    super::wakeup::SYSTEM.disarm();
    super::freezer::set_phase(super::freezer::FreezePhase::idle());
    outcome
}

fn devices_and_enter(state: SuspendState, be: &SuspendBackend, t: Tables,
                     c: &mut Cycle) -> KResult<()> {
    // Steps 3-6. Each failure unwinds the whole table suffix for its step.
    if let Err(e) = platform::begin(t, state) {
        replay(sequence::unwind_from(Step::PlatformBegin), state, be, t, c);
        return Err(e);
    }
    (be.console_suspend)();
    for (call, step) in [((be.dpm_prepare) as fn() -> KResult<()>, Step::DevPrepare),
                         ((be.dpm_suspend) as fn() -> KResult<()>, Step::DevSuspend)] {
        if let Err(e) = call() {
            record(step);
            if sequence::runs_platform_recover(step) { platform::recover(t, state); }
            replay(sequence::unwind_from(step), state, be, t, c);
            return Err(e);
        }
    }

    // Steps 7-15, repeated while the platform asks for another pass without
    // waking userspace.
    let mut enter_err;
    loop {
        match inner(state, be, t, c) {
            Err((step, e)) => {
                record(step);
                replay(sequence::unwind_from(step), state, be, t, c);
                return Err(e);
            }
            Ok(s) => {
                enter_err = s.enter_err;
                if enter_err.is_some() || s.woke || !platform::suspend_again(t, state) { break; }
            }
        }
    }

    // The outer half of a completed cycle runs whether or not the platform
    // enter reported an error: the machine is awake and the devices are down.
    replay(&UNWIND_ORDER[INNER_UNWIND_END..], state, be, t, c);
    match enter_err { Some(e) => Err(e), None => Ok(()) }
}

/// Enter `state`, doing the admission checks a `/sys/power/state` write does.
///
/// Refuses a second concurrent transition rather than queueing it: two
/// transitions racing would each unwind the other's steps.
/// # C: O(N_devices + N_tasks)
/// # Sleeps: yes
pub fn pm_suspend(state: SuspendState, be: &SuspendBackend, t: Tables) -> KResult<()> {
    if state == SuspendState::On { return Err(Error::Inval); }
    if state != SuspendState::ToIdle && !super::state::valid_state(t.suspend, state) {
        return Err(Error::Inval);
    }
    if !tunables::try_claim_transition() { return Err(Error::Busy); }
    let r = enter_state(state, be, t);
    tunables::release_transition();
    STATS.save_errno(match r { Ok(()) => 0, Err(e) => errno_of(e) });
    r
}

/// The negative errno a failure is recorded as. # C: O(1)
pub fn errno_of(e: Error) -> i32 {
    match e {
        Error::Inval => -22, Error::Perm => -1, Error::Io => -5, Error::Busy => -16,
        Error::Nosys => -38, Error::Again => -11, Error::Intr => -4,
        Error::Nomem => -12, Error::Nodata => -61,
    }
}

#[cfg(test)]
#[path = "run/tests.rs"]
mod tests;
