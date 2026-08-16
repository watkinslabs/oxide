// The suspend sequence and its unwind, per `32a§5`.
//
// This module is a table, deliberately: the order is the contract, and a
// contract expressed as control flow spread over a driver cannot be checked.
// [`unwind_from`] answers "a failure here undoes exactly what" for every step,
// and `run.rs` is obliged to obey it.
//
// Two properties the table encodes that are easy to get wrong:
//
//   * Steps 1 and 2 unwind *below* this layer. The freezer thaws what it froze
//     before reporting failure, so the sequence adds nothing.
//   * A failing platform hook still runs its own undo (steps 7 and 11), while a
//     failing device phase does not (steps 6, 8, 10) — the device layer has
//     already resumed whatever it suspended. Treating these alike either
//     double-resumes devices or leaves a platform hook half-applied.

use super::state::SuspendState;

/// Forward steps, in order. Discriminants are the `32a§5` numbering.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Step {
    Sync = 0,
    FreezeUser = 1,
    FreezeKernelThreads = 2,
    PlatformBegin = 3,
    ConsoleSuspend = 4,
    DevPrepare = 5,
    DevSuspend = 6,
    PlatformPrepare = 7,
    DevSuspendLate = 8,
    PlatformPrepareLate = 9,
    DevSuspendNoirq = 10,
    PlatformPrepareNoirq = 11,
    CpusOff = 12,
    IrqsOff = 13,
    SyscoreSuspend = 14,
    PlatformEnter = 15,
    /// Replaces steps 12-15 for `freeze`.
    S2idleLoop = 16,
}

/// Undo actions, in the order a complete cycle runs them.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Undo {
    SyscoreResume = 0,
    IrqsOn = 1,
    CpusOn = 2,
    /// Platform `wake` for a deep state, s2idle `restore_early` for `freeze`.
    PlatformWake = 3,
    DevResumeNoirq = 4,
    /// s2idle `restore`; deep states have no hook here.
    PlatformRestore = 5,
    DevResumeEarly = 6,
    /// Platform `finish`.
    PlatformFinish = 7,
    DevResume = 8,
    DevComplete = 9,
    ConsoleResume = 10,
    /// Platform `end`.
    PlatformEnd = 11,
    /// Thaws every frozen task, kernel threads included. The kernel-thread
    /// pass's own failure thaws them below this layer, so one entry suffices.
    ThawProcesses = 12,
}

/// The complete unwind, in execution order.
pub const UNWIND_ORDER: [Undo; 13] = [
    Undo::SyscoreResume, Undo::IrqsOn, Undo::CpusOn, Undo::PlatformWake,
    Undo::DevResumeNoirq, Undo::PlatformRestore, Undo::DevResumeEarly, Undo::PlatformFinish,
    Undo::DevResume, Undo::DevComplete, Undo::ConsoleResume, Undo::PlatformEnd,
    Undo::ThawProcesses,
];

/// Forward steps for a deep state (`standby`, `mem`).
pub const DEEP_STEPS: [Step; 16] = [
    Step::Sync, Step::FreezeUser, Step::FreezeKernelThreads, Step::PlatformBegin,
    Step::ConsoleSuspend, Step::DevPrepare, Step::DevSuspend, Step::PlatformPrepare,
    Step::DevSuspendLate, Step::PlatformPrepareLate, Step::DevSuspendNoirq,
    Step::PlatformPrepareNoirq, Step::CpusOff, Step::IrqsOff, Step::SyscoreSuspend,
    Step::PlatformEnter,
];

/// Forward steps for `freeze`: the same prefix, then the idle loop.
pub const IDLE_STEPS: [Step; 13] = [
    Step::Sync, Step::FreezeUser, Step::FreezeKernelThreads, Step::PlatformBegin,
    Step::ConsoleSuspend, Step::DevPrepare, Step::DevSuspend, Step::PlatformPrepare,
    Step::DevSuspendLate, Step::PlatformPrepareLate, Step::DevSuspendNoirq,
    Step::PlatformPrepareNoirq, Step::S2idleLoop,
];

/// The forward step list for `state`. # C: O(1)
pub fn forward_steps(state: SuspendState) -> &'static [Step] {
    if state == SuspendState::ToIdle { &IDLE_STEPS } else { &DEEP_STEPS }
}

/// Index into [`UNWIND_ORDER`] at which the unwind starts when `step` fails, or
/// `None` when the failure unwinds entirely below this layer.
///
/// A completed cycle unwinds from index 0; `freeze`'s loop and the deep
/// states' platform enter both land there via their own step.
/// # C: O(1)
pub fn unwind_start(step: Step) -> Option<usize> {
    Some(match step {
        // The sync ran or it did not; nothing above it has happened.
        Step::Sync => return None,
        // The freezer thaws what it froze before reporting failure.
        Step::FreezeUser | Step::FreezeKernelThreads => return None,
        Step::PlatformBegin => 11,
        // Cannot fail; listed so the table is total.
        Step::ConsoleSuspend => 10,
        // The device core resumes its own partial state; the sequence closes
        // the transition around it.
        Step::DevPrepare | Step::DevSuspend => 8,
        // A platform hook runs its own undo: `prepare` pairs with `finish`
        // whether or not `prepare` got all the way through.
        Step::PlatformPrepare => 7,
        Step::DevSuspendLate => 7,
        Step::PlatformPrepareLate => 6,
        Step::DevSuspendNoirq => 5,
        Step::PlatformPrepareNoirq => 3,
        Step::S2idleLoop => 3,
        Step::CpusOff => 2,
        Step::IrqsOff => 1,
        Step::SyscoreSuspend => 1,
        Step::PlatformEnter => 0,
    })
}

/// Whether the platform's recover hook runs before the unwind. Only the device
/// suspend phase reaches it: the platform has begun, so it is told the attempt
/// collapsed before anything deeper happened.
/// # C: O(1)
pub fn runs_platform_recover(step: Step) -> bool {
    matches!(step, Step::DevPrepare | Step::DevSuspend)
}

/// The unwind for a failure at `step`, as a slice of [`UNWIND_ORDER`].
/// # C: O(1)
pub fn unwind_from(step: Step) -> &'static [Undo] {
    match unwind_start(step) { None => &[], Some(i) => &UNWIND_ORDER[i..] }
}

/// The step whose failure a given undo index answers, used to state the pairing
/// in one place: `undo_pairs_with(u)` is the forward step `u` reverses, or
/// `None` for the undos that pair with a step that cannot fail.
/// # C: O(1)
pub fn undo_pairs_with(u: Undo) -> Option<Step> {
    Some(match u {
        Undo::SyscoreResume     => Step::SyscoreSuspend,
        Undo::IrqsOn            => Step::IrqsOff,
        Undo::CpusOn            => Step::CpusOff,
        Undo::PlatformWake      => Step::PlatformPrepareNoirq,
        Undo::DevResumeNoirq    => Step::DevSuspendNoirq,
        Undo::PlatformRestore   => Step::PlatformPrepareLate,
        Undo::DevResumeEarly    => Step::DevSuspendLate,
        Undo::PlatformFinish    => Step::PlatformPrepare,
        Undo::DevResume         => Step::DevSuspend,
        Undo::DevComplete       => Step::DevPrepare,
        Undo::ConsoleResume     => Step::ConsoleSuspend,
        Undo::PlatformEnd       => Step::PlatformBegin,
        Undo::ThawProcesses     => Step::FreezeUser,
    })
}

/// The statistics step a failure at `step` is recorded against (`32a§11`).
/// # C: O(1)
pub fn stat_step(step: Step) -> Option<super::stats::StatStep> {
    use super::stats::StatStep;
    Some(match step {
        Step::FreezeUser | Step::FreezeKernelThreads => StatStep::Freeze,
        Step::DevPrepare        => StatStep::Prepare,
        Step::DevSuspend        => StatStep::Suspend,
        Step::DevSuspendLate    => StatStep::SuspendLate,
        Step::DevSuspendNoirq   => StatStep::SuspendNoirq,
        _ => return None,
    })
}

#[cfg(test)]
#[path = "sequence/tests.rs"]
mod tests;
