//! Suspend, resume, and the table swap between them — as an ordered plan.
//!
//! This is the part of device-mapper that is easy to get subtly wrong and
//! impossible to notice: a table replaced while I/O is still in flight sends
//! the tail of a write to whichever device the OLD table named and the head to
//! the new one, and reports success. So the ordering is not left implicit in
//! the code that performs it. Each entry point returns the exact sequence of
//! steps, the caller executes that sequence and nothing else, and the sequence
//! is what the tests assert against.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::target::DmResult;

bitflags::bitflags! {
    /// Live state of one mapped device.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct DmFlags: u32 {
        /// New submissions are deferred rather than mapped.
        const BLOCK_IO_FOR_SUSPEND = 1 << 0;
        /// A caller suspended this device.
        const SUSPENDED            = 1 << 1;
        /// A filesystem on this device is frozen for the suspend.
        const FROZEN               = 1 << 2;
        /// The device is being torn down; no new reference may be taken.
        const FREEING              = 1 << 3;
        /// A removal has been requested.
        const DELETING             = 1 << 4;
        /// The suspend in progress fails deferred I/O instead of flushing it.
        const NOFLUSH_SUSPENDING   = 1 << 5;
        /// Remove the device once its last opener closes.
        const DEFERRED_REMOVE      = 1 << 6;
        /// The kernel, not a caller, suspended this device.
        const SUSPENDED_INTERNALLY = 1 << 7;
        /// The post-suspend hooks are running.
        const POST_SUSPENDING      = 1 << 8;
    }
}

/// One action in a suspend or resume plan. The order of the sequence is the
/// contract; a step's own effect is the caller's to perform.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Step {
    /// Record that this suspend fails deferred I/O rather than flushing it.
    /// Must precede `Presuspend`: a target asks whether the suspend is a
    /// no-flush one while its pre-suspend hook runs.
    SetNoflushSuspending,
    /// Run the live table's pre-suspend hooks, with I/O still admitted.
    Presuspend,
    /// Freeze any filesystem mounted on the device.
    FreezeFs,
    /// Stop admitting new I/O; later submissions are deferred.
    BlockIo,
    /// Wait until every I/O already handed to a target has completed.
    WaitForCompletion,
    /// Mark the device suspended.
    SetSuspended,
    /// Run the live table's post-suspend hooks, device now quiesced.
    PostSuspend,
    /// Ask the incoming table's targets whether the resume may proceed.
    Preresume,
    /// Install the inactive table as the live one. Legal only while the
    /// device is quiesced, which is why it never appears before
    /// `WaitForCompletion` in any plan this module produces.
    SwapTable,
    /// Run the live table's resume hooks.
    ResumeTargets,
    /// Re-admit I/O and re-submit whatever was deferred.
    FlushDeferred,
    /// Thaw a frozen filesystem.
    ThawFs,
    /// Clear the suspended mark.
    ClearSuspended,
    /// Undo the pre-suspend hooks after an abandoned suspend.
    PresuspendUndo,
}

/// Plan a caller-requested suspend.
///
/// `lockfs` and `noflush` come from the request; `has_map` says whether a live
/// table exists. A device with no table is not frozen, because there is
/// nothing mounted on a device that maps nothing and the freeze would deadlock
/// against the caller that is holding the mount.
/// # C: O(1)
pub fn plan_suspend(flags: DmFlags, lockfs: bool, noflush: bool, has_map: bool) -> DmResult<Vec<Step>> {
    if flags.contains(DmFlags::SUSPENDED) { return Err(Errno::Einval); }
    let mut steps = Vec::new();
    if noflush { steps.push(Step::SetNoflushSuspending); }
    steps.push(Step::Presuspend);
    // A no-flush suspend outranks a freeze request: freezing flushes and waits,
    // which is exactly what the caller asked not to happen.
    if !noflush && lockfs && has_map { steps.push(Step::FreezeFs); }
    steps.push(Step::BlockIo);
    if has_map { steps.push(Step::WaitForCompletion); }
    steps.push(Step::SetSuspended);
    steps.push(Step::PostSuspend);
    Ok(steps)
}

/// Plan the recovery from a suspend that could not complete — a freeze that
/// failed, or a wait that was interrupted. # C: O(1)
pub fn plan_suspend_abort(froze: bool) -> Vec<Step> {
    let mut steps = alloc::vec![Step::FlushDeferred];
    if froze { steps.push(Step::ThawFs); }
    steps.push(Step::PresuspendUndo);
    steps
}

/// Plan a caller-requested resume, which is also how a loaded table becomes
/// live.
///
/// `has_new_table` says whether the inactive slot is filled. The order below
/// is the whole point of this module: when a table is waiting, the device is
/// suspended FIRST if it is not already, and only then is the table swapped.
/// Swapping into a running device would let one submission be mapped by two
/// different tables.
/// # C: O(1)
pub fn plan_resume(flags: DmFlags, has_new_table: bool, lockfs: bool, noflush: bool,
                   has_map: bool, new_table_size: u64) -> DmResult<Vec<Step>> {
    let mut steps = Vec::new();
    let mut suspended = flags.contains(DmFlags::SUSPENDED);

    if has_new_table {
        if !suspended {
            steps.extend(plan_suspend(flags, lockfs, noflush, has_map)?);
            suspended = true;
        }
        steps.push(Step::Preresume);
        steps.push(Step::SwapTable);
    }

    if suspended {
        // Resuming onto no table, or onto a zero-length one, leaves a device
        // that would admit I/O it cannot place. The reference refuses it and
        // the device stays suspended.
        let live_size = if has_new_table { new_table_size } else if has_map { u64::MAX } else { 0 };
        if live_size == 0 { return Err(Errno::Einval); }
        if !has_new_table { steps.push(Step::Preresume); }
        steps.push(Step::ResumeTargets);
        steps.push(Step::FlushDeferred);
        steps.push(Step::ThawFs);
        steps.push(Step::ClearSuspended);
    }
    Ok(steps)
}

/// Whether a plan swaps the table only after the device has been quiesced.
/// A plan that fails this would corrupt data under load, so it is checked
/// rather than assumed. # C: O(N_steps)
pub fn swap_is_quiesced(steps: &[Step]) -> bool {
    let Some(swap) = steps.iter().position(|s| *s == Step::SwapTable) else { return true };
    let blocked = steps.iter().position(|s| *s == Step::BlockIo);
    let waited = steps.iter().position(|s| *s == Step::WaitForCompletion);
    let suspended = steps.iter().position(|s| *s == Step::SetSuspended);
    match (blocked, waited, suspended) {
        // The suspend happens in this plan: every quiescing step precedes it.
        (Some(b), Some(w), Some(s)) => b < swap && w < swap && s < swap,
        // The device was already suspended before the plan started, so the
        // plan contains no suspend steps at all — but then it must contain no
        // resume-side re-admission before the swap either.
        (None, None, None) => steps.iter().position(|s| *s == Step::FlushDeferred).is_none_or(|f| f > swap),
        _ => false,
    }
}
