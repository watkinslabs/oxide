//! Generic write-side hibernation transaction and exact unwind.

use crate::decide::{Error, KResult};
use super::backend::{Backend, FinishMode, ResumeKind, Side};
use super::log::{self, Rollback};
use super::sequence::{self, Step, Undo};
use core::convert::Infallible;

const MAX_UNDOS: usize = 16;

struct Unwind {
    entries: [Option<Undo>; MAX_UNDOS],
    len: usize,
    irq_state: u64,
}

impl Unwind {
    fn new() -> Self { Self { entries: [None; MAX_UNDOS], len: 0, irq_state: 0 } }
    fn push(&mut self, undo: Undo) { self.entries[self.len] = Some(undo); self.len += 1; }
    fn pop<B: Backend>(&mut self, be: &mut B, kind: ResumeKind) -> KResult<()> {
        self.len -= 1;
        let action = self.entries[self.len].take().unwrap();
        log::undo(action, log::UndoBoundary::Begin);
        let result = match action {
            Undo::CpusOn => be.cpus_on(),
            Undo::LeaseRelease => { be.lease_release(); Ok(()) }
            Undo::ConsoleRestore => { be.console_restore(); Ok(()) }
            Undo::NotifyPost => { be.notify_post(); Ok(()) }
            Undo::FilesystemsThaw => { be.filesystems_thaw(); Ok(()) }
            Undo::UsersThaw => { be.users_thaw(); Ok(()) }
            Undo::HelpersEnable => { be.helpers_enable(); Ok(()) }
            Undo::HotplugUnlock => { be.hotplug_unlock(); Ok(()) }
            Undo::KernelThreadsThaw => { be.kernel_threads_thaw(); Ok(()) }
            Undo::SnapshotRelease => { be.snapshot_release(); Ok(()) }
            Undo::DevicesComplete => { be.devices_complete(kind); Ok(()) }
            Undo::DevicesResume => { be.devices_resume(kind); Ok(()) }
            Undo::DevicesResumeEarly => { be.devices_resume_early(kind); Ok(()) }
            Undo::DevicesResumeNoirq => { be.devices_resume_noirq(kind); Ok(()) }
            Undo::IrqsOn => { be.irqs_on(self.irq_state); Ok(()) }
            Undo::SyscoreResume => { be.syscore_resume(); Ok(()) }
        };
        log::undo(action, log::UndoBoundary::End);
        result
    }
    fn all<B: Backend>(&mut self, be: &mut B, kind: ResumeKind) -> KResult<()> {
        let mut first = Ok(());
        while self.len != 0 {
            if let Err(error) = self.pop(be, kind) { if first.is_ok() { first = Err(error); } }
        }
        first
    }
    fn through_devices<B: Backend>(&mut self, be: &mut B, kind: ResumeKind) -> KResult<()> {
        let mut first = Ok(());
        while self.len != 0 {
            let last = self.entries[self.len - 1];
            if let Err(error) = self.pop(be, kind) { if first.is_ok() { first = Err(error); } }
            if last == Some(Undo::DevicesComplete) { break; }
        }
        first
    }
}

macro_rules! forward {
    ($stack:expr, $backend:expr, $call:expr, $step:expr) => {{
        log::phase($step);
        match $call {
            Ok(()) => $stack.push(sequence::undo_for($step).unwrap()),
            Err(e) => { let _ = $stack.all($backend, ResumeKind::Thaw); return Err(e); }
        }
    }};
}

fn transaction<B: Backend>(claim: &crate::transition::Claim, be: &mut B) -> KResult<()> {
    let mut u = Unwind::new();
    forward!(u, be, be.lease_acquire(), Step::Lease);
    forward!(u, be, be.console_prepare(), Step::Console);
    forward!(u, be, be.notify_prepare(), Step::Notify);
    log::phase(Step::Sync);
    if let Err(e) = be.sync_filesystems() { let _ = u.all(be, ResumeKind::Thaw); return Err(e); }
    forward!(u, be, be.filesystems_freeze(), Step::Filesystems);
    forward!(u, be, be.users_freeze(), Step::Users);
    forward!(u, be, be.helpers_disable(), Step::Helpers);
    forward!(u, be, be.hotplug_lock(), Step::Hotplug);
    forward!(u, be, be.kernel_threads_freeze(), Step::KernelThreads);
    forward!(u, be, be.snapshot_prepare(), Step::Snapshot);
    forward!(u, be, be.devices_prepare(), Step::DevicesPrepare);
    forward!(u, be, be.devices_freeze(), Step::DevicesFreeze);
    forward!(u, be, be.devices_late(), Step::DevicesLate);
    forward!(u, be, be.devices_noirq(), Step::DevicesNoirq);
    forward!(u, be, be.cpus_off(), Step::Cpus);
    log::phase(Step::Irqs); u.irq_state = be.irqs_off();
    u.push(sequence::undo_for(Step::Irqs).unwrap());
    forward!(u, be, be.syscore_suspend(), Step::Syscore);

    log::phase(Step::ArchSnapshot);
    let side = match be.arch_snapshot_and_copy() {
        Ok(side) => side,
        Err(e) => { let _ = u.all(be, ResumeKind::Thaw); return Err(e); }
    };
    let kind = if side == Side::Restored { ResumeKind::Restore } else { ResumeKind::Thaw };
    let cpu_restart = u.through_devices(be, kind);
    if side == Side::Restored {
        let outer = u.all(be, ResumeKind::Restore);
        cpu_restart.and(outer)?;
        log::image_resumed();
        return Ok(());
    }
    if let Err(error) = cpu_restart {
        let _ = u.all(be, ResumeKind::Thaw);
        return Err(error);
    }

    log::phase(Step::Serialize);
    if let Err(e) = be.serialize_image() {
        log::rollback(Step::Serialize, Rollback::NotPublished);
        let _ = u.all(be, ResumeKind::Thaw); return Err(e);
    }
    log::phase(Step::Commit);
    if let Err(e) = be.commit_marker() {
        // PREFLUSH|FUA failure does not prove the marker stayed invisible: a
        // device may complete the media write and report a later flush/status
        // error. Re-establish the durable swap signature before thawing; if
        // that proof fails, continuing with a live image is forbidden.
        if be.unmark_image().is_err() {
            log::rollback(Step::Commit, Rollback::UnmarkFailed);
            be.halt_with_live_image();
        }
        log::rollback(Step::Commit, Rollback::Unmarked);
        let _ = u.all(be, ResumeKind::Thaw); return Err(e);
    }
    log::image_created();
    match be.finish_mode() {
        FinishMode::Suspend => {
            if be.suspend_with_image().is_ok() {
                if be.unmark_image().is_err() { be.halt_with_live_image(); }
                let _ = u.all(be, ResumeKind::Thaw);
                return Ok(());
            }
        }
        FinishMode::TestResume => {
            if let Err(error) = be.prepare_test_resume() {
                let _ = u.all(be, ResumeKind::Thaw);
                return Err(error);
            }
            let result = restore_devices_transaction(be);
            let _ = u.all(be, ResumeKind::Thaw);
            return result;
        }
        FinishMode::PowerDown => {}
    }
    log::phase(Step::DevicesPoweroff);
    if let Err(e) = be.devices_poweroff() {
        if be.unmark_image().is_err() {
            log::rollback(Step::DevicesPoweroff, Rollback::UnmarkFailed);
            be.halt_with_live_image();
        }
        log::rollback(Step::DevicesPoweroff, Rollback::Unmarked);
        let _ = u.all(be, ResumeKind::Thaw);
        return Err(e);
    }
    log::phase(Step::Terminal);
    match be.terminal(claim) {
        Ok(never) => match never {},
        Err(e) => {
            if be.unmark_image().is_err() {
                log::rollback(Step::Terminal, Rollback::UnmarkFailed);
                be.halt_with_live_image();
            }
            log::rollback(Step::Terminal, Rollback::Unmarked);
            let _ = u.all(be, ResumeKind::Thaw);
            Err(e)
        }
    }
}

fn restore_devices_transaction<B: Backend>(be: &mut B) -> KResult<()> {
    let mut u = Unwind::new();
    macro_rules! step {
        ($call:expr, $phase:expr) => { if let Err(error) = $call {
            let _ = u.all(be, ResumeKind::Thaw); return Err(error);
        } else { u.push(sequence::undo_for($phase).unwrap()); } };
    }
    step!(be.devices_prepare(), Step::DevicesPrepare);
    step!(be.devices_freeze(), Step::DevicesFreeze);
    step!(be.devices_late(), Step::DevicesLate);
    step!(be.devices_noirq(), Step::DevicesNoirq);
    step!(be.cpus_off(), Step::Cpus);
    u.irq_state = be.irqs_off();
    u.push(sequence::undo_for(Step::Irqs).unwrap());
    step!(be.syscore_suspend(), Step::Syscore);
    match be.enter_test_resume() {
        Ok(never) => match never {},
        Err(error) => { let _ = u.all(be, ResumeKind::Thaw); Err(error) }
    }
}

fn restore_transaction<B, F>(be: &mut B, terminal: F) -> KResult<()>
where B: Backend, F: FnOnce() -> KResult<Infallible>
{
    let mut u = Unwind::new();
    macro_rules! restore_forward {
        ($call:expr, $step:expr) => {{
            match $call {
                Ok(()) => u.push(sequence::undo_for($step).unwrap()),
                Err(error) => { let _ = u.all(be, ResumeKind::Thaw); return Err(error); }
            }
        }};
    }
    restore_forward!(be.console_prepare(), Step::Console);
    restore_forward!(be.notify_prepare(), Step::Notify);
    restore_forward!(be.filesystems_freeze(), Step::Filesystems);
    restore_forward!(be.users_freeze(), Step::Users);
    restore_forward!(be.helpers_disable(), Step::Helpers);
    restore_forward!(be.hotplug_lock(), Step::Hotplug);
    restore_forward!(be.kernel_threads_freeze(), Step::KernelThreads);
    restore_forward!(be.devices_prepare(), Step::DevicesPrepare);
    restore_forward!(be.devices_freeze(), Step::DevicesFreeze);
    restore_forward!(be.devices_late(), Step::DevicesLate);
    restore_forward!(be.devices_noirq(), Step::DevicesNoirq);
    restore_forward!(be.cpus_off(), Step::Cpus);
    u.irq_state = be.irqs_off();
    u.push(sequence::undo_for(Step::Irqs).unwrap());
    restore_forward!(be.syscore_suspend(), Step::Syscore);
    match terminal() {
        Ok(never) => match never {},
        Err(error) => { let _ = u.all(be, ResumeKind::Thaw); Err(error) }
    }
}

/// Run one write-side transaction under the single shared transition claim.
/// # C: O(tasks + devices + populated saveable PFNs)
/// # Ctx: process context
/// # Sleeps: yes
pub fn hibernate<B: Backend>(be: &mut B) -> KResult<()> {
    let claim = crate::transition::try_claim().ok_or(Error::Busy)?;
    hibernate_claimed(&claim, be)
}

/// Run a write transaction whose caller already owns transition admission.
/// This entry lets a production adapter snapshot mutable policy only after
/// admission without recursively acquiring the system transition.
/// # C: O(tasks + devices + populated saveable PFNs)
/// # Ctx: process context
/// # Sleeps: yes
pub fn hibernate_claimed<B: Backend>(claim: &crate::transition::Claim,
                                     be: &mut B) -> KResult<()> {
    transaction(claim, be)
}

/// Quiesce a fresh kernel around one already-loaded terminal restore attempt.
/// The caller's claim proves loading and quiescing are one transition; it is
/// borrowed so this function cannot create a second transition owner.
/// # C: O(tasks + devices)
/// # Ctx: process context
/// # Sleeps: yes until the terminal callback
pub fn restore_loaded<B, F>(_claim: &crate::transition::Claim, be: &mut B,
                            terminal: F) -> KResult<()>
where B: Backend, F: FnOnce() -> KResult<Infallible>
{
    restore_transaction(be, terminal)
}

#[cfg(test)]
#[path = "run/tests.rs"]
mod tests;
