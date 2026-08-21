//! Cold-boot resume admission and terminal orchestration.

use power::hibernate::{identity, image, log, restore, run, settings};
use power::Error;

use super::{enter_arch_restore, prepare_arch_restore, validate_arch_header, MachineBackend,
    RestoreMemory, ResumeStorage};

/// Nonterminal result allowing the fresh boot to continue safely.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResumeOutcome {
    Skipped,
    NoImage,
    Rejected(Error),
}

/// Consume, admit and load the configured image, then enter terminal restore.
/// A return always means the fresh kernel remains usable; successful restore
/// transfers to the saved continuation and cannot return here.
/// # C: O(image pages + tasks + devices)
/// # Ctx: boot process context after resume block target discovery
/// # Sleeps: yes until terminal restore
pub fn software_resume() -> ResumeOutcome {
    if !super::backend::restore_path_available() { return ResumeOutcome::Skipped; }
    match attempt() {
        Ok(()) => ResumeOutcome::Skipped,
        Err(AttemptError::NoImage) => ResumeOutcome::NoImage,
        Err(AttemptError::Rejected(error)) => ResumeOutcome::Rejected(error),
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum AttemptError { NoImage, Rejected(Error) }

fn attempt() -> Result<(), AttemptError> {
    let claim = power::transition::try_claim()
        .ok_or_else(|| reject(log::Invariant::Policy, false, Error::Busy))?;
    let settings = settings::get().ok_or_else(|| reject(log::Invariant::Policy, false, Error::Nodata))?;
    let target = match settings.resume_target() {
        Some(target) => target,
        None => return Ok(()),
    };
    log::resume_phase(log::ResumePath::Cold, log::ResumePhase::Target);
    log::target(&target.name, target.offset, "resume");
    if !settings.hibernate_enabled() { return Err(reject(log::Invariant::Policy, false, Error::Perm)); }
    let mut storage = ResumeStorage::claim(&target.name)
        .map_err(|error| reject(log::Invariant::Target, false, map_block(error)))?;
    log::resume_phase(log::ResumePath::Cold, log::ResumePhase::Marker);
    let reader = match image::ImageReader::open_report(&mut storage, target.offset) {
        Ok(reader) => reader,
        Err(failure) if failure.error == image::Error::NoImage => return Err(AttemptError::NoImage),
        Err(failure) => return Err(reject(log::Invariant::Format, failure.marker_consumed,
            super::backend::map_image(failure.error))),
    };
    let arch_data = reader.header.arch_data;
    let stream_pages = reader.header.stream_pages;
    let expected = identity::current();
    log::compatibility(&reader.header, &expected, false);
    log::resume_phase(log::ResumePath::Cold, log::ResumePhase::Admit);
    restore::validate_compatibility(&reader.header, &expected)
        .map_err(|error| reject(log::Invariant::Compatibility, true, error))?;
    validate_arch_header(&arch_data)
        .map_err(|error| reject(log::Invariant::Architecture, true, error))?;
    let admission = restore::admit(&reader, &expected, validate_arch_header)
        .map_err(|error| reject(log::Invariant::Architecture, true, error))?;
    log::resume_phase(log::ResumePath::Cold, log::ResumePhase::Load);
    let mut memory = RestoreMemory::capture()
        .map_err(|error| reject(log::Invariant::Memory, true, error))?;
    let image = restore::load(admission, &mut storage, &mut memory)
        .map_err(|error| reject(log::Invariant::Checksum, true, error))?;
    let collision = image.collision_count() as u64;
    let total = image.copied().len() as u64 + image.zero().len() as u64;
    log::counts(total, stream_pages, total.saturating_sub(collision), collision);
    log::resume_phase(log::ResumePath::Cold, log::ResumePhase::SafePlan);
    let safe = restore::prepare_safe(image, &mut memory, 0)
        .map_err(|error| reject(log::Invariant::Memory, true, error))?;
    let prepared = prepare_arch_restore(safe, memory, &arch_data)
        .map_err(|error| reject(log::Invariant::Architecture, true, error))?;
    let mut backend = MachineBackend::new()
        .map_err(|error| reject(log::Invariant::Restore, true, error))?;
    log::resume_phase(log::ResumePath::Cold, log::ResumePhase::Quiesce);
    run::restore_loaded(&claim, &mut backend, || {
        log::resume_phase(log::ResumePath::Cold, log::ResumePhase::Terminal);
        // SAFETY: restore_loaded has completed the one-CPU, IRQ-off terminal
        // sequence while claim retains exclusive system-transition ownership.
        unsafe { enter_arch_restore(prepared) }
    }).map_err(|error| reject(log::Invariant::Restore, true, error))
}

fn reject(invariant: log::Invariant, consumed: bool, error: Error) -> AttemptError {
    log::rejected(invariant, consumed);
    AttemptError::Rejected(error)
}

fn map_block(error: block::BlockError) -> Error {
    match error {
        block::BlockError::Ebusy => Error::Busy,
        block::BlockError::Einval => Error::Inval,
        block::BlockError::Enomem => Error::Nomem,
        block::BlockError::Eagain => Error::Again,
        block::BlockError::Eopnotsupp => Error::Opnotsupp,
        block::BlockError::Enxio => Error::Nodata,
        block::BlockError::Eio | block::BlockError::Enospc |
        block::BlockError::Erofs | block::BlockError::Eoverflow |
        block::BlockError::Etoomanyrefs => Error::Io,
    }
}
