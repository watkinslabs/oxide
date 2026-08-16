// The ACPI platform sleep operations table per `32a§4` and `32a§9`.
//
// Module manifest:
// - `admit`: which states this machine may enter, as a pure function of what
//            firmware published.
// - `plan`:  the ordered register writes one sleep entry performs.
// - `io`:    performing them, and publishing the resume address.
// - `enter`: the platform enter, both the shallow and the deep shape.
//
// The table itself is here because it is the seam: a static of function
// pointers, installed once, that the sequence in `run` walks. Nothing in it
// holds state — the resume vector is the one boot-time fact this file owns,
// because it is the answer to "can a deep sleep be admitted at all".

pub mod admit;
pub mod plan;
pub mod io;
pub mod enter;

use core::sync::atomic::{AtomicU64, Ordering};

use firmware::acpi::{SleepState as AcpiState, sleep_action};

use crate::decide::KResult;
use super::ops::PlatformSuspendOps;
use super::state::SuspendState;
use admit::PlatformFacts;

/// Physical address published in the firmware waking vector, plus one so
/// that zero means "none": a resume vector of zero is what an unarmed FACS
/// holds, and publishing it would resume the machine into whatever occupies
/// the first page.
static RESUME_VECTOR: AtomicU64 = AtomicU64::new(0);

/// The resume address, if the arch layer could place its stub. # C: O(1)
pub fn resume_vector() -> Option<u64> {
    match RESUME_VECTOR.load(Ordering::Acquire) { 0 => None, v => Some(v - 1) }
}

fn set_resume_vector(pa: u64) { RESUME_VECTOR.store(pa + 1, Ordering::Release); }

/// What firmware and the arch layer supplied on this machine. # C: O(1)
pub fn platform_facts() -> PlatformFacts {
    PlatformFacts {
        s1_action: sleep_action(AcpiState::S1).is_some(),
        s3_action: sleep_action(AcpiState::S3).is_some(),
        resume_vector: resume_vector().is_some(),
        // The processor-context record is unconditional on this arch: the
        // save is compiled in, so a machine that has a resume vector also
        // has somewhere to come back to.
        state_save: true,
    }
}

fn valid(state: SuspendState) -> bool { admit::admits(platform_facts(), state) }

fn begin(_state: SuspendState) -> KResult<()> { Ok(()) }

fn prepare() -> KResult<()> { Ok(()) }

fn prepare_late() -> KResult<()> { Ok(()) }

fn wake() {}

fn finish() {}

fn end() {}

/// The one ACPI platform sleep table. Installed by [`init`].
pub static ACPI_SUSPEND_OPS: PlatformSuspendOps = PlatformSuspendOps {
    valid: Some(valid),
    begin: Some(begin),
    prepare: Some(prepare),
    prepare_late: Some(prepare_late),
    enter: Some(enter::enter),
    wake: Some(wake),
    finish: Some(finish),
    // The platform never asks for the enter to be repeated: ACPI has no
    // equivalent of the "sleep again without waking userspace" hook, and
    // claiming it would loop a wake that userspace asked to see.
    suspend_again: None,
    end: Some(end),
    // Nothing to unwind: the sleep registers are untouched until `enter`, so
    // a device-suspend failure before it leaves the platform as it was.
    recover: None,
};

/// Place the resume stub, then install the table.
///
/// Called once from the boot path after the ACPI table walk and the AML
/// namespace construction — `_S1` and `_S3` do not exist before then, and a
/// table installed earlier would answer `/sys/power/state` with "no platform
/// sleep" on a machine that has one.
///
/// # SAFETY: boot path, single-CPU, after the ACPI walk. Places the resume
/// stub in the boot-reserved low page and adds one kernel identity mapping.
/// # C: O(1)
/// # Ctx: pre-init, single-CPU
pub unsafe fn init() {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        // SAFETY: per fn contract — boot path, single-CPU, and the stub's
        // page is only written when the boot path declared it reserved.
        if let Some(pa) = unsafe { hal_x86_64::suspend::install_wakeup_trampoline() } { set_resume_vector(pa); }
    }
    super::ops::suspend_set_ops(&ACPI_SUSPEND_OPS);
}

#[cfg(test)]
#[path = "acpi_sleep/tests/ops.rs"]
mod tests;
