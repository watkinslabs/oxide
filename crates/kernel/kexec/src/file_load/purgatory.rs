// The purgatory: the stage the relocated image starts in, which verifies that
// relocation actually delivered the bytes before it lets the new kernel run.
//
// WHY IT EXISTS. `kexec_file_load` builds the segment list, and the copy that
// realises it runs after the machine has stopped being able to report anything.
// A page that landed at the wrong address, a source page overwritten before it
// was copied, a segment that collided with the relocation list — every one of
// those produces a new kernel that starts from rubble, silently. The purgatory
// re-hashes every segment AT ITS DESTINATION and halts forever on a mismatch,
// so the failure is a stopped machine rather than an arbitrary crash inside a
// kernel that thinks it booted.
//
// x86_64 ONLY, and that is the reference's shape, not a gap here: the option
// that builds a purgatory is selected by x86, powerpc, s390 and riscv, and NOT
// by arm64, whose file-mode kexec starts the new kernel directly. The digest
// step is likewise skipped wherever that option is unset, so an arm64 image
// carries no `sha_regions` and no digest at all.
//
// Module manifest:
// - `layout`: ungated — where inside the blob the three patched objects live,
//             and the writes that patch them.
// - `digest`: ungated — the SHA-256 the kernel predicts and the region table
//             the purgatory recomputes it from.
// - `blob`:   x86_64 — the assembled purgatory, and hosted tests that call its
//             own SHA-256.

pub mod layout;
pub mod digest;

#[cfg(target_arch = "x86_64")]
pub mod blob;

use crate::validate::KResult;

/// The purgatory bytes this architecture starts a relocated image in.
///
/// `ENOSYS` where the architecture has none, which is the answer a loader on
/// such an architecture must never need — it is expected to place no purgatory
/// segment at all.
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub fn image() -> KResult<&'static [u8]> { Ok(blob::bytes()) }

/// See the x86_64 arm.
/// # C: O(1)
#[cfg(not(target_arch = "x86_64"))]
pub fn image() -> KResult<&'static [u8]> { Err(crate::validate::Error::NoSys) }

/// Re-exported so a loader names one path for the whole verification step.
pub use digest::calculate;
pub use layout::{patch_digest, patch_entry_regs, patch_sha_regions, EntryRegs, ShaRegion,
    BLOB_LEN, OFF_CODE, OFF_NEW_STACK_END};
