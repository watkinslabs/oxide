// The aarch64 `Image` loader.
//
// THERE IS NO PURGATORY ON THIS ARCHITECTURE. The other architecture's file
// load stages a verification stub that runs first, checks a digest over the
// segments and only then enters the kernel; arm64's `kexec_file_load` enters
// the loaded kernel DIRECTLY. The reference says so in as many words in its
// machine-kexec path: in the kexec_file case the kernel starts without
// purgatory, because the two things a purgatory exists to carry here — the
// entry point and the device-tree address — are passed in registers by the
// relocation trampoline instead (`machine::arm`, x1 and x2). Nothing in this
// module builds, places or digests one, and that is not an omission.
//
// Module manifest:
// - `header`:   the 64-byte `Image` header, its magic and its feature flags.
// - `caps`:     what the running PE implements, decoded from its feature reg.
// - `place`:    the placement loop — kernel bottom-up, then everything above
//               it, retried at a higher floor when the rest does not fit.
// - `fdt`:      a flattened device tree, decoded and re-flattened.
// - `handover`: `/chosen` as the new kernel must find it.
// - `assemble`: the two-pass load that ties the four together.

extern crate alloc;
use alloc::vec::Vec;

use crate::file_load::{FileLoader, LoadCtx, Loaded};
use crate::validate::KResult;

pub mod assemble;
pub mod caps;
pub mod fdt;
pub mod handover;
pub mod header;
pub mod place;

/// aarch64 `Image` loader.
pub struct Arm64Image;

impl FileLoader for Arm64Image {
    /// # C: O(1)
    fn probe(&self, kernel: &[u8]) -> KResult<()> { header::probe(kernel) }
    /// # C: O(file size + tree size)
    fn load(&self, ctx: &LoadCtx) -> KResult<Loaded> { assemble::load(ctx) }
}

/// The running kernel's flattened device tree, or empty on a machine that
/// retained none — where `load` then refuses with EINVAL, exactly where the
/// reference refuses when it cannot build a tree.
///
/// The blob is the one the boot handoff published and the one
/// `/sys/firmware/fdt` serves, so the tree a caller inspects before loading
/// and the tree the load derives from are the same bytes rather than two
/// answers that can disagree.
/// # C: O(fdt size)
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub fn running_fdt() -> Vec<u8> {
    match firmware::fdt::blob() { Some(b) => b.to_vec(), None => Vec::new() }
}
/// # C: O(1)
#[cfg(not(all(target_os = "oxide-kernel", target_arch = "aarch64")))]
pub fn running_fdt() -> Vec<u8> { Vec::new() }

/// Physical extent of the tree the load derives from, as `(pa, len)`, or
/// `(0, 0)` when this boot retained none.
///
/// Its reservation names memory the RUNNING kernel's blob occupies; the new
/// kernel is handed a different blob elsewhere, so carrying the reservation
/// forward would set aside memory nothing is in.
/// # C: O(1)
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub fn running_fdt_phys() -> (u64, u64) { firmware::fdt::phys_extent().unwrap_or((0, 0)) }
/// # C: O(1)
#[cfg(not(all(target_os = "oxide-kernel", target_arch = "aarch64")))]
pub fn running_fdt_phys() -> (u64, u64) { (0, 0) }
