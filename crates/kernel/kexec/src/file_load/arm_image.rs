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

/// The running kernel's flattened device tree.
///
/// EMPTY, AND THAT IS A REPORTED GAP RATHER THAN A DESIGN. The boot DTB's
/// physical address does arrive on this port — the aarch64 entry point takes
/// it in `x0` and stores it — but it is stored in a private static inside the
/// boot crate, which sits ABOVE this one in the dependency graph (the boot
/// crate depends on the kernel main crate, which reaches this one). Neither
/// `BootInfo` nor any shared crate carries the address or the length, so there
/// is no path from here to the blob.
///
/// The consequence is honest and visible rather than silent: with no tree to
/// derive from, `load` refuses with EINVAL exactly where the reference refuses
/// when it cannot build one. Closing it means publishing the boot DTB's
/// address and length through the shared boot-info handoff, which is the boot
/// crate's decision to make, not this module's.
/// # C: O(1)
pub fn running_fdt() -> Vec<u8> { Vec::new() }
