// The machine-specific half: stop the machine, then relocate and enter.
//
// STATUS: refused, with a diagnosis rather than a stub. A staged image is
// complete and correct — the relocation list, the control pages and the source
// pages are all built the way the trampoline needs them — but the trampoline
// that consumes it is not built on either arch, so `reboot(2)`'s KEXEC command
// refuses instead of jumping. `scratch/known_issues.md` carries the row.
//
// Returning success here would be the worst available answer: the caller's
// last observation would be a syscall that returned 0, on a machine that then
// kept running the old kernel, with no way to tell that from a kexec that
// booted an identical kernel.
//
// What the jump needs, per arch, so the next lane starts from the list and not
// from the reference:
//
// x86_64 — `machine_kexec_prepare` + `relocate_kernel`:
//   1. An identity page table (PML4 → 1 GiB pages over all of RAM) built into
//      image-owned control pages, plus the transition mapping that keeps the
//      trampoline's own page executable across the CR3 switch. It must live in
//      pages the relocation cannot overwrite — which is what
//      `KImage::alloc_control_page` already guarantees.
//   2. The trampoline copied into `control_code_page`, entered with IRQs
//      masked, on the identity CR3, after `swapgs` state is irrelevant: it
//      walks `head` following IND_DESTINATION / IND_SOURCE, copies page by
//      page, then `jmp`s to `start` with the boot protocol's register state.
//   3. Machine quiesce: stop the APs (they must not be executing pages the
//      copy is overwriting), mask the IOAPIC and the LAPIC timer, and quiesce
//      every DMA-capable device — a virtio queue still running rewrites the
//      new kernel's memory after the copy.
//
// aarch64 — `machine_kexec` + `arm64_relocate_new_kernel`:
//   1. The same list walk, but performed with the MMU OFF, so the trampoline
//      page must be identity mapped before `SCTLR_EL1.M` is cleared, per the
//      register-clobber and entry-state rules in `docs/54 §1`.
//   2. Every copied page cleaned to the point of coherency and the I-cache
//      invalidated before the branch, because the new kernel starts with
//      caches off and would otherwise execute stale lines.
//   3. Entry per the arm64 boot protocol `docs/36 §4` — x0 = DTB phys,
//      x1..x3 zero, EL1 or EL2 with interrupts masked.
//
// Both also need `machine_shutdown()`'s CPU-stop path, which this kernel has
// only in the halt/reset direction (`power::machine`), never in a form that
// leaves the machine able to run more code afterwards.

use crate::image::KImage;
use crate::validate::{Error, KResult};

/// `machine_kexec_prepare(image)`. Nothing arch-specific is required at STAGE
/// time on either arch here: the identity tables x86_64 builds in prepare are
/// derived from the image, so they belong to the jump that does not exist yet.
/// Kept as the seam the reference has, so the next lane adds the table build
/// in one place instead of threading it through the load.
/// # C: O(1)
pub fn prepare(_image: &KImage) -> KResult<()> { Ok(()) }

/// `machine_kexec(image)`: never returns on success.
///
/// See the module comment for exactly what is missing. `ENOSYS` is a
/// divergence — the reference has no errno for "the trampoline is not built",
/// because there it always is — and it is the only value that cannot be
/// confused with the two refusals the reference DOES make here (`EBUSY` for
/// the lock, `EINVAL` for no image loaded).
/// # C: O(1)
pub fn kexec(_image: &KImage) -> KResult<()> {
    klog::kwarn!("kexec: image staged, relocation trampoline not built, refusing to jump");
    Err(Error::NoSys)
}
