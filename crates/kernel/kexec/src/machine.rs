// The machine-specific half: build the tables at load time, stop the machine,
// then relocate and enter.
//
// Split the way the reference splits it. `machine_kexec_prepare` runs while a
// syscall can still return an errno and does everything that can fail — the
// identity page tables, the trampoline copy, the size and reachability checks.
// `machine_kexec` runs past the point of no return and allocates nothing.
//
// Module manifest:
// - `plan`:    ungated — the ranges the identity map covers, what that costs
//              in control pages, and the control-register state at entry.
// - `walk`:    ungated — the IND_* walk the trampoline performs, so its order
//              is checkable without a boot.
// - `idmap`:   ungated — the identity + transition mappings, over the kernel's
//              own page-table walker.
// - `quiesce`: ungated — which CPUs must stop and when the stop is complete.
// - `x86`:     x86_64 `relocate_kernel` and the privileged steps around it.
// - `arm`:     aarch64 `arm64_relocate_new_kernel` and the same.
//
// WHY THE TRAMPOLINE COPIES ITSELF ONTO A CONTROL PAGE. The pages it is about
// to move include the ones the running kernel occupies — a second kernel is
// normally loaded exactly where the first one lives. Any code still executing
// out of the kernel image at that moment is overwritten mid-instruction. A
// control page is the one supply guaranteed to sit outside every destination
// range, so code copied there survives its own relocation.

pub mod plan;
pub mod walk;
pub mod idmap;
pub mod quiesce;

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub mod x86;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub mod arm;

use crate::frames::Frames;
use crate::image::KImage;
use crate::validate::KResult;

/// `machine_kexec_prepare(image)`: everything the jump needs, built while a
/// failure is still an errno.
///
/// Called from the tail of staging, after the relocation list is terminated,
/// because the identity map has to cover every destination range and those are
/// not all known until then.
/// # C: O(RAM / 2 MiB)
pub fn prepare<F: Frames>(image: &mut KImage, f: &mut F) -> KResult<()> {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { x86::prepare(image, f) }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    { arm::prepare(image, f) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = (image, f); Ok(()) }
}

/// `machine_kexec_cleanup(image)`: undo every mapping change `prepare` made,
/// BEFORE the image's pages go back to the allocator.
///
/// Not a tidy-up. `prepare` narrows the control page's kernel mapping to
/// read-only so the trampoline can be entered through it; a page released in
/// that state is handed to the next caller with a mapping that faults on its
/// first write, in whatever unrelated subsystem happened to draw it. The
/// failure would appear arbitrarily far from the code that caused it.
///
/// Idempotent, because it runs on every teardown path — the successful unload,
/// the replaced image, and the half-staged image a failing `prepare` frees.
/// # C: O(1)
pub fn cleanup(image: &KImage) {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { x86::cleanup(image); }
    #[cfg(not(all(target_os = "oxide-kernel", target_arch = "x86_64")))]
    { let _ = image; }
}

/// `device_shutdown()` from `kernel_restart_prepare("kexec reboot")`.
///
/// Separate from [`kexec`] because it is the only step here that is NOT past
/// the point of no return: the reference runs it while the machine could still
/// abort, and it is idempotent so a later reboot does not drive every device
/// twice.
/// # C: O(N_devices)
pub fn shutdown_devices() {
    #[cfg(target_os = "oxide-kernel")]
    power::machine::shutdown_devices_once();
}

/// `machine_kexec(image)`: never returns on success.
/// # C: O(image size)
pub fn kexec(image: &KImage) -> KResult<()> {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { x86::kexec(image) }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    { arm::kexec(image) }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
        // The hosted harness has no machine to replace. Reporting success
        // would make every store-level test assert on a jump that did not
        // happen; `ENOSYS` is what a build with no relocation support answers.
        let _ = image;
        Err(crate::validate::Error::NoSys)
    }
}
