// Boot cmdline transport. The bootloader's command line lives here so
// `/proc/cmdline` and any kernel parameter parser read from a single
// global. v1: arch defaults installed early in boot reflect what the
// build pipeline actually passes (Limine config / U-Boot bootargs);
// real bootloader parsing (Limine KERNEL_FILE.cmdline on x86, FDT
// /chosen/bootargs on aarch64) replaces `install_arch_default()` in
// follow-up PRs.
//
// The slot is single-writer (boot) / multi-reader (procfs) so an
// `AtomicPtr<&'static [u8]>`-equivalent guarded by `Once`-like
// semantics is enough; we use a plain `&'static [u8]` slot mutated
// only from the BSP-pre-userspace phase.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

static PTR: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static LEN: AtomicUsize = AtomicUsize::new(0);

/// Returns the current boot cmdline as bytes. Empty slice if no
/// bootloader transport has installed one yet.
/// # C: O(1)
pub fn get() -> &'static [u8] {
    let p = PTR.load(Ordering::Acquire);
    let n = LEN.load(Ordering::Acquire);
    if p.is_null() || n == 0 { return b""; }
    // SAFETY: `set` only stores a pointer to a 'static byte slice
    // (either an arch-default static literal or a bootloader-region
    // copy whose lifetime equals the boot environment). Length is
    // the slice length captured at store time.
    unsafe { core::slice::from_raw_parts(p, n) }
}

/// Install the boot cmdline. Boot path only — single-writer.
/// # SAFETY: caller is boot, before any procfs read can race; `bytes`
/// must outlive the kernel.
/// # C: O(1)
pub unsafe fn set(bytes: &'static [u8]) {
    LEN.store(bytes.len(), Ordering::Release);
    PTR.store(bytes.as_ptr() as *mut u8, Ordering::Release);
}

/// Install the arch-default cmdline. Stand-in until real bootloader
/// parsing lands. The console= component matches the UART the boot
/// crate actually programs, so userspace's `console=` introspection
/// agrees with what's emitting on serial.
/// # SAFETY: boot path only.
/// # C: O(1)
pub unsafe fn install_arch_default() {
    #[cfg(target_arch = "x86_64")]
    const DEFAULT: &[u8] =
        b"BOOT_IMAGE=/oxide root=/dev/oxide0 ro quiet console=ttyS0,115200\n";
    #[cfg(target_arch = "aarch64")]
    const DEFAULT: &[u8] =
        b"BOOT_IMAGE=/oxide root=/dev/oxide0 ro quiet console=ttyAMA0,115200\n";
    // Only install if nothing else (e.g. a future Limine/DTB parser)
    // has set it already.
    if PTR.load(Ordering::Acquire).is_null() {
        // SAFETY: install_arch_default is boot-only (single-writer); DEFAULT is a 'static byte literal that outlives the kernel; no procfs read can race here because /proc isn't mounted yet.
        unsafe { set(DEFAULT); }
    }
}
