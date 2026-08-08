// The boot command line itself. Single-writer (boot) / multi-reader
// (procfs, every parameter consumer) global, so `/proc/cmdline` and every
// parameter decision read one string — a second copy would be a second
// answer to "what did the bootloader say".

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

/// Has a bootloader transport installed a command line yet?
/// # C: O(1)
pub fn is_set() -> bool { !PTR.load(Ordering::Acquire).is_null() }

/// Install the boot cmdline. Boot path only — single-writer.
/// # SAFETY: caller is boot, before any procfs read can race; `bytes`
/// must outlive the kernel.
/// # C: O(1)
pub unsafe fn set(bytes: &'static [u8]) {
    LEN.store(bytes.len(), Ordering::Release);
    PTR.store(bytes.as_ptr() as *mut u8, Ordering::Release);
}

/// Install the arch-default cmdline when no bootloader transport supplied
/// one. The console= component matches the UART the boot crate actually
/// programs, so userspace's `console=` introspection agrees with what is
/// emitting on serial.
///
/// With multiple `console=` entries printk fans out to every registered
/// console and the LAST entry is the preferred console backing
/// `/dev/console`. This default keeps serial present for logs while making
/// the video VT the preferred interactive console.
/// # SAFETY: boot path only.
/// # C: O(1)
pub unsafe fn install_arch_default() {
    #[cfg(target_arch = "x86_64")]
    const DEFAULT: &[u8] =
        b"BOOT_IMAGE=/oxide root=/dev/oxide0 ro console=ttyS0,115200 console=tty0\n";
    #[cfg(not(target_arch = "x86_64"))]
    const DEFAULT: &[u8] =
        b"BOOT_IMAGE=/oxide root=/dev/oxide0 ro console=ttyAMA0,115200 console=tty0\n";
    if !is_set() {
        // SAFETY: install_arch_default is boot-only (single-writer); DEFAULT is a 'static byte literal that outlives the kernel; no procfs read can race here because /proc isn't mounted yet.
        unsafe { set(DEFAULT); }
    }
}
