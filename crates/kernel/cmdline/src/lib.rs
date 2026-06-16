#![no_std]
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
///
/// Linux convention `console=tty0 console=ttyS0,115200`: printk fans out
/// to BOTH consoles (framebuffer VT + serial UART), and the LAST entry
/// (serial) is the *preferred console* that backs `/dev/console`
/// (`preferred_console`). So the boot framebuffer stays visible AND the
/// getty/login line on `/dev/console` reaches the serial port.
/// # SAFETY: boot path only.
/// # C: O(1)
pub unsafe fn install_arch_default() {
    #[cfg(target_arch = "x86_64")]
    const DEFAULT: &[u8] =
        b"BOOT_IMAGE=/oxide root=/dev/oxide0 ro quiet console=tty0 console=ttyS0,115200\n";
    #[cfg(target_arch = "aarch64")]
    const DEFAULT: &[u8] =
        b"BOOT_IMAGE=/oxide root=/dev/oxide0 ro quiet console=tty0 console=ttyAMA0,115200\n";
    // Only install if nothing else (e.g. a future Limine/DTB parser)
    // has set it already.
    if PTR.load(Ordering::Acquire).is_null() {
        // SAFETY: install_arch_default is boot-only (single-writer); DEFAULT is a 'static byte literal that outlives the kernel; no procfs read can race here because /proc isn't mounted yet.
        unsafe { set(DEFAULT); }
    }
}

/// Kind of console device named by a `console=` token.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConsoleKind {
    /// A serial UART line (`ttyS<n>` x86 16550, `ttyAMA<n>` arm PL011).
    /// Backs `/dev/ttyS0` (the serial tty).
    Serial,
    /// Video VT `n` — `tty0` = current foreground VT, `tty<n>` = VT n.
    Vt(u8),
}

/// Map a `console=` device name (the token after `console=`, up to `,` or
/// whitespace) to its [`ConsoleKind`]. Linux device naming:
/// `ttyS*`/`ttyAMA*` = serial; `tty0` = fg VT; `tty<n>` = VT n.
fn classify(name: &[u8]) -> Option<ConsoleKind> {
    if name.is_empty() { return None; }
    if name.starts_with(b"ttyS") || name.starts_with(b"ttyAMA") {
        return Some(ConsoleKind::Serial);
    }
    if let Some(rest) = name.strip_prefix(b"tty") {
        // `tty` followed by digits → VT n (tty0 = fg). Non-digit tail
        // (already-handled ttyS/ttyAMA, or unknown) → not a VT.
        if !rest.is_empty() && rest.iter().all(|c| c.is_ascii_digit()) {
            let mut n: u32 = 0;
            for &c in rest { n = n.saturating_mul(10).saturating_add((c - b'0') as u32); }
            return Some(ConsoleKind::Vt(n.min(255) as u8));
        }
    }
    None
}

/// The *preferred console*: the device named by the LAST `console=` token on
/// the boot cmdline (Linux semantics — last wins, backs `/dev/console`).
/// Falls back to `Vt(0)` (the foreground video VT) when no parseable
/// `console=` is present, matching Linux's default-to-VT behavior.
/// # C: O(cmdline length)
pub fn preferred_console() -> ConsoleKind { preferred_console_in(get()) }

/// Pure form of [`preferred_console`] over an explicit cmdline slice (kept
/// global-free so it is unit-testable). Scans every `console=` token, parses
/// its device name, and keeps the LAST parseable one. # C: O(line length)
pub fn preferred_console_in(line: &[u8]) -> ConsoleKind {
    let mut chosen = ConsoleKind::Vt(0);
    let mut i = 0;
    while let Some(p) = find(&line[i..], b"console=") {
        let start = i + p + b"console=".len();
        // device name = bytes up to ',' or ASCII whitespace.
        let mut end = start;
        while end < line.len() && line[end] != b',' && !line[end].is_ascii_whitespace() { end += 1; }
        if let Some(k) = classify(&line[start..end]) { chosen = k; }
        i = end;
    }
    chosen
}

/// First index of `needle` in `hay`, or `None`. # C: O(len)
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() { return None; }
    (0..=hay.len() - needle.len()).find(|&w| &hay[w..w + needle.len()] == needle)
}
