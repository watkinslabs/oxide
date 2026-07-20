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
/// Linux convention with multiple `console=` entries: printk may fan out
/// to every registered console, and the LAST entry is the preferred
/// console backing `/dev/console` (`preferred_console`). Oxide's default
/// keeps serial present for logs/debug while making the video VT the
/// preferred interactive console when a framebuffer console exists.
/// # SAFETY: boot path only.
/// # C: O(1)
pub unsafe fn install_arch_default() {
    #[cfg(target_arch = "x86_64")]
    const DEFAULT: &[u8] =
        b"BOOT_IMAGE=/oxide root=/dev/oxide0 ro quiet console=ttyS0,115200 console=tty0\n";
    #[cfg(target_arch = "aarch64")]
    const DEFAULT: &[u8] =
        b"BOOT_IMAGE=/oxide root=/dev/oxide0 ro quiet console=ttyAMA0,115200 console=tty0\n";
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

/// Does the cmdline request a printk console of each class? Linux registers a
/// `struct console` per `console=` token; a class NOT named gets no printk (its
/// `/dev` tty still works). `(serial, vt)`. If NO parseable `console=` token is
/// present, both are true (safe default: keep every sink, matching the arch
/// default `console=ttyS0 console=tty0`). # C: O(line length)
pub fn console_classes() -> (bool, bool) { console_classes_in(get()) }

/// Pure, global-free form of [`console_classes`] (unit-testable). # C: O(len)
pub fn console_classes_in(line: &[u8]) -> (bool, bool) {
    let mut serial = false;
    let mut vt = false;
    let mut any = false;
    let mut i = 0;
    while let Some(p) = find(&line[i..], b"console=") {
        let start = i + p + b"console=".len();
        let mut end = start;
        while end < line.len() && line[end] != b',' && !line[end].is_ascii_whitespace() { end += 1; }
        match classify(&line[start..end]) {
            Some(ConsoleKind::Serial) => { serial = true; any = true; }
            Some(ConsoleKind::Vt(_))  => { vt = true; any = true; }
            None => {}
        }
        i = end;
    }
    if !any { (true, true) } else { (serial, vt) }
}

/// First index of `needle` in `hay`, or `None`. # C: O(len)
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() { return None; }
    (0..=hay.len() - needle.len()).find(|&w| &hay[w..w + needle.len()] == needle)
}

/// Linux `init=<path>` kernel parameter: the executable PID 1 should run.
/// Returns the path bytes if present. Matched only as a whole token (start of
/// line or after whitespace) so it never matches `systemd.unit=`, etc. Value
/// runs to the next whitespace. # C: O(line length)
pub fn init_path() -> Option<&'static [u8]> { init_path_in(get()) }

/// Pure form of [`init_path`] over an explicit slice (global-free, testable).
/// # C: O(line length)
pub fn init_path_in(line: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    while let Some(p) = find(&line[i..], b"init=") {
        let at = i + p;
        // Whole-token: preceded by start-of-line or whitespace (else it is the
        // tail of another key like `systemd.unit=`... which has no `init=`, but
        // guard anyway).
        if at == 0 || line[at - 1].is_ascii_whitespace() {
            let start = at + b"init=".len();
            let mut end = start;
            while end < line.len() && !line[end].is_ascii_whitespace() { end += 1; }
            if end > start { return Some(&line[start..end]); }
        }
        i = at + b"init=".len();
    }
    None
}

/// Return the value of the last exact `name=value` boot parameter. Linux
/// command-line parsing is token based, so prefixes and embedded `=` text do
/// not match; repeated scalar parameters use the last supplied value.
/// # C: O(cmdline length)
pub fn parameter_value(name: &[u8]) -> Option<&'static [u8]> {
    parameter_value_in(get(), name)
}

/// Global-free form of [`parameter_value`] for boot-option consumers and
/// parser tests. # C: O(line length)
pub fn parameter_value_in<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    if name.is_empty() { return None; }
    let mut value = None;
    for token in line.split(|byte| byte.is_ascii_whitespace()) {
        let Some(separator) = token.iter().position(|byte| *byte == b'=') else { continue; };
        let (key, candidate_with_separator) = token.split_at(separator);
        let candidate = &candidate_with_separator[1..];
        if key == name { value = Some(candidate); }
    }
    value
}

#[cfg(test)]
mod console_class_tests {
    use super::{console_classes_in, ConsoleKind, preferred_console_in};

    #[test]
    fn both_default_cmdline() {
        let (s, v) = console_classes_in(b"root=/dev/oxide0 console=ttyS0,115200 console=tty0");
        assert!(s && v, "default cmdline registers serial + vt");
        assert_eq!(preferred_console_in(b"console=ttyS0 console=tty0"), ConsoleKind::Vt(0));
    }
    #[test]
    fn serial_only() {
        let (s, v) = console_classes_in(b"quiet console=ttyS0,115200");
        assert!(s && !v, "console=ttyS0 only → serial printk, no VT");
    }
    #[test]
    fn vt_only() {
        let (s, v) = console_classes_in(b"console=tty0");
        assert!(!s && v, "console=tty0 only → VT printk, no serial");
    }
    #[test]
    fn none_defaults_both() {
        let (s, v) = console_classes_in(b"root=/dev/oxide0 ro quiet");
        assert!(s && v, "no console= token → keep both sinks (safe default)");
    }
    #[test]
    fn arm_pl011_is_serial() {
        let (s, v) = console_classes_in(b"console=ttyAMA0,115200 console=tty0");
        assert!(s && v, "ttyAMA0 counts as serial");
    }
    #[test]
    fn vt_n_counts_as_vt() {
        let (s, v) = console_classes_in(b"console=tty1");
        assert!(!s && v, "console=tty1 is a VT console");
    }
}

#[cfg(test)]
mod parameter_tests {
    use super::parameter_value_in;

    #[test]
    fn exact_parameter_uses_last_complete_token() {
        let line = b"not.zram.num_devices=9 zram.num_devices=0 zram.num_devices=3";
        assert_eq!(parameter_value_in(line, b"zram.num_devices"), Some(&b"3"[..]));
    }

    #[test]
    fn parameter_does_not_match_prefix_or_flag() {
        let line = b"zram.num_devices_extra=4 zram.num_devices";
        assert_eq!(parameter_value_in(line, b"zram.num_devices"), None);
    }
}
