// Per-subsystem debug-trace gates per `04§3` (R05) + `04§4.0` (R06).
//
// Each `debug_<sub>!` macro expands to its body when the matching
// `debug-<sub>` Cargo feature is on, else to nothing — the call
// site is absent from the binary, not "filtered at runtime".
//
// Defined in this dedicated module + declared `#[macro_use] mod
// debug_macros;` in lib.rs so the macros are available to every
// sibling module without per-call `use` (`macro_rules!` doesn't
// have proper visibility; `#[macro_use]` is the canonical way to
// hoist them crate-wide for kernel-internal use).

#[cfg(feature = "debug-pmm")]
macro_rules! debug_pmm  { ($($t:tt)*) => { $($t)* } }
#[cfg(not(feature = "debug-pmm"))]
macro_rules! debug_pmm  { ($($t:tt)*) => {} }
#[cfg(feature = "debug-vmm")]
macro_rules! debug_vmm  { ($($t:tt)*) => { $($t)* } }
#[cfg(not(feature = "debug-vmm"))]
macro_rules! debug_vmm  { ($($t:tt)*) => {} }
#[cfg(feature = "debug-irq")]
macro_rules! debug_irq  { ($($t:tt)*) => { $($t)* } }
#[cfg(not(feature = "debug-irq"))]
macro_rules! debug_irq  { ($($t:tt)*) => {} }
#[cfg(feature = "debug-acpi")]
macro_rules! debug_acpi { ($($t:tt)*) => { $($t)* } }
#[cfg(not(feature = "debug-acpi"))]
macro_rules! debug_acpi { ($($t:tt)*) => {} }
#[cfg(feature = "debug-sched")]
macro_rules! debug_sched { ($($t:tt)*) => { $($t)* } }
#[cfg(not(feature = "debug-sched"))]
macro_rules! debug_sched { ($($t:tt)*) => {} }
#[cfg(feature = "debug-boot")]
macro_rules! debug_boot { ($($t:tt)*) => { $($t)* } }
#[cfg(not(feature = "debug-boot"))]
macro_rules! debug_boot { ($($t:tt)*) => {} }
#[cfg(feature = "debug-syscall")]
macro_rules! debug_syscall { ($($t:tt)*) => { $($t)* } }
#[cfg(not(feature = "debug-syscall"))]
macro_rules! debug_syscall { ($($t:tt)*) => {} }

// dtrace: structured trace probes that bypass the BOOT_UART lock.
// Emit directly to COM1 (x86) so probes work even when the klog path
// is wedged. Format: `[TAG]` for marker, `[TAG=hhhhhhhh]` for tag+u32.
// Gated under `debug-trace` so call sites are absent in production.
/// Emit one raw byte directly to COM1 (0x3F8). No THRE poll — must
/// be non-blocking so probes work in any kernel context.
/// # C: O(1)
#[cfg(all(feature = "debug-trace", target_arch = "x86_64"))]
#[allow(unused)]
pub fn __dtrace_outb(b: u8) {
    // SAFETY: COM1 (0x3F8) owned by kernel; outb at CPL=0.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") 0x3F8u16, in("al") b,
                         options(nomem, nostack, preserves_flags));
    }
}
/// arm/non-x86 stub for `__dtrace_outb`.
/// # C: O(1)
#[cfg(all(feature = "debug-trace", not(target_arch = "x86_64")))]
#[allow(unused)]
pub fn __dtrace_outb(_b: u8) {}

/// Emit `[tag]` marker via direct UART.
/// # C: O(tag.len())
#[cfg(feature = "debug-trace")]
#[allow(unused)]
pub fn __dtrace_tag(tag: &[u8]) {
    __dtrace_outb(b'[');
    for &b in tag { __dtrace_outb(b); }
    __dtrace_outb(b']');
}

/// Emit `[tag=hhhhhhhhhhhhhhhh]` marker with 64-bit hex value.
/// # C: O(tag.len() + 16)
#[cfg(feature = "debug-trace")]
#[allow(unused)]
pub fn __dtrace_kv(tag: &[u8], val: u64) {
    __dtrace_outb(b'[');
    for &b in tag { __dtrace_outb(b); }
    __dtrace_outb(b'=');
    for i in (0..16u32).rev() {
        let nib = ((val >> (i * 4)) & 0xf) as u8;
        let c = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
        __dtrace_outb(c);
    }
    __dtrace_outb(b']');
}

#[cfg(feature = "debug-trace")]
macro_rules! dtrace {
    ($tag:expr) => { $crate::debug_macros::__dtrace_tag($tag) };
    ($tag:expr, $val:expr) => { $crate::debug_macros::__dtrace_kv($tag, $val as u64) };
}
#[cfg(not(feature = "debug-trace"))]
macro_rules! dtrace {
    ($($t:tt)*) => {}
}
