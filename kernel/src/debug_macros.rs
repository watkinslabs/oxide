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
