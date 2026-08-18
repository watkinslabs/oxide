//! ACPI processor-performance provider.
//!
//! Module manifest:
//! - `decode` — pure `_PSS`, `_PCT`, `_PPC`, and `_PSD` validation.
//! - `command` — compact cross-CPU transition command representation.
//! - `policy` — pure CPU-description grouping into performance domains.
//! - `x86` — policy discovery and x86 P-state register programming.

#[cfg(any(test, all(target_arch = "x86_64", target_os = "oxide-kernel")))]
mod command;
pub mod decode;
#[cfg(any(test, all(target_arch = "x86_64", target_os = "oxide-kernel")))]
mod policy;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
mod x86;

/// Publish every usable ACPI processor-performance policy. # C: O(AML)
pub fn init() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { return x86::init(); }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Execute one fixed-hardware P-state command on the CPU receiving an IPI.
/// # C: O(1)
pub fn service_remote(command: u64) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { x86::service_remote(command); }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = command; }
}
