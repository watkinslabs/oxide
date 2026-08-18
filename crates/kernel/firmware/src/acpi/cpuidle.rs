//! ACPI processor C-state provider.

pub mod decode;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
mod x86;

/// Publish the complete ACPI C-state ladder when the platform exposes one.
/// # C: O(AML²)
pub fn init() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { return x86::init(); }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}
