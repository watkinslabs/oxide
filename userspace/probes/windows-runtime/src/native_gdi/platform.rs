#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
mod arch;
#[cfg(target_arch = "aarch64")]
#[path = "aarch64.rs"]
mod arch;

pub(super) fn entries() -> (u64, u64) { (arch::callback as *const () as u64, arch::complete as *const () as u64) }
