//! Boot-time integration smoke tests per `42`. Per-submodule
//! debug-* feature gates externalize R06 klog gating.

#![cfg(target_os = "oxide-kernel")]

#[cfg(feature = "debug-sched")]
pub mod canary;
#[cfg(feature = "debug-acpi")]
pub mod device_map;
pub mod elf;
#[cfg(target_arch = "aarch64")]
pub mod elf_arm;
#[cfg(feature = "debug-sched")]
pub mod ksched;
#[cfg(feature = "debug-vmm")]
pub mod mmuops;
#[cfg(feature = "debug-vmm")]
pub mod pf_recover;
#[cfg(feature = "debug-sched")]
pub mod preempt;
#[cfg(feature = "debug-vmm")]
pub mod user_map;
pub mod userspace;
#[cfg(target_arch = "aarch64")]
pub mod userspace_arm;
