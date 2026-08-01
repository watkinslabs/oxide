// Core dumps. Module manifest:
//   dumpable whether a dying process may be dumped, and how carefully
//   pattern  `kernel.core_pattern` storage and expansion; destination choice
//   elf      the `ET_CORE` image the dump consists of, built from injected inputs
//   pipe     the `|program` destination: start a helper, feed it the dump
//   current  snapshotting the dying process and dispatching to a destination
//   tests    hosted coverage for the expansion and the argument split

pub mod dumpable;
pub mod pattern;
pub mod elf;
#[cfg(target_os = "oxide-kernel")]
pub mod pipe;
#[cfg(target_os = "oxide-kernel")]
mod current;

pub use dumpable::{dump_allowed, suid_safe_required};
pub use pattern::{core_pattern, register_core_hooks, set_core_pattern, CoreContext, CoreKind};
pub use elf::{build_core_image, CoreArch, CoreIdentity, CoreImageError, CoreImageInput, CoreMem,
    CoreSegFile, CoreSegment, CoreState, CoreThread, CoreTimes, CoreTimeval};
#[cfg(target_os = "oxide-kernel")]
pub use current::write_for_current;

#[cfg(test)]
mod tests;
