// Core dumps. Module manifest:
//   pattern  `kernel.core_pattern` storage and expansion; destination choice
//   elf      the `ET_CORE` image the dump consists of
//   pipe     the `|program` destination: start a helper, feed it the dump
//   current  snapshotting the dying process and dispatching to a destination
//   tests    hosted coverage for the expansion and the argument split

pub mod pattern;
pub mod elf;
#[cfg(target_os = "oxide-kernel")]
pub mod pipe;
#[cfg(target_os = "oxide-kernel")]
mod current;

pub use pattern::{core_pattern, register_core_hooks, set_core_pattern, CoreContext, CoreKind};
pub use elf::build_coredump;
#[cfg(target_os = "oxide-kernel")]
pub use current::write_for_current;

#[cfg(test)]
mod tests;
