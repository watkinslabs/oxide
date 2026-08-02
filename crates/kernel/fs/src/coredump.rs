// Core dumps. Module manifest:
//   dumpable    whether a dying process may be dumped, and how carefully
//   filter      which mappings the dump contains, and how much of each
//   plan        walking a live VMA tree through that ladder into segments
//   gregset     the register and floating-point blocks a thread's notes carry
//   pattern     `kernel.core_pattern` storage and expansion; destination choice
//   limits      `kernel.core_pipe_limit` — how many collectors may run at once
//   stream      chunked delivery shared by every destination
//   file        the file destination's admission rules
//   elf         the `ET_CORE` image the dump consists of, built from injected inputs
//   pipe        the `|program` destination: start a helper, feed it the dump
//   file_target the file destination: create the target, stream the dump in
//   capture     reading the dying process into the builder's inputs
//   current     snapshotting the dying process and dispatching to a destination
//   tests       hosted coverage for the expansion and the argument split

pub mod dumpable;
pub mod filter;
pub mod plan;
pub mod gregset;
pub mod pattern;
pub mod limits;
pub mod stream;
pub mod file;
pub mod elf;
#[cfg(target_os = "oxide-kernel")]
pub mod pipe;
#[cfg(target_os = "oxide-kernel")]
mod file_target;
#[cfg(target_os = "oxide-kernel")]
mod capture;
#[cfg(target_os = "oxide-kernel")]
mod current;

pub use dumpable::{dump_allowed, suid_safe_required};
pub use plan::{plan_mappings, PlannedFile, PlannedSegment};
pub use filter::{describe_vma, dump_size, resolve_elf_probe, vma_dump_verdict, VmaDumpDesc, VmaDumpVerdict};
pub use pattern::{core_pattern, register_core_hooks, set_core_pattern, CoreContext, CoreKind};
pub use limits::{core_pipe_limit, register_limit_hooks, set_core_pipe_limit};
pub use elf::{build_core_image, CoreArch, CoreIdentity, CoreImageError, CoreImageInput, CoreMem,
    CoreSegFile, CoreSegment, CoreState, CoreThread, CoreTimes, CoreTimeval};
#[cfg(target_os = "oxide-kernel")]
pub use current::write_for_current;

#[cfg(test)]
mod tests;
