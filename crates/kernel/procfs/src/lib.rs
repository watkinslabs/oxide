// /dev, /proc, /sys per docs/19. This crate hosts the *shared
// pseudo-FS primitive* (`pseudo.rs`) used by all three; per-FS
// bodies (per-pid procfs / sysfs KObj tree / devfs DevId nodes)
// ride in their own follow-up branches atop this surface.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[macro_use] extern crate kmacros;
pub use vfs::StaticFileInode;  // generic inode lives in vfs
// Consolidated kernel-side procfs (was kernel/src/procfs/), docs/53.
#[cfg(target_os = "oxide-kernel")] pub mod live;
#[cfg(target_os = "oxide-kernel")] pub use live::*;
#[cfg(target_os = "oxide-kernel")] pub mod fs_impl;
#[cfg(target_os = "oxide-kernel")] pub mod proc_links;
#[cfg(target_os = "oxide-kernel")] pub mod static_files;
#[cfg(target_os = "oxide-kernel")] pub mod cgroup_file;
#[cfg(target_os = "oxide-kernel")] pub mod mounts;
#[cfg(target_os = "oxide-kernel")] pub mod cmdline;
#[cfg(target_os = "oxide-kernel")] pub mod stat;
#[cfg(target_os = "oxide-kernel")] pub mod fdinfo;
#[cfg(target_os = "oxide-kernel")] pub mod sysctl;
#[cfg(target_os = "oxide-kernel")] mod pid_sched;
pub mod hooks;

#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod paths;
pub mod pseudo;
pub use paths::{child_under, parse_proc_path, ProcPath};
pub use pseudo::{
    DynamicOps, KResult as PseudoKResult, PseudoError, PseudoFs, PseudoLeaf, PseudoOps,
    StaticBytesOps,
};

#[cfg(test)]
mod tests;

/// Subsystem-level error per `38`. Kept for the existing skeleton
/// `init` shim; the canonical pseudo-FS error is `PseudoError`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NotImplemented,
    NoMem,
    Inval,
    Io,
}

#[allow(dead_code)]
pub(crate) type StubResult<T> = core::result::Result<T, Error>;

// The real boot init is `live::init` (registers all /proc + /sys + /etc
// static files), re-exported via `pub use live::*` above. The old stub
// `init` skeleton was deleted with the consolidation (docs/53).

#[cfg(target_os = "oxide-kernel")]
pub mod meminfo;

#[cfg(target_os = "oxide-kernel")]
pub mod net;

#[cfg(target_os = "oxide-kernel")] pub mod pid_stat;
#[cfg(target_os = "oxide-kernel")] pub mod pid_status;
#[cfg(target_os = "oxide-kernel")] pub mod smaps;
