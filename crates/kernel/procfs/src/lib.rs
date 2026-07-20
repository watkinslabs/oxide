// /dev, /proc, /sys per docs/19. This crate hosts the *shared
// pseudo-FS primitive* (`pseudo.rs`) used by all three; per-FS
// bodies (per-pid procfs / sysfs KObj tree / devfs DevId nodes)
// ride in their own follow-up branches atop this surface.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[macro_use] extern crate kmacros;
mod ids;
pub use vfs::StaticFileInode;  // generic inode lives in vfs
// Consolidated kernel-side procfs (was kernel/src/procfs/), docs/53.
#[cfg(any(target_os = "oxide-kernel", test))] pub mod dyn_file;
#[cfg(target_os = "oxide-kernel")] pub mod live;
#[cfg(target_os = "oxide-kernel")] pub use live::*;
#[cfg(target_os = "oxide-kernel")] pub mod fs_impl;
#[cfg(target_os = "oxide-kernel")] pub mod proc_links;
#[cfg(target_os = "oxide-kernel")] pub mod static_files;
#[cfg(target_os = "oxide-kernel")] pub mod cgroup_file;
#[cfg(target_os = "oxide-kernel")] pub mod mounts;
#[cfg(any(target_os = "oxide-kernel", test))] mod mount_snapshot;
#[cfg(target_os = "oxide-kernel")] pub mod cmdline;
#[cfg(target_os = "oxide-kernel")] pub mod stat;
#[cfg(target_os = "oxide-kernel")] pub mod cpuinfo;
#[cfg(target_os = "oxide-kernel")] pub mod vmstat;
#[cfg(target_os = "oxide-kernel")] pub mod partitions;
#[cfg(target_os = "oxide-kernel")] pub mod diskstats;
#[cfg(target_os = "oxide-kernel")] pub mod interrupts;
#[cfg(target_os = "oxide-kernel")] pub mod devices;
#[cfg(target_os = "oxide-kernel")] pub mod syscpu;
#[cfg(target_os = "oxide-kernel")] pub mod buddyinfo;
#[cfg(target_os = "oxide-kernel")] pub mod fdinfo;
#[cfg(target_os = "oxide-kernel")] pub mod sysctl;
#[cfg(target_os = "oxide-kernel")] pub mod ctl;
#[cfg(target_os = "oxide-kernel")] pub mod pressure;
pub mod proc_dointvec;
pub mod proc_handler;
#[cfg(target_os = "oxide-kernel")] mod pid_sched;
#[cfg(any(target_os = "oxide-kernel", test))] mod proc_clock;
#[cfg(any(target_os = "oxide-kernel", test))] mod timens_offsets;
pub mod hooks;
#[cfg(target_os = "oxide-kernel")] mod util;

#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod paths;
pub mod pseudo;
pub mod reg;
pub use reg::{proc_reg, register, PROCFS_FSID};
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
#[cfg(any(target_os = "oxide-kernel", test))]
pub mod memory;
#[cfg(target_os = "oxide-kernel")]
pub mod swaps;

#[cfg(target_os = "oxide-kernel")]
pub mod net;
#[cfg(any(target_os = "oxide-kernel", test))]
pub mod net_raw;

#[cfg(target_os = "oxide-kernel")] pub mod pid_stat;
#[cfg(target_os = "oxide-kernel")] pub mod pid_status;
#[cfg(target_os = "oxide-kernel")] pub mod smaps;
