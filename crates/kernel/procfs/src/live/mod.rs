//! Kernel-side procfs integration. Body builders live in
//! crates/kernel/procfs (target-clean); the kernel-side mounting
//! and per-pid wiring stays here.

use core::sync::atomic::AtomicU64;

use vfs::Ino;

pub static NEXT_INO: AtomicU64 = AtomicU64::new(0x3000_0000);

pub(crate) fn pid_ino(tag: u64, id: u32) -> Ino {
    0x3000_0000_0000_0000 | (tag << 32) | id as u64
}

mod boot;
mod ns_dir;
mod pid_dir;
mod pid_files;
mod root;
mod self_files;

pub use boot::{init, smoke_test};
pub use ns_dir::make_proc_pid_ns_dir;
pub use pid_dir::{make_proc_pid_dir, make_proc_pid_task_dir};
pub use pid_files::{
    make_pid_cmdline, make_pid_comm, make_pid_environ, make_pid_limits, make_pid_maps,
    make_pid_sched, make_pid_stat, make_pid_statm, make_pid_status,
};
pub use root::make_proc_root;
pub use self_files::*;

pub use crate::cgroup_file::make_proc_cgroup;
