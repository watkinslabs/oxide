#![no_std]
// Host builds compile only the identity/number modules; the kernel-only ones
// are cfg'd out, which leaves their helpers unreferenced.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
#[cfg(target_os = "oxide-kernel")] #[macro_use] extern crate kmacros;
extern crate alloc;

// /dev/ptmx + /dev/pts/<n> per `28§5`. Each open of /dev/ptmx allocates a
// fresh `tty::Pair`, registers a slave inode at /dev/pts/<n> in the devfs
// registry, and returns the master fd. Subsequent open of /dev/pts/<n> binds
// to the same pair.
//
// Module manifest:
// - `ids`:      inode NUMBERS + device identities, from `vfs::pseudo_ino`.
// - `identity`: who an endpoint inode IS — `i_private`, never its number.
// - `pair`:     the shared `LockedPair` object + the index → pair table.
// - `inodes`:   the ONE endpoint constructor, the ptmx nodes, `allocate_pair`.
// - `fs`:       the first-class `DevptsFs` SuperBlock backend.
// - `fileops`:  master + slave `file_operations`, including the job-control gate.
// - `ctty`:     controlling-terminal acquisition when a pty half is opened.
// - `smoke`:    boot-time pair round-trip check.
//
// `fileops`/`ctty`/`smoke` reach `sched::live` + `tty::jobctl::check`, which
// exist only in a kernel build; everything that decides IDENTITY is ungated and
// host-tested.

pub mod ids;
pub mod identity;
pub mod pair;

pub mod fs;
pub mod inodes;

#[cfg(target_os = "oxide-kernel")] pub mod ctty;
#[cfg(target_os = "oxide-kernel")] mod fileops;
#[cfg(target_os = "oxide-kernel")] mod smoke;

pub use ids::{DEVPTS_FSID, DEVPTS_MAGIC, MAX_PTY_PAIRS};
pub use identity::{endpoint_of, is_master_inode, is_pty_endpoint, pair_for_inode, PtyEndpointData};
pub use pair::{pair_for, LockedPair};

pub use fs::{devpts_fs, DevptsFs};
pub use inodes::{allocate_pair, make_master_inode, make_ptmx_sentinel_inode, make_slave_inode};

#[cfg(target_os = "oxide-kernel")]
pub use ctty::acquire_ctty_on_open;

/// Boot-time registration: register `/dev/ptmx` (sentinel inode — the real
/// factory work happens in sys_open) and the `/dev/pts` directory inode so
/// getdents64 enumerates allocated slaves.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn init() {
    devfs::register("/dev/ptmx", inodes::make_ptmx_sentinel_inode());
    devfs::register_dir("/dev/pts");
}

/// Boot-time smoke for the PTY pair surface: allocates a fresh pair, verifies
/// the slave inode is reachable in devfs at `/dev/pts/<n>`, and round-trips
/// bytes both directions.
/// # SAFETY: caller is the boot path; PMM up; pre-userspace.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn smoke_test() { smoke::smoke_test(); }
