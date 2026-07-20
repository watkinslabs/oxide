// fs umbrella per `52§4`. VFS-fd-producing subsystems that need
// both `vfs` (Inode trait) and `sched` (current / WaitList) live
// here as sibling modules. Each was previously its own kernel/*
// crate; folded together to flatten the workspace and match the
// Linux fs/ source layout.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod anon_dname;
pub mod pipe;
pub mod signalfd;
pub mod timerfd;
pub mod epoll;
pub mod inotify;
pub mod userfaultfd;
pub mod flock;
pub mod posix_lock;
pub mod xattr;
pub mod keyring;
pub mod perf;
pub mod tmpfs;
pub mod fuse;
pub mod autofs;
pub mod binfmt_misc;
pub mod coredump;
pub mod ptrace;
pub mod sig_dispatch;
mod userbuf;

/// Install fs runtime hooks: flock release-on-close, inotify
/// IN_MODIFY-on-write, pipe reader/writer close tracking, epoll broadcast.
/// Boot, once, before any File can be dropped.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn init() {
    inotify::install_write_hook();
    pipe::install_close_hook();
    epoll::install_epoll_broadcast();
}
