// fs umbrella per `52§4`. VFS-fd-producing subsystems that need
// both `vfs` (Inode trait) and `sched` (current / WaitList) live
// here as sibling modules. Each was previously its own kernel/*
// crate; folded together to flatten the workspace and match the
// Linux fs/ source layout.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

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
pub mod coredump;
pub mod ptrace;
pub mod sig_dispatch;
