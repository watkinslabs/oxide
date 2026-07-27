// fs umbrella per `52§4`. VFS-fd-producing subsystems that need
// both `vfs` (Inode trait) and `sched` (current / WaitList) live
// here as sibling modules. Each was previously its own kernel/*
// crate; folded together to flatten the workspace and match the
// Linux fs/ source layout.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod anon_dname;
pub mod pipe;
pub mod signalfd;
pub mod timerfd;
pub mod epoll;
pub mod inotify;
pub mod userfaultfd;
pub mod flock;
pub mod posix_lock;
/// `truncate(2)`/`ftruncate(2)` size-change work-fns (Linux `fs/open.c`).
pub mod truncate;
/// `getcwd(2)`/`chdir(2)`/`fchdir(2)` pwd work-fns (Linux `fs/d_path.c`, `fs/open.c`).
pub mod cwd;
/// `fsync(2)`/`fdatasync(2)` work-fn (Linux `fs/sync.c`).
pub mod sync;
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
    truncate::install_rlimit_fsize_hook();
    pipe::install_close_hook();
    epoll::install_epoll_broadcast();
}
