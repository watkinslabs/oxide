// fs umbrella per `52§4`. VFS-fd-producing subsystems that need
// both `vfs` (Inode trait) and `sched` (current / WaitList) live
// here as sibling modules. Each was previously its own kernel/*
// crate; folded together to flatten the workspace and match the
// Linux fs/ source layout.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
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
/// `fsync(2)`/`fdatasync(2)` + `sync_file_range(2)` work-fns (Linux `fs/sync.c`).
pub mod sync;
/// `fallocate(2)` work-fn — the `vfs_fallocate` ladder (Linux `fs/open.c`).
pub mod fallocate;
/// `readahead(2)` work-fn (Linux `mm/readahead.c` `ksys_readahead`).
pub mod readahead;
/// `splice(2)`/`tee(2)`/`vmsplice(2)`/`copy_file_range(2)` work-fns
/// (Linux `fs/splice.c` + `fs/read_write.c`).
pub mod splice;
pub mod xattr;
/// `file_getattr(2)`/`file_setattr(2)` `struct file_attr` ABI (Linux `fs/file_attr.c`).
pub mod fileattr;
pub mod keyring;
pub mod perf;
pub mod tmpfs;
pub mod fuse;
pub mod autofs;
pub mod binfmt_misc;
pub mod coredump;
/// BSD process accounting (`acct(2)`, Linux `kernel/acct.c`): one `acct_v3`
/// record appended per process exit.
pub mod acct;
pub mod ptrace;
pub mod sig_dispatch;
mod userbuf;

/// Install fs runtime hooks: flock release-on-close, inotify
/// IN_MODIFY-on-write, pipe reader/writer close tracking, epoll broadcast.
/// Boot, once, before any File can be dropped.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn init() {
    // `inotify_user_setup`/`fanotify_user_setup` derive the per-user watch and
    // mark ceilings from `si_meminfo()` at init time. Seeded here because the
    // PMM only knows the machine's size after boot memory setup.
    if let Some(p) = pmm::setup::pmm_static() {
        let bytes = p.snapshot().managed_pages.saturating_mul(hal::PAGE_SIZE_BYTES);
        vfs::fsnotify::init_watches_max_from_ram(bytes);
    }
    inotify::install_write_hook();
    truncate::install_rlimit_fsize_hook();
    pipe::install_close_hook();
    epoll::install_epoll_broadcast();
    timerfd::install_clock_was_set_hook();
}
