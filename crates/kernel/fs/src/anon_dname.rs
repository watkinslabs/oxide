// dcache-D22: pseudo-dentry `d_op->d_dname` renderers for the fs/ anon-fd
// factories (signalfd, timerfd, epoll, inotify, fanotify, userfaultfd, perf).
// Linux `anon_inodefs_dname` renders every `anon_inode_getfd` fd as
// `anon_inode:<name>` (e.g. `anon_inode:[signalfd]`); the dentry's static name
// carries the bracketed token. Built via `vfs::dcache::d_alloc_pseudo`.

use alloc::format;
use alloc::string::String;
use vfs::dentry::{Dentry, DentryOps};

/// Every `anon_inode_getfd` fd in the kernel shares ONE `d_op` table, owned by
/// the VFS: `d_alloc_pseudo` recognises it by pointer identity to set
/// `S_ANON_INODE`, which a per-crate copy would defeat.
pub use vfs::dcache::ANON_INODE_OPS;

/// Linux `pipefs_dname`: render `pipe:[ino]`. # C: O(1)
fn pipe_dname(d: &Dentry) -> String {
    format!("pipe:[{}]", d.inode().map(|i| i.ino()).unwrap_or(0))
}

/// `d_op` for anonymous pipe ends. A pipe is not an anon-inode fd — it has its
/// own filesystem and its own name rendering — so it keeps a table of its own.
/// It lives here because the pipe does, so a second creator of a pipe end (the
/// coredump helper's standard input) cannot drift from the `pipe2` one.
pub static PIPE_OPS: DentryOps = DentryOps {
    d_dname: Some(pipe_dname),
    d_hash: None, d_compare: None, d_revalidate: None, d_weak_revalidate: None,
    d_delete: None, d_release: None, d_iput: None, d_init: None, d_prune: None,
};
