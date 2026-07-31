// dcache-D22: pseudo-dentry `d_op->d_dname` renderers for the syscall anon-fd
// factories (eventfd2, pipe2, socket/socketpair/accept, memfd_create, pidfd,
// io_uring, landlock, fscontext/mount fds). Each mirrors the matching Linux
// `dentry_operations::d_dname`: pipefs `pipe:[ino]`, sockfs `socket:[ino]`,
// shmem memfd `/memfd:NAME (deleted)`, anon_inodefs `anon_inode:<name>`.
// Built via `vfs::dcache::d_alloc_pseudo`.

use alloc::format;
use alloc::string::String;
use vfs::dentry::{Dentry, DentryOps};

/// Linux pipefs `pipefs_dname`: render `pipe:[<ino>]`. # C: O(1)
fn pipe_dname(d: &Dentry) -> String { let ino = d.inode().map(|i| i.ino()).unwrap_or(0); format!("pipe:[{ino}]") }
/// Linux sockfs `sockfs_dname`: render `socket:[<ino>]`. # C: O(1)
fn socket_dname(d: &Dentry) -> String { let ino = d.inode().map(|i| i.ino()).unwrap_or(0); format!("socket:[{ino}]") }
/// Linux shmem memfd: an unlinked tmpfs dentry renders `/<name> (deleted)`
/// where `<name>` is the `memfd:` token. # C: O(name.len())
fn memfd_dname(d: &Dentry) -> String { format!("/{} (deleted)", d.name()) }

/// Every `anon_inode_getfd` fd in the kernel shares ONE `d_op` table, owned by
/// the VFS: `d_alloc_pseudo` recognises it by pointer identity to set
/// `S_ANON_INODE`, which a per-crate copy would defeat.
pub use vfs::dcache::ANON_INODE_OPS;
/// `d_op` for pipefs anonymous pipe ends: `pipe:[ino]`.
pub static PIPE_OPS: DentryOps = DentryOps {
    d_dname: Some(pipe_dname),
    d_hash: None, d_compare: None, d_revalidate: None, d_weak_revalidate: None,
    d_delete: None, d_release: None, d_iput: None, d_init: None, d_prune: None,
};
/// `d_op` for sockfs socket fds: `socket:[ino]`.
pub static SOCKET_OPS: DentryOps = DentryOps {
    d_dname: Some(socket_dname),
    d_hash: None, d_compare: None, d_revalidate: None, d_weak_revalidate: None,
    d_delete: None, d_release: None, d_iput: None, d_init: None, d_prune: None,
};
/// `d_op` for shmem memfd fds: `/memfd:NAME (deleted)`.
pub static MEMFD_OPS: DentryOps = DentryOps {
    d_dname: Some(memfd_dname),
    d_hash: None, d_compare: None, d_revalidate: None, d_weak_revalidate: None,
    d_delete: None, d_release: None, d_iput: None, d_init: None, d_prune: None,
};
