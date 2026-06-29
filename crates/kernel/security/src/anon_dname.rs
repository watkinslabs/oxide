// dcache-D22: pseudo-dentry `d_op->d_dname` renderer for the bpf anon-fd
// factories (prog/map/link `install_fd`). Linux `anon_inodefs_dname` renders
// every `anon_inode_getfd` fd as `anon_inode:<name>` (e.g. `anon_inode:bpf-prog`,
// `bpf-map`, `bpf-link`); the dentry's static name carries the bare token.
// Built via `vfs::dcache::d_alloc_pseudo`.

use alloc::format;
use alloc::string::String;
use vfs::dentry::{Dentry, DentryOps};

/// Linux `anon_inodefs_dname`: render `anon_inode:<d_name>`. # C: O(name.len())
fn anon_inode_dname(d: &Dentry) -> String { format!("anon_inode:{}", d.name()) }

/// `d_op` for every `anon_inode_getfd`-style pseudo fd in this crate. The single
/// `d_dname` hook prefixes the dentry's static token with `anon_inode:`.
pub static ANON_INODE_OPS: DentryOps = DentryOps {
    d_dname: Some(anon_inode_dname),
    d_hash: None, d_compare: None, d_revalidate: None, d_weak_revalidate: None,
    d_delete: None, d_release: None, d_iput: None, d_init: None, d_prune: None,
};
