// dcache-D22: pseudo-dentry `d_op->d_dname` renderer for the bpf anon-fd
// factories (prog/map/link `install_fd`). Linux `anon_inodefs_dname` renders
// every `anon_inode_getfd` fd as `anon_inode:<name>` (e.g. `anon_inode:bpf-prog`,
// `bpf-map`, `bpf-link`); the dentry's static name carries the bare token.
// Built via `vfs::dcache::d_alloc_pseudo`.



/// Every `anon_inode_getfd` fd in the kernel shares ONE `d_op` table, owned by
/// the VFS: `d_alloc_pseudo` recognises it by pointer identity to set
/// `S_ANON_INODE`, which a per-crate copy would defeat.
pub use vfs::dcache::ANON_INODE_OPS;
