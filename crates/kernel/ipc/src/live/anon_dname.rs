// dcache-D22: pseudo-dentry `d_op->d_dname` renderer for the POSIX mqueue fd
// factory (`sys_mq_open`). Linux mqueue is a real filesystem (mqueuefs); its
// dentry name is the queue name with the leading `/` stripped (`do_mq_open`
// advances past the leading slash before `lookup_one_len`). The fd's dentry
// renders as that bare queue name. Built via `vfs::dcache::d_alloc_pseudo`.

use alloc::string::{String, ToString};
use vfs::dentry::{Dentry, DentryOps};

/// Linux mqueuefs dentry name: the bare queue name (leading `/` already
/// stripped at construction). # C: O(name.len())
fn mqueue_dname(d: &Dentry) -> String { d.name().to_string() }

/// `d_op` for POSIX mqueue fds: renders the bare queue name.
pub static MQUEUE_OPS: DentryOps = DentryOps {
    d_dname: Some(mqueue_dname),
    d_hash: None, d_compare: None, d_revalidate: None, d_weak_revalidate: None,
    d_delete: None, d_release: None, d_iput: None, d_init: None, d_prune: None,
};
