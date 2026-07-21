use core::sync::atomic::Ordering;

use crate::inode::InodeRef;

use super::Dentry;

impl Drop for Dentry {
    /// Fire `d_op->d_release` on the final free (Linux `d_release`). # C: O(1)
    fn drop(&mut self) {
        // d_release first, while `self` is still live (Linux __dentry_kill).
        if let Some(f) = self.d_op.and_then(|o| o.d_release) { f(self); }
        // Linux dentry_unlink_inode releases the durable inode reference before
        // dentry_free defers only raw dentry storage through RCU.
        if self.counted.swap(false, Ordering::AcqRel) {
            let held = { let mut g = self.inode.write(); g.take() };
            if let Some(inode) = held {
                dentry_iput(inode);
            }
        }
    }
}

/// Release one dentry-held `i_count` reference (Linux `dentry_iput`).
/// # C: O(log N_ino) for an SB inode, else O(1)
pub(super) fn dentry_iput(inode: InodeRef) {
    match inode.i_sb() {
        Some(sb) => sb.iput(inode),
        None     => { inode.i_count_dec(); }
    }
}
