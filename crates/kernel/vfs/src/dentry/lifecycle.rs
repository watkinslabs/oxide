use core::sync::atomic::Ordering;

use crate::inode::InodeRef;

use super::{Dentry, DentryOps};

impl Drop for Dentry {
    /// Fire `d_op->d_release` on the final free (Linux `d_release`). # C: O(1)
    fn drop(&mut self) {
        // d_release first, while `self` is still live (Linux __dentry_kill).
        // Diagnostic hardening (NOT the root-cause fix — an active hunt, see
        // `state.md`): a live `Dentry.d_op` has been observed corrupted (a
        // stray write leaves it non-None but pointing well below the kernel
        // half). Every real `&'static DentryOps` lives in the kernel's own
        // static image, always >= `hal::USER_VA_END`; calling through a
        // corrupted value is a wild function-pointer jump (undefined
        // behavior, an unpredictable #PF). Catching it here turns that into
        // a located, diagnosable panic naming the bad address instead.
        if let Some(o) = self.d_op {
            let addr = o as *const DentryOps as u64;
            if addr < hal::USER_VA_END {
                klog::write_primary_raw(b"[DENTRY] corrupt-d-op addr=0x");
                klog::write_primary_hex_u64(addr);
                klog::write_primary_raw(b"\n");
                assert!(false, "dentry d_op corrupted");
            }
        }
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
