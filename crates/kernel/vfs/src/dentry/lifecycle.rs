use core::sync::atomic::Ordering;

use crate::inode::InodeRef;

#[cfg(target_os = "oxide-kernel")]
extern crate alloc;
#[cfg(target_os = "oxide-kernel")]
use alloc::sync::Weak;

use super::Dentry;
#[cfg(target_os = "oxide-kernel")]
use super::DentryOps;

impl Drop for Dentry {
    /// Fire `d_op->d_release` on the final free (Linux `d_release`). # C: O(1)
    fn drop(&mut self) {
        // Corruption-hunt guard (state.md): `sb: Weak<SuperBlock>` is either
        // the empty-Weak sentinel (`Weak::as_ptr()` returns `usize::MAX` for
        // `Weak::new()`, confirmed empirically -- never 0) or a real
        // non-null `WeakInner` pointer. A live sample this session hit the
        // field's auto-generated drop (inside `Arc<Dentry>::drop_slow`)
        // holding raw 0, misread as "not the sentinel", and faulted a
        // `lock decq` through a null-derived address. Catch it here, before
        // field drop runs, so a corrupted dentry names itself instead of an
        // opaque #PF three instructions later. Kernel-target only, like the
        // d_op guard below: a hosted test's addresses don't share this
        // invariant's provenance assumptions the same way.
        #[cfg(target_os = "oxide-kernel")]
        {
            let sb_raw = Weak::as_ptr(&self.sb) as usize;
            if sb_raw == 0 {
                klog::write_primary_raw(b"[DENTRY] corrupt-sb-weak dentry=0x");
                klog::write_primary_hex_u64(self as *const Dentry as u64);
                klog::write_primary_raw(b"\n");
                assert!(false, "dentry sb weak corrupted");
            }
        }
        // d_release first, while `self` is still live (Linux __dentry_kill).
        // Diagnostic hardening (NOT the root-cause fix — an active hunt, see
        // `state.md`): a live `Dentry.d_op` has been observed corrupted (a
        // stray write leaves it non-None but pointing well below the kernel
        // half). Every real `&'static DentryOps` lives in the kernel's own
        // static image, always >= `hal::USER_VA_END`; calling through a
        // corrupted value is a wild function-pointer jump (undefined
        // behavior, an unpredictable #PF). Catching it here turns that into
        // a located, diagnosable panic naming the bad address instead.
        // Kernel-target only: `USER_VA_END` splits a kernel-half/user-half
        // address space that only exists under the real `oxide-kernel`
        // target. A hosted test binary's own statics (e.g. a `#[cfg(test)]`
        // `DentryOps`) are ordinary process addresses well below that
        // threshold, so this check unconditionally misfired on every hosted
        // test that ever set a real `d_op` — a false positive, not evidence
        // of corruption, and it SIGABRTs the whole test binary via
        // panic-in-a-destructor. Confirmed by reproducing on a clean `main`
        // checkout with zero unrelated changes present.
        #[cfg(target_os = "oxide-kernel")]
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
