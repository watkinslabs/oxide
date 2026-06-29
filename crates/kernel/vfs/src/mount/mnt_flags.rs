//! `mnt_flags` model (`docs/16§6`, Linux `include/linux/mount.h`).
//!
//! TWO disjoint flag spaces ride a `Mount`:
//!   * the MS_*-valued OPTION mask in `Mount.flags` (RDONLY/NOSUID/NODEV/NOEXEC/
//!     atime policy …), set by `mount(2)`/`remount` — typed readback here;
//!   * the kernel-INTERNAL `mnt_flags` bit set in `Mount.mnt_internal_flags`
//!     (MNT_LOCKED/MNT_INTERNAL/MNT_DOOMED/MNT_MARKED/MNT_UMOUNT) never exposed
//!     to userspace — Linux real values, plus the synthetic MNT_EXPIRE_MARK
//!     standing in for Linux's separate `int mnt_expiry_mark`.
//!
//! Split out of `mount.rs` to hold the line cap; parent state reached via
//! `use super::*`. The internal-flag word is mutated by per-bit atomic
//! `fetch_or`/`fetch_and` (each bit gives xchg semantics, matching the
//! `xchg(&mnt->mnt_expiry_mark, 1)` Linux uses).

use super::*;

// --- Kernel-internal mnt_flags (Linux include/linux/mount.h real values). ---
/// Kernel-internal mount (rootfs / kern_mount); never user-visible, never
/// auto-expired. Linux `MNT_INTERNAL`.
pub const MNT_INTERNAL: u32 = 0x4000;
/// Mount locked to its parent: an unprivileged userns may not unmount or move
/// it, and a clone keeps the bit. Linux `MNT_LOCKED`.
pub const MNT_LOCKED: u32 = 0x80_0000;
/// Mount is being torn down (`umount_tree` in progress). Linux `MNT_DOOMED`.
pub const MNT_DOOMED: u32 = 0x100_0000;
/// Transient propagation-walk mark (Linux `MNT_MARKED`); cleared after a pass.
pub const MNT_MARKED: u32 = 0x400_0000;
/// Queued onto the umount list (Linux `MNT_UMOUNT`).
pub const MNT_UMOUNT: u32 = 0x800_0000;
/// Expiry mark (`mark_mounts_for_expiry`). Linux carries this in a SEPARATE
/// `int mnt_expiry_mark`; modelled here as one bit so the whole internal-flag
/// word stays a single atomic. Set on the first sweep, reaps on the second if
/// still unmarked-cleared by use. Top bit, disjoint from every real value.
pub const MNT_EXPIRE_MARK: u32 = 0x8000_0000;

/// Per-mount atime update policy (Linux `__atime_needs_update`), derived from
/// the MS_*-valued option mask. Default since 2.6.30 is relatime.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AtimePolicy { Strict, Relatime, Noatime }

impl Mount {
    // --- Typed OPTION-mask readback (Linux `mnt_flags & MNT_*`). ---
    /// Mount is read-only (`MNT_RDONLY`). # C: O(1)
    pub fn is_readonly(&self) -> bool { self.flags() & MNT_RDONLY != 0 }
    /// set-user-ID / set-group-ID bits ignored on exec (`MNT_NOSUID`). # C: O(1)
    pub fn is_nosuid(&self) -> bool { self.flags() & MNT_NOSUID != 0 }
    /// Device nodes not interpreted (`MNT_NODEV`). # C: O(1)
    pub fn is_nodev(&self) -> bool { self.flags() & MNT_NODEV != 0 }
    /// Execution of binaries disallowed (`MNT_NOEXEC`). # C: O(1)
    pub fn is_noexec(&self) -> bool { self.flags() & MNT_NOEXEC != 0 }
    /// atime never updated (`MNT_NOATIME`). # C: O(1)
    pub fn is_noatime(&self) -> bool { self.flags() & MNT_NOATIME != 0 }
    /// Directory atime never updated (`MNT_NODIRATIME`). # C: O(1)
    pub fn is_nodiratime(&self) -> bool { self.flags() & MNT_NODIRATIME != 0 }
    /// Relative atime policy (`MNT_RELATIME`). # C: O(1)
    pub fn is_relatime(&self) -> bool { self.flags() & MNT_RELATIME != 0 }
    /// Strict atime policy (`MNT_STRICTATIME`). # C: O(1)
    pub fn is_strictatime(&self) -> bool { self.flags() & MNT_STRICTATIME != 0 }

    /// Resolved atime policy (Linux precedence): NOATIME wins, then explicit
    /// RELATIME, then explicit STRICTATIME, else the kernel relatime default.
    /// # C: O(1)
    pub fn atime_policy(&self) -> AtimePolicy {
        let f = self.flags();
        if f & MNT_NOATIME != 0 { AtimePolicy::Noatime }
        else if f & MNT_RELATIME != 0 { AtimePolicy::Relatime }
        else if f & MNT_STRICTATIME != 0 { AtimePolicy::Strict }
        else { AtimePolicy::Relatime }
    }

    // --- Kernel-INTERNAL mnt_flags accessors (xchg-equivalent per bit). ---
    /// Snapshot the internal `mnt_flags` word. # C: O(1)
    pub fn internal_flags(&self) -> u32 { self.mnt_internal_flags.load(Ordering::Acquire) }
    /// Set internal `mnt_flags` bit(s); returns the PRIOR word (xchg-equivalent
    /// for the set bits). # C: O(1)
    pub fn set_internal_flag(&self, bits: u32) -> u32 {
        self.mnt_internal_flags.fetch_or(bits, Ordering::AcqRel)
    }
    /// Clear internal `mnt_flags` bit(s); returns the PRIOR word. # C: O(1)
    pub fn clear_internal_flag(&self, bits: u32) -> u32 {
        self.mnt_internal_flags.fetch_and(!bits, Ordering::AcqRel)
    }
    /// True iff every bit in `bits` is set. # C: O(1)
    pub fn has_internal_flag(&self, bits: u32) -> bool { self.internal_flags() & bits == bits }
    /// `MNT_LOCKED` (clone-preserved; unprivileged userns may not unmount/move).
    /// # C: O(1)
    pub fn is_locked(&self) -> bool { self.internal_flags() & MNT_LOCKED != 0 }
    /// `MNT_INTERNAL` (kernel mount, never user-visible / never auto-expired).
    /// # C: O(1)
    pub fn is_internal(&self) -> bool { self.internal_flags() & MNT_INTERNAL != 0 }
    /// `MNT_DOOMED` (tear-down in progress). # C: O(1)
    pub fn is_doomed(&self) -> bool { self.internal_flags() & MNT_DOOMED != 0 }
}
