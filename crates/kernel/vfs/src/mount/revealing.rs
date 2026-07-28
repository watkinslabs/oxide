//! `mount_too_revealing` (`docs/16§6`, Linux `fs/namespace.c`
//! `mount_too_revealing` / `mnt_already_visible`).
//!
//! `mount_capable` decides WHETHER an unprivileged user-namespace holder may
//! mount a filesystem type at all; this decides whether the instance it is about
//! to mount would show MORE than what that namespace can already see. Without
//! it, a task in a container that had `/proc/kcore`, `/proc/sys`, `/proc/sysrq-
//! trigger` … covered by locked mounts simply does `mount -t proc proc /mnt` and
//! reads the originals from a pristine second instance — the classic
//! masked-path escape. `FS_USERNS_MOUNT_RESTRICTED` (procfs, sysfs) is the set
//! of types this applies to.
//!
//! The rule is comparative, not absolute: the mount is allowed iff the namespace
//! ALREADY has a fully-visible mount of the same `file_system_type` that is at
//! least as permissive, and the new mount then INHERITS that instance's locked
//! read-only / atime attributes. Refusing unconditionally would break every
//! legitimate `unshare -Urm --mount-proc`.
//!
//! Deliberately UNGATED (no `target_os` cfg) so `cargo test -p vfs` compiles and
//! runs the decision (`docs/CLAUDE` phantom-test rule). Split out of `mount.rs`
//! to hold the line cap; parent state via `use super::*`.

use super::*;
use crate::fs::FsFlags;
use crate::superblock::{SB_I_RESTRICTED_VARIANT, SB_I_USERNS_REQUIRED};

/// Address identity of two `file_system_type`s — Linux `sb_visible->s_type !=
/// sb->s_type`. The registry mints exactly one `Arc<FsType>` per registered
/// name, so pointer identity IS type identity; the explicit thin-pointer cast
/// keeps this an address comparison regardless of vtable duplication.
/// # C: O(1)
fn same_fs_type(a: &Arc<dyn FileSystemType>, b: &Arc<dyn FileSystemType>) -> bool {
    core::ptr::eq(Arc::as_ptr(a) as *const (), Arc::as_ptr(b) as *const ())
}

/// Linux `mnt_add_to_ns`'s membership test for `ns->mnt_visible_mounts`:
/// `(fs_flags & FS_USERNS_MOUNT_RESTRICTED) && mnt->mnt.mnt_root ==
/// mnt->mnt.mnt_sb->s_root` — the mount must expose the filesystem's WHOLE root,
/// not a bind of some subdirectory of it (a bind of `/proc/self` reveals
/// nothing about `/proc/kcore`, so it cannot vouch for a fresh procfs).
///
/// Read straight off the live mount tree rather than a parallel visible-mount
/// index: Linux keeps the hlist purely to avoid walking the rbtree, and a second
/// structure here would be a split source of truth (`07§5`). Bind clones share
/// the source's dentries, so the comparison is `mnt_root` vs `s_root` — never a
/// dentry-keyed lookup. # C: O(1)
fn is_visible_candidate(m: &Arc<Mount>) -> bool {
    let sb = m.sb();
    if !sb.s_type.fs_flags().contains(FsFlags::FS_USERNS_MOUNT_RESTRICTED) { return false; }
    match (m.mnt_root(), sb.s_root()) {
        (Some(r), Some(s)) => Arc::ptr_eq(&r, &s),
        _ => false,
    }
}

/// Linux `mnt_already_visible`: is there a mount in namespace `ns` of the same
/// `file_system_type` as `sb`, showing the whole filesystem, at least as
/// permissive as the proposed `new_mnt_flags`, and covering nothing with a
/// locked child? Returns the `MNT_LOCK_READONLY`/`MNT_LOCK_ATIME` bits the new
/// mount must inherit from it ("Preserve the locked attributes"), or `None` when
/// no such mount exists.
///
/// The three `continue` ladders below are Linux's, in order:
///   * a RESTRICTED variant (procfs `-o subset=pid`) can vouch for nothing —
///     it does not show the full view itself;
///   * a mount whose read-only or atime policy is LOCKED cannot vouch for a new
///     mount that would not reproduce it, else the caller launders the lock away
///     by mounting a fresh instance;
///   * a mount with any locked child is not FULLY visible — the child is
///     covering something, and Linux only forgives it when the covered directory
///     is a permanently-empty one (`is_empty_dir_inode`, the
///     `proc_create_mount_point` placeholders). This tree has no
///     permanently-empty-directory inode class, so every locked child disqualifies
///     — strictly the safe side of Linux, and the exemption becomes reachable the
///     moment such inodes exist.
/// # C: O(N_ns_mounts × children)
pub fn mnt_already_visible(ns: u64, sb: &Arc<SuperBlock>, new_mnt_flags: u64) -> Option<u32> {
    for m in mounts_in_ns(ns) {
        if !is_visible_candidate(&m) { continue; }
        let vsb = m.sb();
        if !same_fs_type(&vsb.s_type, &sb.s_type) { continue; }
        // "Restricted variants are not compatible with anything, even other
        // restricted variants."
        if vsb.is_restricted_variant() { continue; }
        let opts = m.flags();
        // "Don't miss readonly hidden in the superblock flags."
        let mut lock = m.internal_flags() & MNT_LOCK_MASK;
        if vsb.sb_rdonly() { lock |= MNT_LOCK_READONLY; }
        // "Verify the mount flags are equal to or more permissive than the
        // proposed new mount."
        if lock & MNT_LOCK_READONLY != 0 && new_mnt_flags & MNT_RDONLY == 0 { continue; }
        if lock & MNT_LOCK_ATIME != 0
            && (opts & MNT_ATIME_MASK) != (new_mnt_flags & MNT_ATIME_MASK) { continue; }
        if m.mnt_mounts.lock().iter().any(|c| c.is_locked()) { continue; }
        return Some(lock & (MNT_LOCK_READONLY | MNT_LOCK_ATIME));
    }
    None
}

/// Linux `mount_too_revealing`, as the admission side of a graft: `Ok(lock)`
/// admits the mount and names the `MNT_LOCK_*` bits to stamp on it,
/// `Err(Eperm)` refuses it (Linux `do_new_mount_fc` / `do_fsmount`: "Mount too
/// revealing" → `-EPERM`).
///
/// `new_mnt_flags` is the per-mount `MNT_*` OPTION word the graft would install
/// ([`ms_to_mnt`] / [`mount_attr_to_mnt`]); the lock bits are returned separately
/// because this tree keeps the option mask and the internal `mnt_flags` word in
/// two fields, where Linux has one.
///
/// The four early exits are Linux's, in order: the initial user namespace is
/// unrestricted; a type not marked `FS_USERNS_MOUNT_RESTRICTED` cannot be too
/// revealing; a restricted type that failed to stamp `SB_I_NOEXEC | SB_I_NODEV`
/// is refused outright (Linux `WARN_ONCE` + `return true`); and a
/// `SB_I_RESTRICTED_VARIANT` instance needs no already-visible mount because it
/// does not expose the full view. # C: O(N_ns_mounts × children)
pub fn mount_too_revealing(sb: &Arc<SuperBlock>, new_mnt_flags: u64) -> KResult<u32> {
    let namespace = current_namespace();
    let init_user_ns = namespace_identity::initial(namespace_identity::NamespaceKind::User).pin();
    if namespace_identity::NamespacePin::ptr_eq(&namespace.owner_user_namespace(), &init_user_ns) {
        return Ok(0);
    }
    if !sb.s_type.fs_flags().contains(FsFlags::FS_USERNS_MOUNT_RESTRICTED) { return Ok(0); }
    let s_iflags = sb.s_iflags();
    if s_iflags & SB_I_USERNS_REQUIRED != SB_I_USERNS_REQUIRED { return Err(VfsError::Eperm); }
    if s_iflags & SB_I_RESTRICTED_VARIANT != 0 { return Ok(0); }
    mnt_already_visible(namespace.id(), sb, new_mnt_flags).ok_or(VfsError::Eperm)
}
