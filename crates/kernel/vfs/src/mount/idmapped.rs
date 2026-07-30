//! Idmapped-mount installation (`fs/namespace.c` `can_idmap_mount` /
//! `mount_setattr_prepare` / `mount_setattr_commit`).
//!
//! The uid/gid map itself is immutable. Only its `Arc` on a mount changes, and
//! only while that mount is detached from a userspace-visible namespace tree.
//! Detached option, propagation and idmap changes are prepared across the
//! whole requested subtree before any field is committed.

use alloc::sync::Arc;

use super::*;

/// Filesystem-level idmap admission shared by an open_tree clone and the
/// deferred `fsmount` representation. # C: O(1)
pub fn can_idmap_superblock(sb: &SuperBlock) -> KResult<()> {
    if !sb.s_type.fs_flags().contains(crate::fs::FsFlags::FS_ALLOW_IDMAP) {
        return Err(VfsError::Einval);
    }
    if sb.sb_has_iflag(crate::superblock::SB_I_NOIDMAP) {
        return Err(VfsError::Einval);
    }
    Ok(())
}

fn recalc(m: &Mount, set: u64, clr: u64) -> u64 {
    (m.flags() & !(clr & MNT_OPTION_MASK)) | (set & MNT_OPTION_MASK)
}

/// Prepare and atomically commit one `mount_setattr` request on an unpublished
/// open_tree clone. Linux permits first-time idmap installation only while the
/// mount is in its anonymous detached namespace; a second install is `EPERM`.
/// `AT_RECURSIVE` selects the whole detached subtree, otherwise only its root.
///
/// All fallible checks run before the first write, matching Linux's
/// `mount_setattr_prepare` then `mount_setattr_commit` two-pass transaction.
/// # C: O(selected mounts)
pub fn mnt_setattr_detached_tree(
    tree: &DetachedMountTree,
    set: u64,
    clr: u64,
    idmap: Option<Arc<crate::idmap::Idmap>>,
    controls_superblock: bool,
    propagation: Option<Propagation>,
    recursive: bool,
) -> KResult<()> {
    if tree.is_empty() { return Err(VfsError::Einval); }
    let _write = MOUNT_WRITE.lock();

    for (index, node) in tree.iter().enumerate() {
        if !recursive && index != 0 { continue; }
        let new = recalc(&node.m, set, clr);
        if !can_change_locked_flags(&node.m, new) { return Err(VfsError::Eperm); }
        if let Some(map) = idmap.as_ref() {
            if map.is_identity() { return Err(VfsError::Einval); }
            if !node.m.idmap().is_identity() { return Err(VfsError::Eperm); }
            can_idmap_superblock(node.m.sb())?;
            if !controls_superblock { return Err(VfsError::Eperm); }
        }
    }

    for (index, node) in tree.iter().enumerate() {
        if !recursive && index != 0 { continue; }
        write_mnt_attrs(&node.m, set, clr);
        if let Some(map) = idmap.as_ref() { node.m.install_idmap(map.clone()); }
        if let Some(kind) = propagation { propagation::apply_propagation(&node.m, kind); }
    }
    Ok(())
}

/// Prepare and commit the non-idmap portion of `mount_setattr` on a visible
/// mount. Locked-option and writer checks cover the complete selected subtree
/// before options or propagation change, so a failure cannot leave a partial
/// transition. Idmap installation is intentionally absent: Linux rejects an
/// idmap change once a mount has been visible. # C: O(selected mounts)
pub fn mnt_setattr_attached(
    top_id: u64,
    set: u64,
    clr: u64,
    propagation: Option<Propagation>,
    recursive: bool,
) -> KResult<()> {
    let _write = MOUNT_WRITE.lock();
    let top = mount_by_id(top_id).ok_or(VfsError::Einval)?;
    if !check_mnt(&top) { return Err(VfsError::Einval); }
    let namespace_id = top.namespace_id();
    let mounts = if recursive {
        subtree_ids(namespace_id, top_id).into_iter()
            .filter_map(mount_by_id).collect::<Vec<_>>()
    } else {
        alloc::vec![top]
    };

    for mount in mounts.iter() {
        let old = mount.flags();
        let new = (old & !(clr & MNT_OPTION_MASK)) | (set & MNT_OPTION_MASK);
        if !can_change_locked_flags(mount, new) { return Err(VfsError::Eperm); }
        if set & MNT_RDONLY != 0 && old & MNT_RDONLY == 0
            && mount.mnt_writers.load(Ordering::Acquire) > 0 {
            return Err(VfsError::Ebusy);
        }
    }
    for mount in mounts.iter() {
        write_mnt_attrs(mount, set, clr);
        if let Some(kind) = propagation { propagation::apply_propagation(mount, kind); }
    }
    mntns::bump_gen(namespace_id);
    Ok(())
}
