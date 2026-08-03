//! Idmapped-mount installation: the per-mount admission ladder plus the
//! prepare/commit transaction that applies a `mount_setattr` request.
//!
//! The uid/gid map itself is immutable. Only its `Arc` on a mount changes, and
//! only while that mount is unreachable from any userspace-visible namespace
//! tree. Detached option, propagation and idmap changes are prepared across the
//! whole requested subtree before any field is committed.
//!
//! Two callers reach the same ladder from opposite directions — a path in a
//! live mount namespace, and a detached clone or deferred `fsmount` object — so
//! the ladder is a pure decision over sampled facts ([`can_idmap_mount`]) and
//! the ORDER of its rungs is a hosted unit test rather than a property of
//! whichever call site happens to run.

use alloc::sync::Arc;

use super::*;

/// A prepared idmap change: the map to install plus the facts the per-mount
/// ladder needs about how it was obtained.
pub struct IdmapSet {
    /// The map to install. The identity map is a REMOVAL, not a no-op request.
    pub map: Arc<crate::idmap::Idmap>,
    /// User namespace the map was derived from. `None` for a removal, which
    /// resolves no namespace at all.
    pub userns: Option<namespace_identity::NamespacePin>,
    /// Caller may overwrite an existing map, not merely install a first one.
    pub replace: bool,
    /// `CAP_SYS_ADMIN` held over the superblock's owning user namespace.
    pub controls_superblock: bool,
}

/// The facts [`can_idmap_mount`] decides over, sampled from one mount.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IdmapFacts {
    /// An idmap change was requested at all.
    pub requested: bool,
    /// The requested map's user namespace IS the one the superblock's on-disk
    /// ids are already expressed in, so the mapping would be a tautology.
    pub userns_is_sb_user_ns: bool,
    /// Caller may overwrite an existing map.
    pub replace: bool,
    /// The mount already carries a non-identity map.
    pub already_idmapped: bool,
    /// The filesystem type opts in to idmapped mounts.
    pub fs_allow_idmap: bool,
    /// This instance has turned idmapped mounts off.
    pub sb_noidmap: bool,
    /// `CAP_SYS_ADMIN` over the superblock's owning user namespace.
    pub controls_superblock: bool,
    /// The mount lives in an anonymous namespace, i.e. has never been
    /// reachable from a userspace-visible mount tree.
    pub anon_ns: bool,
}

/// Per-mount idmap admission. The rung ORDER is the whole observable contract
/// of a refusal, and it separates two distinct refusals that a caller uses to
/// tell apart "this kernel/filesystem cannot" from "you may not":
///
/// * a tautological mapping, a filesystem that does not support idmapping, an
///   instance that switched it off, and a mount already visible in a namespace
///   are all EINVAL;
/// * overwriting an existing map without the replace mode, and acting without
///   `CAP_SYS_ADMIN` over the superblock's user namespace, are EPERM.
///
/// The already-idmapped rung precedes the filesystem-support rungs, so a
/// second install on a supported filesystem reports EPERM rather than being
/// masked by anything below it. The visibility rung is LAST, so a request that
/// is malformed for any other reason reports that reason even when aimed at an
/// attached mount. # C: O(1)
pub fn can_idmap_mount(f: IdmapFacts) -> KResult<()> {
    if !f.requested { return Ok(()); }
    if f.userns_is_sb_user_ns { return Err(VfsError::Einval); }
    if !f.replace && f.already_idmapped { return Err(VfsError::Eperm); }
    if !f.fs_allow_idmap { return Err(VfsError::Einval); }
    if f.sb_noidmap { return Err(VfsError::Einval); }
    if !f.controls_superblock { return Err(VfsError::Eperm); }
    if !f.anon_ns { return Err(VfsError::Einval); }
    Ok(())
}

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

/// Sample the superblock-derived half of [`IdmapFacts`] for one mount, so a
/// call site cannot get the fs-support and tautology rungs subtly different
/// from the other call site. `anon_ns` stays with the caller: only it knows
/// whether the mount it holds is attached. # C: O(1)
pub fn idmap_facts_for(sb: &SuperBlock, req: &IdmapSet, already_idmapped: bool, anon_ns: bool)
                       -> IdmapFacts {
    IdmapFacts {
        requested: true,
        userns_is_sb_user_ns: req.userns.as_ref()
            .map(|ns| namespace_identity::NamespacePin::ptr_eq(ns, &sb.s_user_ns))
            .unwrap_or(false),
        replace: req.replace,
        already_idmapped,
        fs_allow_idmap: sb.s_type.fs_flags().contains(crate::fs::FsFlags::FS_ALLOW_IDMAP),
        sb_noidmap: sb.sb_has_iflag(crate::superblock::SB_I_NOIDMAP),
        controls_superblock: req.controls_superblock,
        anon_ns,
    }
}

fn recalc(m: &Mount, set: u64, clr: u64) -> u64 {
    (m.flags() & !(clr & MNT_OPTION_MASK)) | (set & MNT_OPTION_MASK)
}

/// Prepare and atomically commit one `mount_setattr` request on an unpublished
/// open_tree clone. Such a tree is in an anonymous namespace, which is the one
/// place an idmap may be installed at all — and, with the replace mode, the one
/// place an existing idmap may be overwritten or removed. `AT_RECURSIVE`
/// selects the whole detached subtree, otherwise only its root.
///
/// All fallible checks run before the first write, so a refusal anywhere in the
/// subtree leaves every mount in it untouched. # C: O(selected mounts)
pub fn mnt_setattr_detached_tree(
    tree: &DetachedMountTree,
    set: u64,
    clr: u64,
    idmap: Option<IdmapSet>,
    propagation: Option<Propagation>,
    recursive: bool,
) -> KResult<()> {
    if tree.is_empty() { return Err(VfsError::Einval); }
    let _write = MOUNT_WRITE.lock();

    for (index, node) in tree.iter().enumerate() {
        if !recursive && index != 0 { continue; }
        let new = recalc(&node.m, set, clr);
        if !can_change_locked_flags(&node.m, new) { return Err(VfsError::Eperm); }
        if let Some(req) = idmap.as_ref() {
            let already = !node.m.idmap().is_identity();
            can_idmap_mount(idmap_facts_for(node.m.sb(), req, already, true))?;
        }
    }

    for (index, node) in tree.iter().enumerate() {
        if !recursive && index != 0 { continue; }
        write_mnt_attrs(&node.m, set, clr);
        if let Some(req) = idmap.as_ref() { node.m.install_idmap(req.map.clone()); }
        if let Some(kind) = propagation { propagation::apply_propagation(&node.m, kind); }
    }
    Ok(())
}

/// Prepare and commit the non-idmap portion of `mount_setattr` on a visible
/// mount. Locked-option and writer checks cover the complete selected subtree
/// before options or propagation change, so a failure cannot leave a partial
/// transition. Idmap installation is intentionally absent: [`can_idmap_mount`]
/// refuses every idmap change on a mount that is not in an anonymous
/// namespace, so the syscall layer never reaches this transaction with one.
/// # C: O(selected mounts)
pub fn mnt_setattr_attached(
    top_id: u64,
    set: u64,
    clr: u64,
    propagation: Option<Propagation>,
    recursive: bool,
) -> KResult<()> {
    let _write = MOUNT_WRITE.lock();
    let top = mount_by_id(top_id).ok_or(VfsError::Einval)?;
    // A DETACHED mount is settable too. The reference's `do_mount_setattr`
    // checks only that the path names a mount ROOT — it has no namespace test
    // at all — because the whole point of the new mount API is
    // `fsmount` → `mount_setattr` → `move_mount`: the attributes are applied
    // while the mount still lives in the anonymous namespace `fsmount` put it
    // in, BEFORE it is grafted anywhere. Requiring the caller's namespace
    // refused every one of those, so `mount -o nosuid,nodev,noexec` failed for
    // every filesystem the service manager mounts that way — four mount units
    // at boot. Reaching the mount at all already proves access: it was named
    // either by a path the caller can resolve or by a descriptor it holds.
    if !check_mnt(&top) && !super::anon_ns_root(&top) { return Err(VfsError::Einval); }
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

#[cfg(test)]
mod tests;
