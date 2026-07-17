use crate::mount::Mount;
use super::state::RootfsState;

/// Charge quota for a soon-to-exist ext4 inode. # C: O(1)+VFS quota
pub(crate) fn charge_new_inode(st: &RootfsState, parent_ino: u32, mode: u16, uid: u32, gid: u32) -> vfs::KResult<()> {
    let Some(sb) = st.i_sb() else { return Ok(()); };
    let projid = inherited_projid(&st.mount, parent_ino, mode)?;
    vfs::dquot_alloc_inode(&sb, uid, gid, projid, vfs::DquotUsage::inode(0, 0))
}

/// Roll back a pre-create inode quota charge. # C: O(1)+VFS quota
pub(crate) fn release_new_inode_charge(st: &RootfsState, parent_ino: u32, mode: u16, uid: u32, gid: u32) -> vfs::KResult<()> {
    let Some(sb) = st.i_sb() else { return Ok(()); };
    let projid = inherited_projid(&st.mount, parent_ino, mode)?;
    vfs::dquot_free_inode(&sb, uid, gid, projid, vfs::DquotUsage::inode(0, 0))
}

/// Roll back a pre-create inode charge and retry once if quota dirtying failed. # C: O(1)+VFS quota
pub(crate) fn rollback_new_inode_charge(st: &RootfsState, parent_ino: u32, mode: u16, uid: u32, gid: u32) -> vfs::KResult<()> {
    match release_new_inode_charge(st, parent_ino, mode, uid, gid) {
        Ok(()) => Ok(()),
        Err(_) => release_new_inode_charge(st, parent_ino, mode, uid, gid),
    }
}

/// Release quota for an ext4 inode that lost its final link. # C: O(1)+VFS quota
pub(crate) fn release_existing_inode(st: &RootfsState, ino: u32, raw: &crate::Inode) -> vfs::KResult<()> {
    release_existing_inode_usage(st, raw)?;
    drop_existing_inode_dquots(st, ino);
    Ok(())
}

/// Release existing inode quota after committed deletion, retrying dirty failure once. # C: O(1)+VFS quota
pub(crate) fn release_existing_inode_retry(st: &RootfsState, ino: u32, raw: &crate::Inode) -> vfs::KResult<()> {
    match release_existing_inode_usage(st, raw) {
        Ok(()) => {
            drop_existing_inode_dquots(st, ino);
            Ok(())
        }
        Err(_) => {
            release_existing_inode_usage(st, raw)?;
            drop_existing_inode_dquots(st, ino);
            Ok(())
        }
    }
}

/// Release complete inode quota usage without detaching cached dquots. # C: O(1)+VFS quota
pub(crate) fn release_existing_inode_usage(st: &RootfsState, raw: &crate::Inode) -> vfs::KResult<()> {
    let Some(sb) = st.i_sb() else { return Ok(()); };
    let usage = vfs::DquotUsage { space: raw.i_blocks.saturating_mul(512), reserved_space: 0, inodes: 1 };
    vfs::dquot_free_inode(&sb, raw.uid, raw.gid, raw.i_projid, usage)
}

/// Roll back a pre-release of complete existing inode usage. # C: O(1)+VFS quota
pub(crate) fn recharge_existing_inode_usage(st: &RootfsState, raw: &crate::Inode) -> vfs::KResult<()> {
    let Some(sb) = st.i_sb() else { return Ok(()); };
    let usage = vfs::DquotUsage { space: raw.i_blocks.saturating_mul(512), reserved_space: 0, inodes: 1 };
    vfs::dquot_alloc_inode(&sb, raw.uid, raw.gid, raw.i_projid, usage)
}

/// Roll back a pre-release and retry once if quota dirtying failed. # C: O(1)+VFS quota
pub(crate) fn rollback_existing_inode_release(st: &RootfsState, raw: &crate::Inode) -> vfs::KResult<()> {
    match recharge_existing_inode_usage(st, raw) {
        Ok(()) => Ok(()),
        Err(_) => recharge_existing_inode_usage(st, raw),
    }
}

/// Drop cached dquot attachments after final deletion commits. # C: O(1)
pub(crate) fn drop_existing_inode_dquots(st: &RootfsState, ino: u32) {
    let Some(sb) = st.i_sb() else { return; };
    if let Some(victim) = sb.ilookup(super::inode::ext4_wrap_ino(ino)) { vfs::dquot_drop(&victim); }
}

/// Pre-release final-link quota without dropping cached dquots. # C: O(1)+VFS quota
pub(crate) fn pre_release_existing_inode_if_final(st: &RootfsState, raw: &crate::Inode) -> vfs::KResult<bool> {
    if raw.links_count <= 1 { release_existing_inode_usage(st, raw)?; Ok(true) } else { Ok(false) }
}

/// Transfer existing inode usage to a new project quota id. # C: O(1)+VFS quota
pub(crate) fn transfer_project_inode(st: &RootfsState, inode: &vfs::Inode, raw: &crate::Inode, projid: u32) -> vfs::KResult<()> {
    let usage = vfs::DquotUsage { space: raw.i_blocks.saturating_mul(512), reserved_space: 0, inodes: 1 };
    vfs::dquot_transfer_inode(inode, usage, vfs::DquotTransferIds { uid: None, gid: None, projid: Some(projid) })
}

/// Roll back a project-id transfer, retrying once if quota dirtying failed. # C: O(MAXQUOTAS log N)+FS
pub(crate) fn rollback_project_inode_transfer(st: &RootfsState, inode: &vfs::Inode, raw: &crate::Inode, projid: u32) -> vfs::KResult<()> {
    match transfer_project_inode(st, inode, raw, projid) {
        Ok(()) => Ok(()),
        Err(_) => transfer_project_inode(st, inode, raw, projid),
    }
}

fn inherited_projid(mount: &Mount, parent_ino: u32, _mode: u16) -> vfs::KResult<u32> {
    if !mount.sb.has_project() { return Ok(0); }
    let parent = mount.read_inode(parent_ino).map_err(|_| vfs::VfsError::Eio)?;
    if parent.i_flags & vfs::inode::FS_PROJINHERIT_FL == 0 { return Ok(0); }
    Ok(parent.i_projid)
}
