use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::rootfs::RootfsState;

use crate::inode::Inode;

use super::backend::{
    Ext4QuotaOps, QT_TREEOFF, detect_format, ops_as_ext4, quota_ino, read_file_info, read_info,
    read_quota_inode,
};
use super::cleanup::mark_visible_quota_file;
use super::scan::collect_tree;

/// Enable ext4 quota from a hidden inode or a Linux quotactl path. # C: O(quota-file)
pub fn quota_on_ext4(st: &Arc<RootfsState>, sb: &vfs::SuperBlock, kind: vfs::QuotaType, fmt: u32, path: Option<&vfs::VfsPath>) -> vfs::KResult<()> {
    let ino = match path {
        Some(p) => quota_path_ino(sb, p)?,
        None => quota_ino(&st.mount, kind)?,
    };
    quota_on_inode(st, sb, kind, fmt, ino, path.is_none(), false)?;
    if let Some(p) = path {
        let ops = sb.s_dquot.operations(kind).ok_or(vfs::VfsError::Einval)?;
        let ext4 = ops_as_ext4(ops.as_ref()).ok_or(vfs::VfsError::Einval)?;
        match mark_visible_quota_file(st, &p.inode, ino) {
            Ok(flags) => ext4.remember_visible_orig_flags(kind, flags),
            Err(e) => {
                if let Err(rb) = rollback_quota_on(sb, kind, ext4) { return Err(rb); }
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Enable a journalled (visible) quota file named by the mount options.
///
/// Same visible-file handling as the quotactl path — the quota file gains the
/// immutable/noatime protection flags — but the file is reached by inode
/// number resolved in the filesystem root rather than by a namespace path,
/// because at mount time the filesystem is not yet attached anywhere.
/// # C: O(quota-file)
pub fn quota_on_journalled(st: &Arc<RootfsState>, sb: &vfs::SuperBlock, kind: vfs::QuotaType, fmt: u32, ino: u32, allow_readonly: bool) -> vfs::KResult<()> {
    quota_on_inode(st, sb, kind, fmt, ino, false, allow_readonly)?;
    let ops = sb.s_dquot.operations(kind).ok_or(vfs::VfsError::Einval)?;
    let ext4 = ops_as_ext4(ops.as_ref()).ok_or(vfs::VfsError::Einval)?;
    let inode = st.wrap_any_ino(ino).ok_or(vfs::VfsError::Eio)?;
    match mark_visible_quota_file(st, &inode, ino) {
        Ok(flags) => { ext4.remember_visible_orig_flags(kind, flags); Ok(()) }
        Err(e) => {
            if let Err(rb) = rollback_quota_on(sb, kind, ext4) { return Err(rb); }
            Err(e)
        }
    }
}

/// Enable ext4 hidden quota inode for one quota class. # C: O(quota-file)
pub fn quota_on_hidden(st: &Arc<RootfsState>, sb: &vfs::SuperBlock, kind: vfs::QuotaType, fmt: u32) -> vfs::KResult<()> {
    quota_on_ext4(st, sb, kind, fmt, None)
}

/// Enable a hidden quota inode during RO→RW remount before `SB_RDONLY` is
/// cleared on the live superblock. # C: O(quota-file)
pub fn quota_on_hidden_remount(st: &Arc<RootfsState>, sb: &vfs::SuperBlock, kind: vfs::QuotaType, fmt: u32) -> vfs::KResult<()> {
    let ino = quota_ino(&st.mount, kind)?;
    quota_on_inode(st, sb, kind, fmt, ino, true, true)
}

fn quota_path_ino(sb: &vfs::SuperBlock, path: &vfs::VfsPath) -> vfs::KResult<u32> {
    let psb = path.inode.i_sb().ok_or(vfs::VfsError::Enodev)?;
    if psb.s_dev != sb.s_dev { return Err(vfs::VfsError::Exdev); }
    quota_inode_preflight(sb, &path.inode, None)?;
    Ok(path.inode.ino() as u32)
}

fn quota_on_inode(st: &Arc<RootfsState>, sb: &vfs::SuperBlock, kind: vfs::QuotaType, fmt: u32, ino: u32, hidden: bool, allow_readonly: bool) -> vfs::KResult<()> {
    let inode = read_quota_inode(&st.mount, ino)?;
    quota_raw_inode_preflight(sb, &inode, kind, allow_readonly)?;
    let fmt = if hidden && fmt == 0 { detect_format(&st.mount, &inode, kind)? } else { fmt };
    if fmt != vfs::QFMT_VFS_V0 && fmt != vfs::QFMT_VFS_V1 { return Err(vfs::VfsError::Einval); }
    let qi = read_info(&st.mount, &inode, kind, fmt)?;
    let mut info = read_file_info(&st.mount, &inode)?;
    if hidden { info.dqi_flags |= vfs::DQF_SYS_FILE; }
    let mut loaded = Vec::new();
    collect_tree(&st.mount, &inode, &qi, kind, QT_TREEOFF, 0, 0, &mut loaded)?;
    let ops = match sb.s_dquot.any_operations() {
        Some(existing) => existing,
        None => Arc::new(Ext4QuotaOps::new(st.clone())),
    };
    let ext4 = ops_as_ext4(ops.as_ref()).ok_or(vfs::VfsError::Einval)?;
    vfs::quota_on(sb, kind, fmt, ops.clone())?;
    ext4.set_file(kind, ino, fmt, hidden);
    sb.s_dquot.load_info(kind, info);
    for (qid, off, dqblk) in loaded {
        ext4.remember_offset(qid, off);
        let dq = match sb.s_dquot.dqget(qid) {
            Ok(dq) => dq,
            Err(e) => {
                if let Err(rb) = rollback_quota_on(sb, kind, ext4) { return Err(rb); }
                return Err(e);
            }
        };
        dq.set_dqblk(dqblk);
        sb.s_dquot.dqput(dq);
    }
    Ok(())
}

fn rollback_quota_on(sb: &vfs::SuperBlock, kind: vfs::QuotaType, ext4: &Ext4QuotaOps) -> vfs::KResult<()> {
    let mut first = Ok(());
    for dq in sb.s_dquot.dquots().by_kind(kind) {
        if let Err(e) = sb.s_dquot.drop_inactive_dquot(dq) {
            if first.is_ok() { first = Err(e); }
        }
    }
    sb.s_dquot.disable(kind);
    sb.s_dquot.clear_info(kind);
    sb.s_dquot.clear_operations(kind);
    ext4.forget_file(kind);
    first
}

fn quota_inode_preflight(sb: &vfs::SuperBlock, inode: &vfs::Inode, kind: Option<vfs::QuotaType>) -> vfs::KResult<()> {
    if inode.is_freeing() { return Err(vfs::VfsError::Euclean); }
    if inode.file_type() != vfs::FileType::Regular { return Err(vfs::VfsError::Eacces); }
    if sb.sb_rdonly() { return Err(vfs::VfsError::Erofs); }
    if kind.is_some_and(|k| sb.s_dquot.is_enabled(k)) { return Err(vfs::VfsError::Ebusy); }
    if inode.i_flags() & vfs::inode::S_ENCRYPTED != 0 { return Err(vfs::VfsError::Einval); }
    Ok(())
}

fn quota_raw_inode_preflight(sb: &vfs::SuperBlock, inode: &Inode, kind: vfs::QuotaType, allow_readonly: bool) -> vfs::KResult<()> {
    if !inode.is_reg() { return Err(vfs::VfsError::Eacces); }
    if sb.sb_rdonly() && !allow_readonly { return Err(vfs::VfsError::Erofs); }
    if sb.s_dquot.is_enabled(kind) { return Err(vfs::VfsError::Ebusy); }
    if inode.i_flags & vfs::inode::S_ENCRYPTED != 0 { return Err(vfs::VfsError::Einval); }
    Ok(())
}
