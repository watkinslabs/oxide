use crate::rootfs::{RootfsState, ext4_wrap_ino};

const EXT4_IMMUTABLE_FL: u32 = 0x0000_0010;
const EXT4_NOATIME_FL:   u32 = 0x0000_0080;
const EXT4_QUOTA_FLAGS:  u32 = EXT4_IMMUTABLE_FL | EXT4_NOATIME_FL;

/// Set Linux visible-quota-file protection flags after quota-on. # C: O(1)
pub(super) fn mark_visible_quota_file(st: &RootfsState, inode: &vfs::Inode, ino: u32) -> vfs::KResult<()> {
    let raw = st.mount.read_inode(ino).map_err(|_| vfs::VfsError::Eio)?;
    st.mount.persist_inode_flags_only(ino, raw.i_flags | EXT4_QUOTA_FLAGS).map_err(|_| vfs::VfsError::Eio)?;
    inode.set_i_flags(inode.i_flags() | vfs::S_IMMUTABLE | vfs::S_NOATIME);
    vfs::inode::inode_inc_iversion(inode);
    Ok(())
}

/// Clear Linux visible-quota-file protection flags on quota-off. Hidden quota
/// inodes keep their private ext4 state. # C: O(1) inode IO
pub(super) fn clear_visible_quota_file(st: &RootfsState, ino: u32) -> vfs::KResult<()> {
    let raw = st.mount.read_inode(ino).map_err(|_| vfs::VfsError::Eio)?;
    let raw_now = vfs::inode_times::realtime_now_ns();
    let mut ts = raw_now;
    let mut cached = None;
    if let Some(sb) = st.i_sb() {
        if let Some(inode) = sb.ilookup(ext4_wrap_ino(ino)) {
            ts = vfs::inode_times::current_time(&inode, raw_now);
            cached = Some(inode);
        }
    }
    st.mount.persist_inode_flags_mctime(ino, raw.i_flags & !EXT4_QUOTA_FLAGS, ts, ts).map_err(|_| vfs::VfsError::Eio)?;
    if let Some(inode) = cached {
        inode.set_i_flags(inode.i_flags() & !(vfs::S_IMMUTABLE | vfs::S_NOATIME));
        vfs::inode::inode_inc_iversion(&inode);
        inode.set_times(None, Some(ts), ts)?;
    }
    Ok(())
}
