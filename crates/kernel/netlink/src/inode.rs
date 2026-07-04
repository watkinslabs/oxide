extern crate alloc;

use alloc::sync::Arc;

use crate::NetlinkSocket;

/// `ino()` high tag identifying a netlink socket inode (so its inode numbers
/// don't collide with fs / AF_INET socket inode space). # C: O(1)
pub const NETLINK_INO_TAG: u64 = 0x4E4C_534B_0000_0000;

/// `file_operations` for a netlink-socket inode — delegates the data path to
/// the `NetlinkSocket` stored in `i_private`.
struct NetlinkFileOps;

impl vfs::FileOps for NetlinkFileOps {
    fn read(&self, inode: &vfs::Inode, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        match inode.private::<NetlinkSocket>() {
            Some(s) => s.read(buf),
            None => Err(vfs::VfsError::Einval),
        }
    }

    fn write(&self, inode: &vfs::Inode, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        match inode.private::<NetlinkSocket>() {
            Some(s) => s.write(buf),
            None => Err(vfs::VfsError::Einval),
        }
    }

    fn poll(&self, inode: &vfs::Inode) -> u32 {
        inode.private::<NetlinkSocket>().map(|s| s.poll()).unwrap_or(vfs::POLL_OUT)
    }
}

/// Build the `Arc<Inode>` wrapping a netlink socket fd.
/// # C: O(1)
pub fn make_netlink_socket_inode(sock: Arc<NetlinkSocket>) -> vfs::InodeRef {
    let ino = NETLINK_INO_TAG | (Arc::as_ptr(&sock) as u64 & 0xFFFF_FFFF);
    let subs = sock.poll_subs.clone();
    vfs::InodeBuilder::new(
        ino,
        vfs::mk_mode(vfs::FileType::Socket, 0o600),
        vfs::default_inode_ops(),
        Arc::new(NetlinkFileOps),
    )
    .private(sock)
    .poll_subs_arc(subs)
    .build()
}

/// Recover the `&NetlinkSocket` stored in a netlink-socket inode's `i_private`.
/// # C: O(1)
pub fn netlink_from_inode(inode: &vfs::Inode) -> Option<&NetlinkSocket> {
    inode.private::<NetlinkSocket>()
}

/// Recover an owning `Arc<NetlinkSocket>` from a netlink-socket inode. # C: O(1)
pub fn netlink_arc_from_inode(inode: &vfs::InodeRef) -> Option<Arc<NetlinkSocket>> {
    inode.i_private().clone().downcast::<NetlinkSocket>().ok()
}
