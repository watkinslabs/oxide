extern crate alloc;

use alloc::sync::Arc;

use crate::NetlinkSocket;

/// `ino()` high tag identifying a netlink socket inode (so its inode numbers
/// don't collide with fs / AF_INET socket inode space). # C: O(1)
pub const NETLINK_INO_TAG: u64 = 0x4E4C_534B_0000_0000;
pub const NETLINK_INO_ID_MASK: u64 = 0xFFFF_FFFF;

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

    fn read_file(&self, file: &vfs::File, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let Some(s) = file.inode().private::<NetlinkSocket>() else { return Err(vfs::VfsError::Einval); };
        loop {
            match s.receive(false) {
                crate::ReceiveState::Datagram(dgram) => {
                    let n = dgram.bytes.len().min(buf.len());
                    buf[..n].copy_from_slice(&dgram.bytes[..n]);
                    return Ok(n);
                }
                crate::ReceiveState::Error(errno) => return Err(match errno {
                    x if x == vfs::VfsError::Enobufs as i32 => vfs::VfsError::Enobufs,
                    x if x == vfs::VfsError::Econnreset as i32 => vfs::VfsError::Econnreset,
                    _ => vfs::VfsError::Eio,
                }),
                crate::ReceiveState::Empty => {
                    #[cfg(target_os = "oxide-kernel")]
                    {
                        if s.arm_receive_wait() {
                            // SAFETY: this syscall process is parked through the socket wait owner.
                            unsafe { sched::live::schedule::schedule(); }
                            s.waiters.remove_current();
                        }
                        continue;
                    }
                    #[cfg(not(target_os = "oxide-kernel"))]
                    { return Ok(0); }
                }
            }
        }
    }

    fn read_nonblock_file(&self, file: &vfs::File, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let Some(s) = file.inode().private::<NetlinkSocket>() else { return Err(vfs::VfsError::Einval); };
        match s.receive(false) {
            crate::ReceiveState::Datagram(dgram) => {
                let n = dgram.bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&dgram.bytes[..n]);
                Ok(n)
            }
            crate::ReceiveState::Error(errno) => Err(if errno == vfs::VfsError::Enobufs as i32 {
                vfs::VfsError::Enobufs
            } else { vfs::VfsError::Eio }),
            crate::ReceiveState::Empty => Err(vfs::VfsError::Eagain),
        }
    }

    fn write(&self, inode: &vfs::Inode, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        match inode.private::<NetlinkSocket>() {
            Some(s) => s.write(buf),
            None => Err(vfs::VfsError::Einval),
        }
    }

    fn write_iter_file(&self, file: &vfs::File, _off: u64, bufs: &[&[u8]], _nonblock: bool) -> vfs::KResult<usize> {
        let Some(socket) = file.inode().private::<NetlinkSocket>() else { return Err(vfs::VfsError::Einval); };
        socket.write_iter(bufs)
    }

    fn poll(&self, inode: &vfs::Inode) -> u32 {
        inode.private::<NetlinkSocket>().map(|s| s.poll()).unwrap_or(vfs::POLL_OUT)
    }

    fn ioctl_int(&self, file: &vfs::File, cmd: vfs::IoctlIntCmd) -> vfs::KResult<u32> {
        let Some(s) = file.inode().private::<NetlinkSocket>() else { return Err(vfs::VfsError::Einval); };
        net::security_admission::check(
            net::net_ns::namespace_id(&s.net_ns),
            net::socket_args::AF_NETLINK_WIRE,
            security::network::Operation::Ioctl,
        ).map_err(|_| vfs::VfsError::Eacces)?;
        match cmd { vfs::IoctlIntCmd::Fionread => Ok(s.front_len()), vfs::IoctlIntCmd::Siocoutq => Ok(0) }
    }

    fn fasync_file(&self, _fd: i32, file: &Arc<vfs::File>, on: bool) -> vfs::KResult<()> {
        file.set_fasync_state(on);
        Ok(())
    }
}

/// Build the `Arc<Inode>` wrapping a netlink socket fd.
/// # C: O(1)
pub fn make_netlink_socket_inode(sock: Arc<NetlinkSocket>) -> vfs::InodeRef {
    let ino = NETLINK_INO_TAG | (Arc::as_ptr(&sock) as u64 & NETLINK_INO_ID_MASK);
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
