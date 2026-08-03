extern crate alloc;

use alloc::sync::Arc;

use crate::NetlinkSocket;

/// Netlink socket inode numbers, from the one range `vfs::pseudo_ino` reserves
/// for them. The id used to be the socket's own heap ADDRESS, which the
/// allocator reuses the moment a socket is freed, so two live netlink sockets
/// could carry the same `st_ino` — the key `lsof` and `ss` identify a socket
/// by. Each socket now draws its own number. # C: O(1)
static NEXT_NETLINK_INO: vfs::pseudo_ino::RegionAllocator
    = vfs::pseudo_ino::RegionAllocator::new(&vfs::pseudo_ino::NETLINK);

/// `file_operations` for a netlink-socket inode — delegates the data path to
/// the `NetlinkSocket` stored in `i_private`.
struct NetlinkFileOps;

fn admit(socket: &NetlinkSocket, operation: security::network::Operation) -> vfs::KResult<()> {
    net::security_admission::check(net::net_ns::namespace_id(&socket.net_ns),
        net::socket_args::AF_NETLINK_WIRE, operation).map_err(|_| vfs::VfsError::Eacces)
}

impl vfs::FileOps for NetlinkFileOps {
    fn read(&self, inode: &vfs::Inode, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        match inode.private::<NetlinkSocket>() {
            Some(s) => { admit(s, security::network::Operation::Receive)?; s.read(buf) },
            None => Err(vfs::VfsError::Einval),
        }
    }

    fn read_file(&self, file: &vfs::File, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let Some(s) = file.inode().private::<NetlinkSocket>() else { return Err(vfs::VfsError::Einval); };
        admit(s, security::network::Operation::Receive)?;
        loop {
            match s.receive(false) {
                crate::ReceiveState::Datagram(dgram) => {
                    let n = dgram.bytes.len().min(buf.len());
                    buf[..n].copy_from_slice(&dgram.bytes[..n]);
                    return Ok(n);
                }
                crate::ReceiveState::Error(errno) => return Err(crate::receive::vfs_error(errno)),
                crate::ReceiveState::Empty => {
                    #[cfg(target_os = "oxide-kernel")]
                    {
                        // Interrupted receives derive their errno from the
                        // effective receive timeout.
                        if sched::live::deliverable_signals_self() != 0 {
                            return Err(net::sock_intr::sock_intr_vfs(s.recv_deadline_ns()));
                        }
                        if s.arm_receive_wait() {
                            // SAFETY: this syscall process is parked through the socket wait owner.
                            unsafe { sched::live::schedule::schedule(); }
                            s.waiters.remove_current();
                            if sched::live::deliverable_signals_self() != 0 {
                                return Err(net::sock_intr::sock_intr_vfs(s.recv_deadline_ns()));
                            }
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
        admit(s, security::network::Operation::Receive)?;
        match s.receive(false) {
            crate::ReceiveState::Datagram(dgram) => {
                let n = dgram.bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&dgram.bytes[..n]);
                Ok(n)
            }
            crate::ReceiveState::Error(errno) => Err(crate::receive::vfs_error(errno)),
            crate::ReceiveState::Empty => Err(vfs::VfsError::Eagain),
        }
    }

    fn write(&self, inode: &vfs::Inode, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        match inode.private::<NetlinkSocket>() {
            Some(s) => { admit(s, security::network::Operation::Send)?; s.write(buf) },
            None => Err(vfs::VfsError::Einval),
        }
    }

    fn write_iter_file(&self, file: &vfs::File, _off: u64, bufs: &[&[u8]], _nonblock: bool) -> vfs::KResult<usize> {
        let Some(socket) = file.inode().private::<NetlinkSocket>() else { return Err(vfs::VfsError::Einval); };
        admit(socket, security::network::Operation::Send)?;
        socket.write_iter(bufs)
    }

    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
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
        match cmd {
            vfs::IoctlIntCmd::Fionread => Ok(s.front_len()),
            vfs::IoctlIntCmd::Siocoutq => Ok(0),
            vfs::IoctlIntCmd::Siocoutqnsd => Err(vfs::VfsError::Enotty),
            vfs::IoctlIntCmd::Siocatmark => Err(vfs::VfsError::Enotty),
        }
    }

    fn fasync_file(&self, fd: i32, file: &Arc<vfs::File>, on: bool) -> vfs::KResult<()> {
        file.set_fasync_state(fd, on);
        Ok(())
    }
}

/// Build the `Arc<Inode>` wrapping a netlink socket fd.
/// # C: O(1)
pub fn make_netlink_socket_inode(sock: Arc<NetlinkSocket>) -> vfs::InodeRef {
    crate::register_port_id(&sock);
    let ino = NEXT_NETLINK_INO.alloc();
    sock.ino.store(ino, core::sync::atomic::Ordering::Release);
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
