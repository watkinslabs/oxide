//! AF_VSOCK inode construction and VFS operation adapter.

use alloc::sync::Arc;

use super::{VsockSocket, NEXT_VSOCK_INO};

/// Build the `Arc<Inode>` wrapping an AF_VSOCK socket fd. # C: O(1)
pub fn make_vsock_socket_inode(sock: Arc<VsockSocket>) -> vfs::InodeRef {
    let ino = NEXT_VSOCK_INO.alloc();
    let subs = sock.poll_subs.clone();
    vfs::InodeBuilder::new(ino, vfs::mk_mode(vfs::FileType::Socket, 0o600),
        vfs::default_inode_ops(), Arc::new(VsockFileOps))
        .private(sock).poll_subs_arc(subs).build()
}

/// Recover the socket stored in an inode private owner. # C: O(1)
pub fn vsock_from_inode(inode: &vfs::Inode) -> Option<&VsockSocket> { inode.private::<VsockSocket>() }

/// Recover an owning socket Arc from an inode private owner. # C: O(1)
pub fn vsock_arc_from_inode(inode: &vfs::InodeRef) -> Option<Arc<VsockSocket>> {
    inode.i_private().clone().downcast::<VsockSocket>().ok()
}

struct VsockFileOps;

impl vfs::FileOps for VsockFileOps {
    fn read(&self, inode: &vfs::Inode, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        inode.private::<VsockSocket>().ok_or(vfs::VfsError::Einval)?.read(off, buf)
    }
    fn write(&self, inode: &vfs::Inode, off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        inode.private::<VsockSocket>().ok_or(vfs::VfsError::Einval)?.write(off, buf)
    }
    fn read_nonblock(&self, inode: &vfs::Inode, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        inode.private::<VsockSocket>().ok_or(vfs::VfsError::Einval)?.read_nonblock(off, buf)
    }
    fn write_nonblock(&self, inode: &vfs::Inode, off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        inode.private::<VsockSocket>().ok_or(vfs::VfsError::Einval)?.write_nonblock(off, buf)
    }
    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll(&self, inode: &vfs::Inode) -> u32 {
        inode.private::<VsockSocket>().map(VsockSocket::poll).unwrap_or(vfs::POLL_OUT)
    }
    fn poll_subscribers(&self, file: &vfs::File) -> Option<Arc<vfs::PollSubscribers>> {
        let socket = file.inode().private::<VsockSocket>()?;
        socket.attach_poll_source();
        Some(socket.poll_subs.clone())
    }
    fn ioctl_int(&self, file: &vfs::File, cmd: vfs::IoctlIntCmd) -> vfs::KResult<u32> {
        let socket = file.inode().private::<VsockSocket>().ok_or(vfs::VfsError::Einval)?;
        crate::security_admission::check(socket.net_ns(), crate::socket_args::AF_VSOCK as u16,
            security::network::Operation::Ioctl).map_err(|_| vfs::VfsError::Eacces)?;
        Ok(match cmd {
            vfs::IoctlIntCmd::Fionread => socket.conn().map(|conn| {
                if socket.socket_type() == super::VsockSocketType::Seqpacket {
                    conn.seq_rx.lock().next_len() as u32
                } else { conn.rx.lock().len() as u32 }
            }).unwrap_or(0),
            vfs::IoctlIntCmd::Siocoutq => socket.conn().map(|conn| {
                let tx = conn.tx.lock(); tx.credit.tx_cnt.wrapping_sub(tx.credit.peer_fwd_cnt)
            }).unwrap_or(0),
            // Linux exposes SIOCOUTQNSD only for TCP's split send queues.
            // AF_VSOCK has no equivalent transport boundary, so it must not
            // manufacture a TCP queue measurement for this command.
            vfs::IoctlIntCmd::Siocoutqnsd => return Err(vfs::VfsError::Enotty),
            vfs::IoctlIntCmd::Siocatmark => return Err(vfs::VfsError::Enotty),
        })
    }
    fn fasync_file(&self, fd: i32, file: &Arc<vfs::File>, on: bool) -> vfs::KResult<()> {
        file.set_fasync_state(fd, on); Ok(())
    }
    fn on_release_file(&self, file: &vfs::File) {
        if let Some(socket) = file.inode().private::<VsockSocket>() { socket.release_file(); }
    }
}

#[cfg(test)]
mod ino_tests {
    use super::*;

    // The id used to be `Arc::as_ptr(&sock)`, which the heap allocator hands
    // back the moment a socket is freed, so two live AF_VSOCK sockets could
    // report the same `st_ino`.

    fn a_vsock() -> Arc<VsockSocket> { Arc::new(VsockSocket::new()) }

    #[test]
    fn two_live_vsock_sockets_get_different_inode_numbers() {
        let a = make_vsock_socket_inode(a_vsock());
        let b = make_vsock_socket_inode(a_vsock());
        assert_ne!(a.ino(), b.ino());
    }

    /// Each socket is dropped before the next is built, so the allocator may
    /// place them at one address — the case the pointer id could not survive.
    #[test]
    fn vsock_numbers_are_not_reused_after_a_socket_is_freed() {
        let mut seen = alloc::collections::BTreeSet::new();
        for _ in 0..256 {
            let ino = make_vsock_socket_inode(a_vsock()).ino();
            assert!(vfs::pseudo_ino::VSOCK.contains(ino), "{ino:#x} left the vsock region");
            assert!(seen.insert(ino), "reused st_ino {ino:#x}");
        }
    }

    /// Identity still comes from `i_private`, not the number.
    #[test]
    fn vsock_identity_still_comes_from_the_private_socket() {
        let sock = a_vsock();
        let inode = make_vsock_socket_inode(Arc::clone(&sock));
        let got = vsock_arc_from_inode(&inode).expect("socket resolves from i_private");
        assert!(Arc::ptr_eq(&got, &sock));
    }
}
