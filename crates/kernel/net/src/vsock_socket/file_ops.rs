//! AF_VSOCK inode construction and VFS operation adapter.

use alloc::sync::Arc;

use super::{VsockSocket, VSOCK_INO_ID_MASK, VSOCK_INO_TAG};

/// Build the `Arc<Inode>` wrapping an AF_VSOCK socket fd. # C: O(1)
pub fn make_vsock_socket_inode(sock: Arc<VsockSocket>) -> vfs::InodeRef {
    let ino = VSOCK_INO_TAG | (Arc::as_ptr(&sock) as u64 & VSOCK_INO_ID_MASK);
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
            vfs::IoctlIntCmd::Siocatmark => return Err(vfs::VfsError::Enotty),
        })
    }
    fn fasync_file(&self, _fd: i32, file: &Arc<vfs::File>, on: bool) -> vfs::KResult<()> {
        file.set_fasync_state(on); Ok(())
    }
    fn on_release_file(&self, file: &vfs::File) {
        if let Some(socket) = file.inode().private::<VsockSocket>() { socket.release_file(); }
    }
}
