// Fixtures shared by the send-path test modules: one builder per target kind,
// the control-message encoders, and the phase-recording `MessageIo`.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::*;

pub(super) struct Ops;
impl vfs::FileOps for Ops {
    fn write(&self, _inode: &vfs::Inode, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        Ok(buf.len())
    }
}

/// A retained regular file, which is never a send target. # C: O(1)
pub(super) fn file(flags: vfs::OpenFlags) -> Arc<vfs::File> {
    let inode = vfs::InodeBuilder::new(41, vfs::mk_mode(vfs::FileType::Regular, 0o600),
        vfs::default_inode_ops(), Arc::new(Ops)).build();
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("send"), inode.clone());
    vfs::File::new(inode, dentry, flags)
}

/// One well-formed `nlmsghdr` carrying `index` as its payload word. # C: O(1)
pub(super) fn valid_netlink_payload(index: u32) -> Vec<u8> {
    Vec::from([16u8, 0, 0, 0, 1, 0, 0, 0, index as u8, 0, 0, 0, 0, 0, 0, 0])
}

/// A retained NETLINK_ROUTE socket in the initial namespace. # C: O(1)
pub(super) fn netlink_file() -> Arc<vfs::File> {
    let namespace = network_namespace::initial();
    let socket = Arc::new(netlink::NetlinkSocket::new(netlink::proto::NETLINK_ROUTE, &namespace));
    let inode = netlink::make_netlink_socket_inode(socket);
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("netlink"), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
}

/// A retained internet-family socket. # C: O(1)
pub(super) fn inet_file(socket: Arc<net::sock::InetSocket>) -> Arc<vfs::File> {
    let inode = net::sock::make_inet_socket_inode(socket);
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("inet"), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
}

pub(super) struct InterruptOps;
impl vfs::FileOps for InterruptOps {
    fn write(&self, _inode: &vfs::Inode, _off: u64, _buf: &[u8]) -> vfs::KResult<usize> {
        Err(vfs::VfsError::Eintr)
    }
}

/// A retained AF_VSOCK socket whose backing write always reports EINTR. # C: O(1)
pub(super) fn vsock_file(socket: Arc<net::vsock_socket::VsockSocket>) -> Arc<vfs::File> {
    let inode = vfs::InodeBuilder::new(0x5653_4f43_0000_0042,
        vfs::mk_mode(vfs::FileType::Socket, 0o600), vfs::default_inode_ops(), Arc::new(InterruptOps))
        .private(socket).build();
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("vsock"), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
}

/// An `SCM_CREDENTIALS` control naming a pid no task holds. # C: O(1)
pub(super) fn invalid_credentials_control() -> Vec<u8> {
    let mut control = alloc::vec![0u8; 28];
    control[..8].copy_from_slice(&28u64.to_ne_bytes());
    control[8..12].copy_from_slice(&1i32.to_ne_bytes());
    control[12..16].copy_from_slice(&2i32.to_ne_bytes());
    control
}

/// An `SCM_RIGHTS` control carrying `fds`. # C: O(fds)
pub(super) fn rights_control(fds: &[i32]) -> Vec<u8> {
    let len = 16 + fds.len() * 4;
    let mut control = alloc::vec![0u8; len];
    control[..8].copy_from_slice(&(len as u64).to_ne_bytes());
    control[8..12].copy_from_slice(&1i32.to_ne_bytes());
    control[12..16].copy_from_slice(&1i32.to_ne_bytes());
    for (index, fd) in fds.iter().enumerate() {
        let at = 16 + index * 4;
        control[at..at + 4].copy_from_slice(&fd.to_ne_bytes());
    }
    control
}

/// Records which import phases one send actually ran.
pub(super) struct Phased {
    pub(super) target: Arc<vfs::File>,
    pub(super) events: Vec<&'static str>,
    pub(super) name: Option<Vec<u8>>,
}

impl MessageIo for Phased {
    fn file(&mut self) -> KResult<Arc<vfs::File>> {
        self.events.push("file"); Ok(self.target.clone())
    }
    fn import(&mut self, _mode: ImportMode) -> KResult<Message> {
        self.events.push("envelope"); Ok(Message::default())
    }
    fn import_envelope(&mut self) -> KResult<Option<Message>> {
        self.events.push("envelope");
        Ok(Some(Message { requested_len: 1, name: self.name.clone(), ..Message::default() }))
    }
    fn import_payload(&mut self, message: &mut Message) -> KResult<()> {
        self.events.push("payload"); message.payload.push(1); Ok(())
    }
}
