use alloc::sync::Arc;

pub enum SendKind {
    File,
    Inet(Arc<net::sock::InetSocket>),
    Netlink(Arc<netlink::NetlinkSocket>),
    Vsock(Arc<net::vsock_socket::VsockSocket>),
}

pub struct SendFile {
    file: Arc<vfs::File>,
    kind: SendKind,
}

impl SendFile {
    /// Retain and classify one open file description for a complete operation. # C: O(1)
    pub fn new(file: Arc<vfs::File>) -> Self {
        let private = file.inode().i_private();
        let kind = if let Ok(socket) = private.clone().downcast::<netlink::NetlinkSocket>() {
            SendKind::Netlink(socket)
        } else if let Ok(socket) = private.clone().downcast::<net::vsock_socket::VsockSocket>() {
            SendKind::Vsock(socket)
        } else if let Ok(socket) = private.clone().downcast::<net::sock::InetSocket>() {
            SendKind::Inet(socket)
        } else { SendKind::File };
        Self { file, kind }
    }

    /// Retained open file description. # C: O(1)
    pub fn file(&self) -> &Arc<vfs::File> { &self.file }

    /// Canonical family classification for this retained file. # C: O(1)
    pub fn kind(&self) -> &SendKind { &self.kind }

    /// Open-file-description nonblocking status. # C: O(1)
    pub fn nonblock(&self) -> bool { self.file.flags().contains(vfs::OpenFlags::O_NONBLOCK) }

    /// Whether Linux socket send syscalls accept this target. # C: O(1)
    pub fn is_socket(&self) -> bool { !matches!(self.kind, SendKind::File) }
}
