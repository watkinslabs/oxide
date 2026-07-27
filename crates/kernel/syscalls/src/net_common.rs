// net_common — shared net-syscall helpers + consts (docs/53 §0).
// Moved verbatim from net.rs.
use alloc::sync::Arc;
use net::sock::InetSocket;

pub(crate) use crate::net_errno::errno_from_neterr;

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "307_sendmmsg.rs"]
mod sendmmsg_hosted;

/// Socket plus the `fget`-style file pin held for the syscall duration.
pub(crate) struct SocketFileRef {
    file: Arc<vfs::File>,
    socket: Arc<InetSocket>,
}

/// AF_VSOCK socket plus the `fget`-style file pin held for the syscall duration.
pub(crate) struct VsockFileRef {
    file: Arc<vfs::File>,
    socket: Arc<net::vsock_socket::VsockSocket>,
}

impl VsockFileRef {
    /// Snapshot `O_NONBLOCK` from the pinned open file description. # C: O(1)
    pub(crate) fn is_nonblock(&self) -> bool {
        self.file.flags().contains(vfs::OpenFlags::O_NONBLOCK)
    }
}

impl SocketFileRef {
    /// Snapshot `O_NONBLOCK` from the pinned open file description. # C: O(1)
    pub(crate) fn is_nonblock(&self) -> bool {
        self.file.flags().contains(vfs::OpenFlags::O_NONBLOCK)
    }
}

impl core::ops::Deref for VsockFileRef {
    type Target = Arc<net::vsock_socket::VsockSocket>;
    fn deref(&self) -> &Self::Target { &self.socket }
}

impl core::ops::Deref for SocketFileRef {
    type Target = Arc<InetSocket>;
    fn deref(&self) -> &Self::Target { &self.socket }
}

pub(crate) const AF_INET:     u32 = 2;
pub(crate) const AF_INET6:    u32 = 10;
pub(crate) const SOCK_STREAM: u32 = 1;
pub(crate) const SOCK_DGRAM:  u32 = 2;
pub(crate) const SOCK_SEQPACKET: u32 = 5;

/// Classify an already-pinned file as INET/AF_UNIX while retaining its pin.
/// # C: O(1)
pub(crate) fn socket_from_file(file: Arc<vfs::File>) -> Option<SocketFileRef> {
    let socket = inode_as_inet_socket(file.inode())?;
    Some(SocketFileRef { file, socket })
}

/// Downcast an `Arc<dyn vfs::Inode>` to `Arc<InetSocket>` by
/// pattern: only succeeds when the inode IS an InetSocket
/// (vouched by the high-bit tag in `ino()`).
/// # C: O(1)
pub(crate) fn inode_as_inet_socket(inode: &vfs::InodeRef) -> Option<Arc<InetSocket>> {
    // Post-KEYSTONE: the socket lives in the concrete inode's `i_private`
    // (`Arc<dyn Any + Send + Sync>`); recover the typed `Arc<InetSocket>` via
    // `Arc::downcast` (the ino tag is no longer needed — the downcast IS the
    // type check).
    inode.i_private().clone().downcast::<InetSocket>().ok()
}

/// Downcast an inode to the concrete AF_VSOCK socket. # C: O(1)
pub(crate) fn inode_as_vsock(inode: &vfs::InodeRef) -> Option<Arc<net::vsock_socket::VsockSocket>> {
    inode.i_private().clone().downcast::<net::vsock_socket::VsockSocket>().ok()
}

/// Classify an already-pinned file as AF_VSOCK while retaining its file pin.
/// # C: O(1)
pub(crate) fn vsock_from_file(file: Arc<vfs::File>) -> Option<VsockFileRef> {
    let socket = inode_as_vsock(file.inode())?;
    Some(VsockFileRef { file, socket })
}

#[cfg(target_os = "oxide-kernel")]
/// Resolve an fd to its vfs::File Arc (running task's fd table).
/// # C: O(1)
pub(crate) fn fd_file(fd: u64) -> Option<Arc<vfs::File>> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    fdt.get(fd as i32).ok()
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod tests {
    use super::*;

    #[test]
    fn vsock_ref_delays_final_file_release_until_operation_ends() {
        let socket = Arc::new(net::vsock_socket::VsockSocket::new());
        let inode = net::vsock_socket::make_vsock_socket_inode(socket.clone());
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("socket"), inode.clone());
        let file = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR);
        let socket_file = vsock_from_file(file.clone()).expect("AF_VSOCK file");

        drop(file);
        assert!(!matches!(*socket.kind.lock(), net::vsock_socket::VsockKind::Released));

        drop(socket_file);
        assert!(matches!(*socket.kind.lock(), net::vsock_socket::VsockKind::Released));
    }

    #[test]
    fn inet_ref_reads_status_flags_from_its_pinned_file() {
        let socket = Arc::new(net::sock::InetSocket::new_udp());
        let inode = net::sock::make_inet_socket_inode(socket);
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("socket"), inode.clone());
        let file = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR | vfs::OpenFlags::O_NONBLOCK);
        let socket_file = socket_from_file(file).expect("INET file");

        assert!(socket_file.is_nonblock());
    }

    #[test]
    fn inet_ref_keeps_original_endpoint_and_flags_across_close_reuse() {
        let old = Arc::new(net::sock::InetSocket::new_udp());
        let old_inode = net::sock::make_inet_socket_inode(old.clone());
        let old_dentry = vfs::Dentry::new(None, alloc::string::String::from("old"), old_inode.clone());
        let fdt = vfs::FdTable::new();
        let fd = fdt.alloc(vfs::File::new(old_inode, old_dentry, vfs::OpenFlags::O_RDWR)).unwrap();
        let target = socket_from_file(fdt.get(fd).unwrap()).expect("old INET target");

        fdt.close(fd).unwrap();
        let replacement = Arc::new(net::sock::InetSocket::new_udp());
        let new_inode = net::sock::make_inet_socket_inode(replacement.clone());
        let new_dentry = vfs::Dentry::new(None, alloc::string::String::from("new"), new_inode.clone());
        let new_file = vfs::File::new(new_inode, new_dentry,
            vfs::OpenFlags::O_RDWR | vfs::OpenFlags::O_NONBLOCK);
        assert_eq!(fdt.alloc(new_file).unwrap(), fd);

        assert!(Arc::ptr_eq(&target.socket, &old));
        assert!(!target.is_nonblock());
        assert!(!old.released.load(core::sync::atomic::Ordering::Acquire));
        assert!(!replacement.released.load(core::sync::atomic::Ordering::Acquire));
        drop(target);
        assert!(old.released.load(core::sync::atomic::Ordering::Acquire));
        assert!(!replacement.released.load(core::sync::atomic::Ordering::Acquire));
        fdt.close(fd).unwrap();
        assert!(replacement.released.load(core::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn every_blocking_socket_receive_wait_routes_through_sock_intr_errno() {
        // B1449: the shim receive loops are kernel-gated, so a compiled hosted
        // test cannot reach them; the DECISION they must call is hosted-tested
        // in `net_errno`. This asserts each wait actually calls it rather than
        // hard-coding `Errno::Eintr`, which is what made every untimed
        // SA_RESTART recv report EINTR where Linux resumes the call.
        let sources: [(&str, &str); 5] = [
            ("unix_recv.rs", include_str!("unix_recv.rs")),
            ("recvmsg/inet.rs", include_str!("recvmsg/inet.rs")),
            ("recvmsg/netlink.rs", include_str!("recvmsg/netlink.rs")),
            ("recvmsg/vsock.rs", include_str!("recvmsg/vsock.rs")),
            ("043_accept.rs", include_str!("043_accept.rs")),
        ];
        let mut waits = 0usize;
        for (name, text) in sources {
            for (at, _) in text.match_indices("deliverable_signals_self") {
                waits += 1;
                let arm = &text[at..core::cmp::min(at + 240, text.len())];
                assert!(arm.contains("sock_intr_errno") || arm.contains("recv_interrupted"),
                    "{name}: interrupted socket wait does not use sock_intr_errno:\n{arm}");
            }
        }
        assert_eq!(waits, 8, "expected 8 interrupted socket waits across the recv/accept shims");
    }

    #[test]
    fn read_receive_and_writev_do_not_reresolve_pinned_files() {
        let read = include_str!("000_read.rs");
        assert!(read.contains("recvmsg::from_file(file.clone())"));
        assert!(!read.contains("socket_from_fd"));
        assert!(!read.contains("sys_recvfrom"));
        assert!(read.contains("file.read(slice)"));

        let recvfrom = include_str!("045_recvfrom.rs");
        assert!(recvfrom.contains("crate::recvmsg::lookup(args.a0)"));
        assert!(recvfrom.contains("crate::recvmsg::recv(&target, &user, args.a3)"));
        assert!(!recvfrom.contains("file_is_nonblock"));
        assert!(!recvfrom.contains("socket_from_fd"));
        assert!(!recvfrom.contains("vsock_from_fd"));

        let unix = include_str!("unix_recv.rs");
        assert!(!unix.contains("file_is_nonblock"));

        let writev = include_str!("020_writev.rs");
        assert!(writev.contains("let file = match fdt.get(fd)"));
        assert!(writev.contains("socket::writev(&context, file.clone(), &bufs)"));
        assert!(!writev.contains("netlink_fd::"));
        assert!(!writev.contains("SockKind::"));
        assert!(!writev.contains("socket_from_fd(args.a0)"));

        let sendto = include_str!("044_sendto.rs");
        assert!(sendto.contains("socket::send_io(&context"));
        assert!(!sendto.contains("file_is_nonblock"));
        assert!(!sendto.contains("SockKind::"));

        let sendmsg = include_str!("046_sendmsg.rs");
        assert!(sendmsg.contains("socket::send_io(&context"));
        assert!(!sendmsg.contains("file_is_nonblock"));
        assert!(!sendmsg.contains("SockKind::"));

        let sendmmsg = include_str!("307_sendmmsg.rs");
        let send_user = include_str!("send_user.rs");
        assert!(send_user.contains("impl socket::BatchIo for SendBatchIo"));
        assert!(sendmmsg.contains("socket::send_batch(&context, spec, &mut importer)"));
        assert!(!sendmmsg.contains("message_data_len"));
        assert!(!sendmmsg.contains("sys_sendmsg(&"));

        let recvmmsg = include_str!("299_recvmmsg.rs");
        let lookup = recvmmsg.find("let target = match crate::recvmsg::lookup(args.a0)").unwrap();
        let timeout = recvmmsg.find("let mut timeout = match timeout_import(args.a4)").unwrap();
        assert!(timeout < lookup, "recvmmsg imports timeout before fd lookup");
        assert!(recvmmsg.contains("if result > 0"),
            "recvmmsg copies a supplied timeout back only after a completed datagram");

        let bind = include_str!("049_bind.rs");
        assert!(bind.contains("move_sockaddr_to_kernel_shape(addr_p, addrlen)"));

        let sockaddr = include_str!("net_sockaddr.rs");
        let address_copy = sockaddr.find("|copy_len| uaccess::copy_to_user(addr, &sa.as_bytes()").unwrap();
        let length_copy = sockaddr.find("|full_len| uaccess::copy_to_user(addrlen, &full_len.to_ne_bytes())").unwrap();
        assert!(length_copy < address_copy, "sockaddr value-result length publishes before bytes");

        for source in [include_str!("051_getsockname.rs"), include_str!("052_getpeername.rs")] {
            assert!(source.contains("copy_sockaddr_to_user(addr_p, len_p"));
        }

        let listen = include_str!("050_listen.rs");
        assert!(listen.contains("vs.listen_with_backlog(backlog)"));

        let accept = include_str!("043_accept.rs");
        assert!(accept.contains("vs.listener_for_accept()"));

        let setsockopt = include_str!("054_setsockopt/main.rs");
        assert!(setsockopt.contains("vsock.check_option()"));
        assert!(setsockopt.contains("let read_i32_required"));
        assert!(setsockopt.contains("sock.opts.reuseaddr.store(v, Ordering::Release)"));

        let getsockopt = include_str!("055_getsockopt.rs");
        assert!(getsockopt.contains("vsock.check_option()"));
        let bytes_back = &getsockopt[getsockopt.find("let bytes_back").unwrap()..];
        let value_copy = bytes_back.find("copy_to_user(optval, &value[..take])").unwrap();
        let length_copy = bytes_back.find("copy_to_user(optlen_p, &(take as u32)").unwrap();
        assert!(value_copy < length_copy, "getsockopt bytes publish before value-result length");
    }
}
