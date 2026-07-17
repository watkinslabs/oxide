use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::*;

struct Ops;
impl vfs::FileOps for Ops {
    fn write(&self, _inode: &vfs::Inode, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        Ok(buf.len())
    }
}

fn file(flags: vfs::OpenFlags) -> Arc<vfs::File> {
    let inode = vfs::InodeBuilder::new(41, vfs::mk_mode(vfs::FileType::Regular, 0o600),
        vfs::default_inode_ops(), Arc::new(Ops)).build();
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("send"), inode.clone());
    vfs::File::new(inode, dentry, flags)
}

#[test]
fn classification_retains_original_file_across_fd_reuse() {
    let table = vfs::FdTable::new();
    let original = file(vfs::OpenFlags::O_RDWR);
    let fd = table.alloc(original).unwrap();
    let target = SendFile::new(table.get(fd).unwrap());
    table.close(fd).unwrap();
    let replacement = file(vfs::OpenFlags::O_RDWR | vfs::OpenFlags::O_NONBLOCK);
    assert_eq!(table.alloc(replacement.clone()).unwrap(), fd);
    assert!(!target.nonblock());
    assert!(!Arc::ptr_eq(target.file(), &replacement));
}

struct Batch {
    imported: Vec<u32>,
    published: Vec<(u32, u32)>,
}

fn valid_netlink_payload(index: u32) -> Vec<u8> {
    Vec::from([16u8, 0, 0, 0, 1, 0, 0, 0, index as u8, 0, 0, 0, 0, 0, 0, 0])
}

impl BatchIo for Batch {
    fn file(&mut self) -> KResult<Arc<vfs::File>> {
        let namespace = network_namespace::initial();
        let endpoint = Arc::new(netlink::NetlinkSocket::new(netlink::proto::NETLINK_ROUTE, &namespace));
        let inode = netlink::make_netlink_socket_inode(endpoint);
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("socket"), inode.clone());
        Ok(vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR))
    }

    fn import(&mut self, index: u32, mode: ImportMode) -> KResult<Message> {
        let _ = (index, mode);
        Err(Error::Eio)
    }

    fn import_envelope(&mut self, index: u32) -> KResult<Option<Message>> {
        self.imported.push(index);
        Ok(Some(Message { requested_len: 16, ..Message::default() }))
    }

    fn import_payload(&mut self, index: u32, message: &mut Message) -> KResult<()> {
        message.payload = valid_netlink_payload(index);
        Ok(())
    }

    fn publish(&mut self, index: u32, len: u32) -> KResult<()> {
        self.published.push((index, len)); Ok(())
    }
}

#[test]
fn batch_imports_and_publishes_one_message_at_a_time() {
    let task = sched::Task::new(7, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut batch = Batch { imported: Vec::new(), published: Vec::new() };
    assert_eq!(send_batch(&ctx, BatchSpec { len: 3, flags: 0 }, &mut batch), Ok(3));
    assert_eq!(batch.imported, [0, 1, 2]);
    assert_eq!(batch.published, [(0, 16), (1, 16), (2, 16)]);
    assert_eq!(task.sigpending.load(Ordering::Acquire), 0);
}

struct PartialBatch { imported: Vec<u32>, published: Vec<(u32, u32)> }

impl BatchIo for PartialBatch {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(netlink_file()) }
    fn import(&mut self, _index: u32, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self, index: u32) -> KResult<Option<Message>> {
        self.imported.push(index);
        Ok(Some(Message { requested_len: 16, ..Message::default() }))
    }
    fn import_payload(&mut self, index: u32, message: &mut Message) -> KResult<()> {
        if index == 1 { return Err(Error::Efault); }
        message.payload = valid_netlink_payload(index);
        Ok(())
    }
    fn publish(&mut self, index: u32, len: u32) -> KResult<()> {
        self.published.push((index, len)); Ok(())
    }
}

#[test]
fn phased_batch_returns_completed_prefix_without_failed_copyout() {
    let task = sched::Task::new(20, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut batch = PartialBatch { imported: Vec::new(), published: Vec::new() };
    assert_eq!(send_batch(&ctx, BatchSpec { len: 3, flags: 0 }, &mut batch), Ok(1));
    assert_eq!(batch.imported, [0, 1]);
    assert_eq!(batch.published, [(0, 16)]);
}

#[test]
fn compat_batch_flag_is_rejected_before_import() {
    let task = sched::Task::new(8, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut batch = Batch { imported: Vec::new(), published: Vec::new() };
    assert_eq!(send_batch(&ctx, BatchSpec { len: 1, flags: batch::MSG_CMSG_COMPAT }, &mut batch),
        Err(Error::Einval));
    assert!(batch.imported.is_empty());
}

struct Single {
    target: Arc<vfs::File>,
    imported: bool,
}

impl MessageIo for Single {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _mode: ImportMode) -> KResult<Message> {
        self.imported = true;
        Ok(Message::default())
    }
}

#[test]
fn single_send_rejects_regular_file_before_message_import() {
    let task = sched::Task::new(9, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut io = Single { target: file(vfs::OpenFlags::O_RDWR), imported: false };
    assert_eq!(send_io(&ctx, 0, &mut io), Err(Error::Enotsock));
    assert!(!io.imported);
}

struct RegularBatch {
    target: Arc<vfs::File>,
    imported: bool,
}

impl BatchIo for RegularBatch {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _index: u32, _mode: ImportMode) -> KResult<Message> {
        self.imported = true;
        Ok(Message::default())
    }
    fn publish(&mut self, _index: u32, _len: u32) -> KResult<()> { Ok(()) }
}

#[test]
fn zero_batch_rejects_regular_file_before_message_import() {
    let task = sched::Task::new(10, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut io = RegularBatch { target: file(vfs::OpenFlags::O_RDWR), imported: false };
    assert_eq!(send_batch(&ctx, BatchSpec { len: 0, flags: 0 }, &mut io), Err(Error::Enotsock));
    assert!(!io.imported);
}

#[test]
fn oversized_batch_is_rejected_after_fd_validation() {
    let task = sched::Task::new(11, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut io = RegularBatch { target: file(vfs::OpenFlags::O_RDWR), imported: false };
    assert_eq!(send_batch(&ctx, BatchSpec { len: batch::UIO_MAXIOV + 1, flags: 0 }, &mut io),
        Err(Error::Enotsock));
    assert!(!io.imported);
}

fn netlink_file() -> Arc<vfs::File> {
    let namespace = network_namespace::initial();
    let socket = Arc::new(netlink::NetlinkSocket::new(netlink::proto::NETLINK_ROUTE, &namespace));
    let inode = netlink::make_netlink_socket_inode(socket);
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("netlink"), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
}

fn invalid_credentials_control() -> Vec<u8> {
    let mut control = alloc::vec![0u8; 28];
    control[..8].copy_from_slice(&28u64.to_ne_bytes());
    control[8..12].copy_from_slice(&1i32.to_ne_bytes());
    control[12..16].copy_from_slice(&2i32.to_ne_bytes());
    control
}

struct EnvelopeProbe {
    target: Arc<vfs::File>, message: Message, payload_called: bool,
}

impl MessageIo for EnvelopeProbe {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self) -> KResult<Option<Message>> { Ok(Some(self.message.clone())) }
    fn import_payload(&mut self, _message: &mut Message) -> KResult<()> {
        self.payload_called = true;
        Err(Error::Efault)
    }
}

#[test]
fn netlink_prepares_oob_length_control_and_address_in_linux_order() {
    let task = sched::Task::new(18, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let malformed = Message { requested_len: 1, control: invalid_credentials_control(),
        name: Some(Vec::new()), ..Message::default() };
    let mut io = EnvelopeProbe { target: netlink_file(), message: malformed.clone(),
        payload_called: false };
    assert_eq!(send_io(&ctx, 0, &mut io), Err(Error::Esrch));
    assert!(!io.payload_called);

    let mut zero = malformed.clone(); zero.requested_len = 0;
    let mut io = EnvelopeProbe { target: netlink_file(), message: zero, payload_called: false };
    assert_eq!(send_io(&ctx, 0, &mut io), Err(Error::Enodata));
    assert!(!io.payload_called);

    let mut io = EnvelopeProbe { target: netlink_file(), message: malformed, payload_called: false };
    assert_eq!(send_io(&ctx, net::uapi::MSG_OOB as u32, &mut io), Err(Error::Eopnotsupp));
    assert!(!io.payload_called);
    assert_eq!(Error::Enodata.errno(), 61);
}

fn inet_file(socket: Arc<net::sock::InetSocket>) -> Arc<vfs::File> {
    let inode = net::sock::make_inet_socket_inode(socket);
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("inet"), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
}

struct Phased {
    target: Arc<vfs::File>, events: Vec<&'static str>, name: Option<Vec<u8>>,
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

#[test]
fn sendto_rejects_address_before_payload_materialization() {
    let task = sched::Task::new(11, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut io = Phased { target: netlink_file(), events: Vec::new(), name: Some(Vec::new()) };
    assert_eq!(send_io(&ctx, 0, &mut io), Err(Error::Einval));
    assert_eq!(io.events, ["file", "envelope"]);
}

#[test]
fn udp_sendmsg_rejects_destination_before_payload_materialization() {
    let task = sched::Task::new(16, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let target = inet_file(Arc::new(net::sock::InetSocket::new_udp()));
    let mut io = Phased { target, events: Vec::new(), name: Some(Vec::new()) };
    assert_eq!(send_io(&ctx, 0, &mut io), Err(Error::Einval));
    assert_eq!(io.events, ["file", "envelope"]);
}

struct InterruptOps;
impl vfs::FileOps for InterruptOps {
    fn write(&self, _inode: &vfs::Inode, _off: u64, _buf: &[u8]) -> vfs::KResult<usize> {
        Err(vfs::VfsError::Eintr)
    }
}

fn vsock_file(socket: Arc<net::vsock_socket::VsockSocket>) -> Arc<vfs::File> {
    let inode = vfs::InodeBuilder::new(0x5653_4f43_0000_0042,
        vfs::mk_mode(vfs::FileType::Socket, 0o600), vfs::default_inode_ops(), Arc::new(InterruptOps))
        .private(socket).build();
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("vsock"), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
}

#[test]
fn vsock_oob_imports_envelope_only() {
    let task = sched::Task::new(12, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let target = vsock_file(Arc::new(net::vsock_socket::VsockSocket::new()));
    let mut io = Phased { target, events: Vec::new(), name: Some(alloc::vec![0; 16]) };
    assert_eq!(send_io(&ctx, net::uapi::MSG_OOB as u32, &mut io), Err(Error::Eopnotsupp));
    assert_eq!(io.events, ["file", "envelope"]);
}

struct VsockBatch { target: Arc<vfs::File>, modes: Vec<ImportMode> }
impl BatchIo for VsockBatch {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _index: u32, mode: ImportMode) -> KResult<Message> {
        self.modes.push(mode); Ok(Message::default())
    }
    fn publish(&mut self, _index: u32, _len: u32) -> KResult<()> { Ok(()) }
}

#[test]
fn vsock_batch_oob_imports_each_attempt_as_envelope_only() {
    let task = sched::Task::new(15, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let target = vsock_file(Arc::new(net::vsock_socket::VsockSocket::new()));
    let mut io = VsockBatch { target, modes: Vec::new() };
    assert_eq!(send_batch(&ctx, BatchSpec { len: 1, flags: net::uapi::MSG_OOB as u32 }, &mut io),
        Err(Error::Eopnotsupp));
    assert_eq!(io.modes, [ImportMode::RawOobEnvelope]);
}

#[test]
fn vsock_destination_and_interrupt_errors_match_linux() {
    let task = sched::Task::new(13, "send", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let init = Arc::new(net::vsock_socket::VsockSocket::new());
    assert_eq!(send(&ctx, vsock_file(init), Message { name: Some(alloc::vec![0; 16]),
        ..Message::default() }, 0), Err(Error::Eopnotsupp));

    let owner = net::vsock::VsockOwner::from_raw(0x0c00_0042).unwrap();
    let conn = Arc::new(net::vsock::VsockConn::new(owner, 3, 62_100, 2, 1024,
        net::vsock::VsockState::Connected));
    let connected = Arc::new(net::vsock_socket::VsockSocket::new());
    *connected.kind.lock() = net::vsock_socket::VsockKind::Conn(conn);
    let file = vsock_file(connected);
    assert_eq!(send(&ctx, file.clone(), Message { name: Some(alloc::vec![0; 16]),
        ..Message::default() }, 0), Err(Error::Eisconn));
    assert_eq!(send(&ctx, file.clone(), Message { name: Some(Vec::new()),
        ..Message::default() }, 0), Err(Error::Eisconn));
    assert_eq!(send(&ctx, file, Message { payload: alloc::vec![1], requested_len: 1,
        name: None, ..Message::default() }, 0), Err(Error::Eintr));
}

#[test]
fn vfs_errors_keep_their_exact_errno() {
    for error in [vfs::VfsError::Eintr, vfs::VfsError::Enodev, vfs::VfsError::Eisdir,
        vfs::VfsError::Enospc, vfs::VfsError::Enotempty, vfs::VfsError::Euclean,
        vfs::VfsError::Edquot, vfs::VfsError::Ecanceled]
    {
        assert_eq!(Error::from(error).errno(), error as i32);
    }
}

fn rights_control(fds: &[i32]) -> Vec<u8> {
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

struct UnixMalformedPayload {
    target: Arc<vfs::File>, fd: i32, payload_called: bool,
}

impl MessageIo for UnixMalformedPayload {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self) -> KResult<Option<Message>> {
        Ok(Some(Message { requested_len: 1, control: rights_control(&[self.fd]),
            name: Some(Vec::new()), ..Message::default() }))
    }
    fn import_payload(&mut self, _message: &mut Message) -> KResult<()> {
        self.payload_called = true;
        Err(Error::Efault)
    }
}

#[test]
fn unix_scm_is_pinned_before_atomic_payload_fault_and_cleaned_on_failure() {
    let task = sched::Task::new(14, "send", sched::SchedClass::Normal { weight: 1024 });
    let table = Arc::new(vfs::FdTable::new());
    // SAFETY: hosted test has exclusive ownership of this unscheduled task.
    unsafe { task.replace_fd_table(Some(table.clone())); }
    let held = file(vfs::OpenFlags::O_RDWR);
    let fd = table.alloc(held.clone()).unwrap();
    let baseline = Arc::strong_count(&held);
    let target = inet_file(Arc::new(net::sock::InetSocket::new_unix_dgram()));
    let ctx = SendContext::new(&task);
    let message = Message { payload_faulted: true, requested_len: 1,
        control: rights_control(&[fd, i32::MAX]), ..Message::default() };

    assert_eq!(send(&ctx, target, message, 0), Err(Error::Ebadf));
    assert_eq!(Arc::strong_count(&held), baseline);

    let target = inet_file(Arc::new(net::sock::InetSocket::new_unix_dgram()));
    let mut io = UnixMalformedPayload { target, fd, payload_called: false };
    assert_eq!(send_io(&ctx, 0, &mut io), Err(Error::Einval));
    assert!(!io.payload_called);
    assert_eq!(Arc::strong_count(&held), baseline);
}

struct ReuseDuringPayload {
    target: Arc<vfs::File>, table: Arc<vfs::FdTable>, fd: i32, held: Arc<vfs::File>,
}

impl MessageIo for ReuseDuringPayload {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self) -> KResult<Option<Message>> {
        Ok(Some(Message { requested_len: 1, control: rights_control(&[self.fd]),
            ..Message::default() }))
    }
    fn import_payload(&mut self, message: &mut Message) -> KResult<()> {
        assert_eq!(Arc::strong_count(&self.held), 4);
        self.table.close(self.fd).unwrap();
        assert_eq!(self.table.alloc(file(vfs::OpenFlags::O_RDWR)).unwrap(), self.fd);
        assert_eq!(Arc::strong_count(&self.held), 3);
        message.payload_faulted = true;
        Ok(())
    }
}

#[test]
fn unix_scm_pin_survives_exact_fd_reuse_during_payload_import() {
    let task = sched::Task::new(17, "send", sched::SchedClass::Normal { weight: 1024 });
    let table = Arc::new(vfs::FdTable::new());
    // SAFETY: hosted test has exclusive ownership of this unscheduled task.
    unsafe { task.replace_fd_table(Some(table.clone())); }
    let held = file(vfs::OpenFlags::O_RDWR);
    let fd = table.alloc(held.clone()).unwrap();
    let socket = Arc::new(net::sock::InetSocket::new_unix());
    *socket.kind.lock() = net::sock::SockKind::UnixMsgPair(net::UnixMsgPair::new(), net::UnixEnd::A);
    let mut io = ReuseDuringPayload { target: inet_file(socket), table, fd, held: held.clone() };
    assert_eq!(send_io(&SendContext::new(&task), 0, &mut io), Err(Error::Efault));
    assert_eq!(Arc::strong_count(&held), 2);
}

struct BatchReuseDuringPayload {
    target: Arc<vfs::File>, table: Arc<vfs::FdTable>, fd: i32, held: Arc<vfs::File>,
    published: bool,
}

impl BatchIo for BatchReuseDuringPayload {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _index: u32, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self, index: u32) -> KResult<Option<Message>> {
        assert_eq!(index, 0);
        Ok(Some(Message { requested_len: 1, control: rights_control(&[self.fd]),
            ..Message::default() }))
    }
    fn import_payload(&mut self, index: u32, message: &mut Message) -> KResult<()> {
        assert_eq!(index, 0);
        assert_eq!(Arc::strong_count(&self.held), 4);
        self.table.close(self.fd).unwrap();
        assert_eq!(self.table.alloc(file(vfs::OpenFlags::O_RDWR)).unwrap(), self.fd);
        assert_eq!(Arc::strong_count(&self.held), 3);
        message.payload_faulted = true;
        Ok(())
    }
    fn publish(&mut self, _index: u32, _len: u32) -> KResult<()> {
        self.published = true;
        Ok(())
    }
}

#[test]
fn sendmmsg_scm_pin_survives_exact_fd_reuse_during_payload_import() {
    let task = sched::Task::new(19, "send", sched::SchedClass::Normal { weight: 1024 });
    let table = Arc::new(vfs::FdTable::new());
    // SAFETY: hosted test has exclusive ownership of this unscheduled task.
    unsafe { task.replace_fd_table(Some(table.clone())); }
    let held = file(vfs::OpenFlags::O_RDWR);
    let fd = table.alloc(held.clone()).unwrap();
    let socket = Arc::new(net::sock::InetSocket::new_unix());
    *socket.kind.lock() = net::sock::SockKind::UnixMsgPair(net::UnixMsgPair::new(), net::UnixEnd::A);
    let mut io = BatchReuseDuringPayload { target: inet_file(socket), table, fd,
        held: held.clone(), published: false };
    assert_eq!(send_batch(&SendContext::new(&task), BatchSpec { len: 1, flags: 0 }, &mut io),
        Err(Error::Efault));
    assert!(!io.published);
    assert_eq!(Arc::strong_count(&held), 2);
}
