use alloc::sync::Arc;
use alloc::vec::Vec;

use super::*;

fn netlink_file() -> Arc<vfs::File> {
    let socket = Arc::new(netlink::NetlinkSocket::new(netlink::proto::NETLINK_ROUTE,
        &network_namespace::initial()));
    let inode = netlink::make_netlink_socket_inode(socket);
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("netlink-preflight"),
        inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
}

fn oversized() -> usize {
    netlink::NETLINK_SNDBUF_DEFAULT - netlink::NETLINK_SEND_OVERHEAD + 1
}

fn valid_netlink_payload() -> Vec<u8> {
    Vec::from([16u8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
}

struct BadPayload {
    target: Arc<vfs::File>, error: Error, payload_called: bool,
}

impl MessageIo for BadPayload {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self) -> KResult<Option<Message>> {
        Ok(Some(Message { requested_len: oversized(), ..Message::default() }))
    }
    fn import_payload(&mut self, _message: &mut Message) -> KResult<()> {
        self.payload_called = true;
        Err(self.error)
    }
}

#[test]
fn netlink_emsgsize_precedes_payload_fault_or_allocation_failure() {
    let task = sched::Task::new(21, "netlink-preflight",
        sched::SchedClass::Normal { weight: 1024 });
    for error in [Error::Efault, Error::Enomem] {
        let mut io = BadPayload { target: netlink_file(), error, payload_called: false };
        assert_eq!(send_io(&SendContext::new(&task), 0, &mut io), Err(Error::Emsgsize));
        assert!(!io.payload_called);
    }
}

struct PreflightBatch {
    target: Arc<vfs::File>, payload_calls: Vec<u32>, published: Vec<(u32, u32)>,
}

impl BatchIo for PreflightBatch {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _index: u32, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self, index: u32) -> KResult<Option<Message>> {
        let requested_len = if index == 0 { 16 } else { oversized() };
        Ok(Some(Message { requested_len, ..Message::default() }))
    }
    fn import_payload(&mut self, index: u32, message: &mut Message) -> KResult<()> {
        self.payload_calls.push(index);
        if index == 0 { message.payload = valid_netlink_payload(); Ok(()) } else { Err(Error::Efault) }
    }
    fn publish(&mut self, index: u32, len: u32) -> KResult<()> {
        self.published.push((index, len));
        Ok(())
    }
}

#[test]
fn sendmmsg_keeps_completed_prefix_when_next_netlink_datagram_is_oversized() {
    let task = sched::Task::new(22, "netlink-batch-preflight",
        sched::SchedClass::Normal { weight: 1024 });
    let mut io = PreflightBatch { target: netlink_file(), payload_calls: Vec::new(),
        published: Vec::new() };
    assert_eq!(send_batch(&SendContext::new(&task), BatchSpec { len: 2, flags: 0 }, &mut io),
        Ok(1));
    assert_eq!(io.payload_calls, [0]);
    assert_eq!(io.published, [(0, 16)]);
}
