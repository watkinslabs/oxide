use super::*;
use alloc::sync::Arc;
use alloc::vec::Vec;

struct PacketKickDev;
impl net::NetDev for PacketKickDev {
    fn name(&self) -> &str { "socktx0" }
    fn mac(&self) -> net::MacAddr { net::MacAddr([2, 1, 2, 3, 4, 5]) }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, _pkt: net::Pkt) -> net::NetResult<()> { Ok(()) }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> net::NamespaceDropAction {
        net::NamespaceDropAction::Destroy
    }
}

fn packet_tx_ring_file() -> Arc<vfs::File> {
    let owner = network_namespace::initial();
    let iface = net::sock::stack().ifaces.register_in_ns(Arc::new(PacketKickDev),
        owner.id().as_u64());
    let socket = Arc::new(net::sock::InetSocket::new_packet_in(net::eth_p::IPV4, 3, owner));
    if let net::sock::SockKind::Packet { ifindex, .. } = &*socket.kind.lock() {
        ifindex.store(iface.raw(), core::sync::atomic::Ordering::Release);
    }
    socket.set_packet_ring(net::sock::PacketRingKind::Tx, net::sock::PacketRingRequest {
        block_size: 4096, block_nr: 1, frame_size: 1024, frame_nr: 4,
        ..net::sock::PacketRingRequest::default()
    }).unwrap();
    let inode = net::sock::make_inet_socket_inode(socket);
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("packet"), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)
}

struct PacketKickIo { target: Arc<vfs::File>, events: Vec<&'static str> }
impl MessageIo for PacketKickIo {
    fn file(&mut self) -> KResult<Arc<vfs::File>> {
        self.events.push("file"); Ok(self.target.clone())
    }
    fn import(&mut self, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self) -> KResult<Option<Message>> {
        self.events.push("envelope");
        Ok(Some(Message { requested_len: 1, ..Message::default() }))
    }
    fn import_payload(&mut self, _message: &mut Message) -> KResult<()> {
        self.events.push("payload"); Err(Error::Efault)
    }
}

#[test]
fn packet_tx_ring_kick_skips_payload_materialization() {
    let task = sched::Task::new(19, "packet-kick", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut io = PacketKickIo { target: packet_tx_ring_file(), events: Vec::new() };
    assert_eq!(send_io(&ctx, 0, &mut io), Ok(SendOutcome { bytes: 0, complete: false }));
    assert_eq!(io.events, ["file", "envelope"]);
}

struct PacketKickBatch { target: Arc<vfs::File>, payload_called: bool, published: bool }
impl BatchIo for PacketKickBatch {
    fn file(&mut self) -> KResult<Arc<vfs::File>> { Ok(self.target.clone()) }
    fn import(&mut self, _index: u32, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self, _index: u32) -> KResult<Option<Message>> {
        Ok(Some(Message { requested_len: 1, ..Message::default() }))
    }
    fn import_payload(&mut self, _index: u32, _message: &mut Message) -> KResult<()> {
        self.payload_called = true; Err(Error::Efault)
    }
    fn publish(&mut self, _index: u32, len: u32) -> KResult<()> {
        assert_eq!(len, 0); self.published = true; Ok(())
    }
}

#[test]
fn packet_tx_ring_sendmmsg_kick_skips_each_payload_import() {
    let task = sched::Task::new(20, "packet-batch", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut io = PacketKickBatch { target: packet_tx_ring_file(),
        payload_called: false, published: false };
    assert_eq!(send_batch(&ctx, BatchSpec { len: 1, flags: 0 }, &mut io), Ok(1));
    assert!(!io.payload_called); assert!(io.published);
}
