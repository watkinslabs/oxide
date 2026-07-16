use super::*;
use alloc::vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Barrier, Mutex};

const RAW: u8 = 3;
const DGRAM: u8 = 2;

struct TxDev {
    frames: Mutex<Vec<Vec<u8>>>,
    fail_at: AtomicUsize,
    block: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
}

impl TxDev {
    fn new() -> Self { Self { frames: Mutex::new(Vec::new()),
        fail_at: AtomicUsize::new(usize::MAX), block: Mutex::new(None) } }
    fn frames(&self) -> Vec<Vec<u8>> { self.frames.lock().unwrap().clone() }
    fn block(&self, entered: Arc<Barrier>, release: Arc<Barrier>) {
        *self.block.lock().unwrap() = Some((entered, release));
    }
}

impl crate::NetDev for TxDev {
    fn name(&self) -> &str { "txring0" }
    fn mac(&self) -> crate::MacAddr { crate::MacAddr([2, 3, 4, 5, 6, 7]) }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, pkt: crate::Pkt) -> crate::NetResult<()> { self.xmit_raw(pkt.data()) }
    fn xmit_raw(&self, frame: &[u8]) -> crate::NetResult<()> {
        if let Some((entered, release)) = self.block.lock().unwrap().take() {
            entered.wait(); release.wait();
        }
        let index = self.frames.lock().unwrap().len();
        if index == self.fail_at.load(Ordering::Acquire) { return Err(crate::NetError::Eio); }
        self.frames.lock().unwrap().push(frame.to_vec());
        Ok(())
    }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
}

fn request() -> PacketRingRequest {
    PacketRingRequest { block_size: 4096, block_nr: 1, frame_size: 1024, frame_nr: 4,
        ..PacketRingRequest::default() }
}

fn fixture(version: u8, kind: u8, loss: bool)
    -> (Arc<InetSocket>, PacketRingMmap, Arc<TxDev>, u32)
{
    let owner = crate::net_ns::test_support::allocate_namespace();
    let device = Arc::new(TxDev::new());
    let iface = stack().ifaces.register_in_ns(device.clone(), owner.id().as_u64());
    let socket = Arc::new(InetSocket::new_packet_in(crate::eth_p::IPV4, kind, owner));
    if loss { socket.set_packet_loss(true).unwrap(); }
    socket.set_packet_version(version).unwrap();
    socket.set_packet_ring(PacketRingKind::Tx, request()).unwrap();
    let pin = socket.packet_ring_mmap(0, 4096).unwrap();
    if let SockKind::Packet { ifindex, .. } = &*socket.kind.lock() {
        ifindex.store(iface.raw(), Ordering::Release);
    }
    (socket, pin, device, iface.raw())
}

fn publish(pin: &PacketRingMmap, index: u32, length: u32, payload: &[u8], next: u32) {
    let ring = pin.tx_test().unwrap();
    let frame = ring.frame_offset(index).unwrap();
    let (length_off, data_off) = match ring.layout().version {
        crate::uapi::TPACKET_V1 => (8, crate::uapi::TPACKET_V1_HEADER_LEN),
        crate::uapi::TPACKET_V2 => (4, crate::uapi::TPACKET_V2_HEADER_LEN),
        crate::uapi::TPACKET_V3 => {
            assert!(ring.write(frame, &next.to_ne_bytes()));
            (16, crate::uapi::TPACKET_V3_HEADER_LEN)
        }
        _ => unreachable!(),
    };
    assert!(ring.write(frame + length_off, &length.to_ne_bytes()));
    assert!(ring.write(frame + data_off as u64, payload));
    assert!(ring.publish_status(index, crate::uapi::TP_STATUS_SEND_REQUEST));
}

fn raw(seed: u8) -> Vec<u8> {
    let mut frame = vec![seed; 64];
    frame[12..14].copy_from_slice(&crate::eth_p::IPV4.to_be_bytes());
    frame
}

#[test]
fn valid_raw_frames_use_all_native_versions_and_stop_at_available_head() {
    for version in [crate::uapi::TPACKET_V1, crate::uapi::TPACKET_V2,
                    crate::uapi::TPACKET_V3] {
        let (socket, pin, device, _) = fixture(version, RAW, false);
        let first = raw(1); let second = raw(2);
        publish(&pin, 0, first.len() as u32, &first, 0);
        publish(&pin, 1, second.len() as u32, &second, 0);
        assert_eq!(socket.kick_packet_tx_ring(None), Ok(first.len() + second.len()));
        assert_eq!(device.frames(), vec![first, second]);
        assert_eq!(pin.tx_test().unwrap().status(0), Some(crate::uapi::TP_STATUS_AVAILABLE));
        assert_eq!(pin.tx_test().unwrap().status(1), Some(crate::uapi::TP_STATUS_AVAILABLE));
        assert_eq!(pin.tx_test().unwrap().head(), 2);
        assert_eq!(socket.kick_packet_tx_ring(None), Ok(0));
    }
}

#[test]
fn v3_status_is_at_twenty_and_nonzero_next_offset_is_wrong_format() {
    let (socket, pin, device, _) = fixture(crate::uapi::TPACKET_V3, RAW, false);
    let frame = raw(3);
    publish(&pin, 0, frame.len() as u32, &frame, 8);
    assert_eq!(socket.kick_packet_tx_ring(None), Err(crate::NetError::Einval));
    assert!(device.frames().is_empty());
    assert_eq!(pin.tx_test().unwrap().status(0), Some(crate::uapi::TP_STATUS_WRONG_FORMAT));
    let mut next = [0u8; 4]; assert!(pin.read(0, &mut next));
    assert_eq!(u32::from_ne_bytes(next), 8);
}

#[test]
fn packet_loss_skips_bad_frames_but_sticky_mode_stops_at_the_bad_head() {
    let good = raw(4);
    let (sticky, pin, device, _) = fixture(crate::uapi::TPACKET_V2, RAW, false);
    publish(&pin, 0, 4096, &[], 0);
    publish(&pin, 1, good.len() as u32, &good, 0);
    assert_eq!(sticky.kick_packet_tx_ring(None), Err(crate::NetError::Emsgsize));
    assert_eq!(pin.tx_test().unwrap().status(0), Some(crate::uapi::TP_STATUS_WRONG_FORMAT));
    assert_eq!(pin.tx_test().unwrap().status(1), Some(crate::uapi::TP_STATUS_SEND_REQUEST));
    assert!(device.frames().is_empty());

    let (lossy, pin, device, _) = fixture(crate::uapi::TPACKET_V2, RAW, true);
    publish(&pin, 0, 4096, &[], 0);
    publish(&pin, 1, good.len() as u32, &good, 0);
    assert_eq!(lossy.kick_packet_tx_ring(None), Ok(good.len()));
    assert_eq!(device.frames(), vec![good]);
    assert_eq!(pin.tx_test().unwrap().head(), 2);
}

#[test]
fn datagram_ring_builds_header_from_one_explicit_batch_destination() {
    let (socket, pin, device, iface) = fixture(crate::uapi::TPACKET_V1, DGRAM, false);
    let payload = vec![9u8; 32];
    publish(&pin, 0, payload.len() as u32, &payload, 0);
    let address = PacketTxAddress { ifindex: iface, protocol: 0,
        address: [8, 7, 6, 5, 4, 3, 0, 0], name_len: 20 };
    assert_eq!(socket.kick_packet_tx_ring(Some(address)), Ok(payload.len()));
    let frames = device.frames();
    assert_eq!(&frames[0][..6], &[8, 7, 6, 5, 4, 3]);
    assert_eq!(&frames[0][6..12], &[2, 3, 4, 5, 6, 7]);
    assert_eq!(&frames[0][12..14], &[0, 0]);
    assert_eq!(&frames[0][14..], &payload);
}

#[test]
fn current_head_ownership_drives_tx_ring_writable_state_without_transmitting() {
    let (socket, pin, device, _) = fixture(crate::uapi::TPACKET_V1, RAW, false);
    assert_eq!(socket.packet_tx_ring_writable(), Some(true));
    let frame = raw(5); publish(&pin, 0, frame.len() as u32, &frame, 0);
    assert_eq!(socket.packet_tx_ring_writable(), Some(false));
    assert!(device.frames().is_empty());
    let generation = socket.poll_subs.generation();
    assert_eq!(socket.kick_packet_tx_ring(None), Ok(frame.len()));
    assert_eq!(socket.packet_tx_ring_writable(), Some(true));
    assert!(socket.poll_subs.generation() > generation);
}

#[test]
fn device_error_restores_request_and_does_not_discard_under_packet_loss() {
    let (socket, pin, device, _) = fixture(crate::uapi::TPACKET_V2, RAW, true);
    device.fail_at.store(0, Ordering::Release);
    let frame = raw(6); publish(&pin, 0, frame.len() as u32, &frame, 0);
    assert_eq!(socket.kick_packet_tx_ring(None), Err(crate::NetError::Eio));
    assert_eq!(pin.tx_test().unwrap().status(0), Some(crate::uapi::TP_STATUS_SEND_REQUEST));
    assert_eq!(pin.tx_test().unwrap().head(), 0);
    device.fail_at.store(usize::MAX, Ordering::Release);
    assert_eq!(socket.kick_packet_tx_ring(None), Ok(frame.len()));
}

#[test]
fn concurrent_kicks_consume_each_requested_frame_exactly_once() {
    let (socket, pin, device, _) = fixture(crate::uapi::TPACKET_V1, RAW, false);
    for index in 0..4 {
        let frame = raw(index as u8 + 10);
        publish(&pin, index, frame.len() as u32, &frame, 0);
    }
    let a = socket.clone(); let b = socket.clone();
    let first = std::thread::spawn(move || a.kick_packet_tx_ring(None));
    let second = std::thread::spawn(move || b.kick_packet_tx_ring(None));
    let total = first.join().unwrap().unwrap() + second.join().unwrap().unwrap();
    assert_eq!(total, 4 * 64);
    assert_eq!(device.frames().len(), 4);
    assert_eq!(pin.tx_test().unwrap().head(), 0);
}

#[test]
fn close_serializes_with_active_kick_and_mmap_keeps_completed_bytes_alive() {
    let (socket, pin, device, _) = fixture(crate::uapi::TPACKET_V2, RAW, false);
    let frame = raw(20); publish(&pin, 0, frame.len() as u32, &frame, 0);
    let entered = Arc::new(Barrier::new(2)); let release = Arc::new(Barrier::new(2));
    device.block(entered.clone(), release.clone());
    let sender = socket.clone();
    let kick = std::thread::spawn(move || sender.kick_packet_tx_ring(None));
    entered.wait();
    let closing = socket.clone();
    let close = std::thread::spawn(move || closing.release_file());
    assert_eq!(pin.tx_test().unwrap().status(0), Some(crate::uapi::TP_STATUS_SENDING));
    release.wait();
    assert_eq!(kick.join().unwrap(), Ok(frame.len()));
    close.join().unwrap();
    assert_eq!(pin.tx_test().unwrap().status(0), Some(crate::uapi::TP_STATUS_AVAILABLE));
    assert_eq!(socket.kick_packet_tx_ring(None), Err(crate::NetError::Ebusy));
}

#[test]
fn malformed_or_device_error_after_progress_keeps_exact_completed_prefix() {
    let (socket, pin, device, _) = fixture(crate::uapi::TPACKET_V2, RAW, false);
    let first = raw(21); publish(&pin, 0, first.len() as u32, &first, 0);
    publish(&pin, 1, 4096, &[], 0);
    assert_eq!(socket.kick_packet_tx_ring(None), Err(crate::NetError::Emsgsize));
    assert_eq!(device.frames(), vec![first]);
    assert_eq!(pin.tx_test().unwrap().status(0), Some(crate::uapi::TP_STATUS_AVAILABLE));
    assert_eq!(pin.tx_test().unwrap().status(1), Some(crate::uapi::TP_STATUS_WRONG_FORMAT));
    assert_eq!(pin.tx_test().unwrap().head(), 1);

    let (socket, pin, device, _) = fixture(crate::uapi::TPACKET_V2, RAW, false);
    device.fail_at.store(1, Ordering::Release);
    let first = raw(22); let second = raw(23);
    publish(&pin, 0, first.len() as u32, &first, 0);
    publish(&pin, 1, second.len() as u32, &second, 0);
    assert_eq!(socket.kick_packet_tx_ring(None), Err(crate::NetError::Eio));
    assert_eq!(pin.tx_test().unwrap().status(0), Some(crate::uapi::TP_STATUS_AVAILABLE));
    assert_eq!(pin.tx_test().unwrap().status(1), Some(crate::uapi::TP_STATUS_SEND_REQUEST));
    assert_eq!(pin.tx_test().unwrap().head(), 1);
}

#[test]
fn one_generation_lease_covers_the_batch_and_blocks_interface_retirement() {
    let (socket, pin, device, iface) = fixture(crate::uapi::TPACKET_V1, RAW, false);
    let first = raw(24); let second = raw(25);
    publish(&pin, 0, first.len() as u32, &first, 0);
    publish(&pin, 1, second.len() as u32, &second, 0);
    let entered = Arc::new(Barrier::new(2)); let release = Arc::new(Barrier::new(2));
    device.block(entered.clone(), release.clone());
    let net_ns = socket.net_ns();
    let sender = socket.clone();
    let kick = std::thread::spawn(move || sender.kick_packet_tx_ring(None));
    entered.wait();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let teardown = std::thread::spawn(move || {
        done_tx.send(stack().teardown_iface_in(net_ns, crate::NetIfaceId::from_raw(iface))).unwrap();
    });
    while stack().ifaces.acquire_egress_in_ns(crate::NetIfaceId::from_raw(iface), net_ns).is_some() {
        std::thread::yield_now();
    }
    assert!(matches!(done_rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));
    release.wait();
    assert_eq!(kick.join().unwrap(), Ok(first.len() + second.len()));
    assert!(done_rx.recv().unwrap()); teardown.join().unwrap();
    assert_eq!(device.frames(), vec![first, second]);
    assert!(stack().ifaces.acquire_egress_in_ns(
        crate::NetIfaceId::from_raw(iface), net_ns).is_none());
}

#[test]
fn destination_resolution_preserves_missing_foreign_down_and_short_address_errors() {
    let (socket, _pin, _device, iface) = fixture(crate::uapi::TPACKET_V1, RAW, false);
    if let SockKind::Packet { ifindex, .. } = &*socket.kind.lock() {
        ifindex.store(0, Ordering::Release);
    }
    assert_eq!(socket.kick_packet_tx_ring(None), Err(crate::NetError::Enodev));

    let (foreign, _pin, _device, _) = fixture(crate::uapi::TPACKET_V1, RAW, false);
    let address = PacketTxAddress { ifindex: iface, protocol: crate::eth_p::IPV4,
        address: [0; 8], name_len: 20 };
    assert_eq!(foreign.kick_packet_tx_ring(Some(address)), Err(crate::NetError::Enodev));

    let (down, _pin, _device, iface) = fixture(crate::uapi::TPACKET_V1, RAW, false);
    {
        let rtnl = stack().rtnl_lock();
        stack().ifaces.set_iface_flags_in_ns(&rtnl, crate::NetIfaceId::from_raw(iface),
            down.net_ns(), 0, crate::netdev::iff::IFF_UP).unwrap();
    }
    assert_eq!(down.kick_packet_tx_ring(None), Err(crate::NetError::Enetdown));

    let (dgram, _pin, _device, iface) = fixture(crate::uapi::TPACKET_V1, DGRAM, false);
    let short = PacketTxAddress { ifindex: iface, protocol: crate::eth_p::IPV4,
        address: [0; 8], name_len: 17 };
    assert_eq!(dgram.kick_packet_tx_ring(Some(short)), Err(crate::NetError::Einval));
}
