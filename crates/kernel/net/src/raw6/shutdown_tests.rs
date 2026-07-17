use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use super::Raw6Endpoint;
use crate::addr::Ipv6Addr;
use crate::raw6::{Raw6RxDisposition, Raw6RxPacket};

fn endpoint() -> Raw6Endpoint { Raw6Endpoint::standalone(network_namespace::initial(), 143) }

#[test]
fn shutdown_before_arm_rejects_wait_registration() {
    let endpoint = endpoint();
    let read_shut = AtomicBool::new(false);
    endpoint.shutdown_read(&read_shut);

    assert!(!endpoint.arm_recv_wait_with(&read_shut, || panic!("armed after shutdown")));
}

#[test]
fn arm_before_shutdown_wakes_after_latch_publication() {
    let endpoint = endpoint();
    let read_shut = AtomicBool::new(false);
    let (armed_tx, armed_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (started_tx, started_rx) = mpsc::channel();
    let (wake_tx, wake_rx) = mpsc::channel();

    std::thread::scope(|scope| {
        let endpoint = &endpoint;
        let read_shut = &read_shut;
        scope.spawn(move || {
            assert!(endpoint.arm_recv_wait_with(read_shut, || {
                armed_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            }));
        });
        armed_rx.recv().unwrap();
        scope.spawn(move || {
            started_tx.send(()).unwrap();
            endpoint.shutdown_read_with(read_shut, || {
                assert!(read_shut.load(Ordering::Acquire));
                wake_tx.send(()).unwrap();
            });
        });
        started_rx.recv().unwrap();
        assert!(wake_rx.recv_timeout(Duration::from_millis(10)).is_err());
        release_tx.send(()).unwrap();
        wake_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    });
}

#[test]
fn queued_datagram_drains_before_shutdown_eof() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let endpoint = endpoint();
    let read_shut = AtomicBool::new(false);
    let stack = crate::NetStack::new();
    let (iface, _) = stack.register_loopback();
    let payload = alloc::vec![1, 2, 3];
    assert_eq!(endpoint.receive(Raw6RxPacket {
        net_ns: 0, protocol: 143, src: Ipv6Addr::LOOPBACK,
        dst: Ipv6Addr::LOOPBACK, iface, hop_limit: 64, traffic_class: 0,
        flow_label: 0, hatype: 0, payload: &payload,
    }), Raw6RxDisposition::Queued);

    endpoint.shutdown_read(&read_shut);
    assert_eq!(endpoint.recv(false).unwrap().payload, payload);
    assert!(endpoint.recv(false).is_none());
    assert!(read_shut.load(Ordering::Acquire));
}

#[test]
fn close_latches_terminal_poll_state() {
    let endpoint = endpoint();
    assert!(endpoint.is_accepting());
    endpoint.close();
    assert!(!endpoint.is_accepting());
}
