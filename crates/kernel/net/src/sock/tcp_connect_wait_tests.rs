use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use super::InetSocket;
use crate::Ipv4Addr;

#[test]
fn blocking_tcp_connect_parks_on_the_transport_queue_and_wakes_established() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let sock = Arc::new(InetSocket::new_tcp());
    sock.opts.base.sndtimeo_ns.store(5_000_000_000, Ordering::Release);
    let stack = crate::NetStack::new();
    let (iface, loopback) = stack.register_loopback();
    let _listener = stack.tcp_listen(Ipv4Addr::LOOPBACK, 40_002, true).unwrap();
    let entry = stack.tcp_connect(Ipv4Addr::LOOPBACK, 40_001,
        Ipv4Addr::LOOPBACK, 40_002).unwrap();
    let finished = Arc::new(AtomicBool::new(false));

    std::thread::scope(|scope| {
        let waiter_sock = sock.clone();
        let waiter_entry = entry.clone();
        let waiter_finished = finished.clone();
        let join = scope.spawn(move || {
            let result = super::tcp_connect_wait::connect_wait_established(
                &waiter_sock, &waiter_entry);
            waiter_finished.store(true, Ordering::Release);
            result
        });
        crate::hosted_fixture::spin_until("TCP connect publishes on its transport queue", ||
            entry.poll_subs.sleep().has_waiters());
        assert!(!finished.load(Ordering::Acquire), "connect returned before transport publication");
        crate::hosted_fixture::spin_until("loopback TCP handshake reaches established", || {
            stack.drain_loopback(iface, &loopback);
            entry.conn.lock().state.is_established()
        });
        assert_eq!(join.join().unwrap(), Ok(()));
    });
}
