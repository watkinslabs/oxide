use super::*;
use alloc::sync::{Arc, Weak};
use std::sync::{Barrier, Condvar, Mutex};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(2);

struct GateState {
    block_next: bool,
    fail_next: bool,
    entered: bool,
    release: bool,
    records: Vec<u8>,
}

struct OrderedXmitDev {
    state: Mutex<GateState>,
    changed: Condvar,
    reentry: Mutex<Option<Reentry>>,
}

enum Reentry {
    V4 { stack: Weak<NetStack>, iface: crate::NetIfaceId, group: Ipv4Addr, source: Ipv4Addr },
    V6 { stack: Weak<NetStack>, iface: crate::NetIfaceId, group: Ipv6Addr, source: Ipv6Addr },
}

impl OrderedXmitDev {
    fn new() -> Self {
        Self { state: Mutex::new(GateState {
            block_next: false, fail_next: false, entered: false, release: false, records: Vec::new(),
        }), changed: Condvar::new(), reentry: Mutex::new(None) }
    }

    fn arm(&self) {
        let mut state = self.state.lock().unwrap();
        state.records.clear();
        state.block_next = true;
        state.fail_next = false;
        state.entered = false;
        state.release = false;
    }

    fn arm_failure(&self) {
        self.arm();
        self.state.lock().unwrap().fail_next = true;
    }

    fn wait_until_blocked(&self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut state = self.state.lock().unwrap();
        while !state.entered {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.release = true;
                self.changed.notify_all();
                panic!("multicast report did not reach xmit gate");
            }
            let (next, _) = self.changed.wait_timeout(state, remaining).unwrap();
            state = next;
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.release = true;
        self.changed.notify_all();
    }

    fn records(&self) -> Vec<u8> { self.state.lock().unwrap().records.clone() }

    fn clear(&self) { self.state.lock().unwrap().records.clear(); }

    fn reenter(&self, action: Reentry) {
        self.clear();
        *self.reentry.lock().unwrap() = Some(action);
    }
}

impl crate::NetDev for OrderedXmitDev {
    fn name(&self) -> &str { "mcast-order" }
    fn mac(&self) -> crate::MacAddr { crate::MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, pkt: crate::Pkt) -> crate::NetResult<()> {
        let data = pkt.data();
        let record = match data[0] >> 4 {
            4 => data[32],
            6 => data[56],
            _ => panic!("unexpected multicast report protocol"),
        };
        let fail = {
            let mut state = self.state.lock().unwrap();
            state.records.push(record);
            if state.block_next {
                state.block_next = false;
                state.entered = true;
                self.changed.notify_all();
                while !state.release { state = self.changed.wait(state).unwrap(); }
            }
            let fail = state.fail_next;
            state.fail_next = false;
            fail
        };
        match self.reentry.lock().unwrap().take() {
            Some(Reentry::V4 { stack, iface, group, source }) =>
                stack.upgrade().unwrap().join_ipv4_multicast(iface, group, source).unwrap(),
            Some(Reentry::V6 { stack, iface, group, source }) =>
                stack.upgrade().unwrap().join_ipv6_multicast(iface, group, source).unwrap(),
            None => {}
        }
        if fail { Err(crate::NetError::Eio) } else { Ok(()) }
    }
}

fn wait_for_generation(mut generation: impl FnMut() -> u64, expected: u64) {
    let deadline = Instant::now() + WAIT;
    while generation() < expected {
        if Instant::now() >= deadline { panic!("new multicast generation was not published"); }
        std::thread::yield_now();
    }
}

fn finish_initial_v4(stack: &NetStack, iface: crate::NetIfaceId, group: Ipv4Addr,
                     source: Ipv4Addr) {
    stack.join_ipv4_multicast(iface, group, source).unwrap();
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
}

fn finish_initial_v6(stack: &NetStack, iface: crate::NetIfaceId, group: Ipv6Addr,
                     source: Ipv6Addr) {
    stack.join_ipv6_multicast(iface, group, source).unwrap();
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
}

#[test]
fn igmp_leave_blocked_in_xmit_precedes_concurrent_rejoin() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = Arc::new(NetStack::new());
    let dev = Arc::new(OrderedXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let group = Ipv4Addr::new(239, 7, 8, 40);
    let source = Ipv4Addr::new(10, 0, 0, 1);
    finish_initial_v4(&stack, iface, group, source);
    let initial = stack.v4_mcast.lock()[&iface][0].generation;

    dev.arm();
    let leaving = stack.clone();
    let leave = std::thread::spawn(move || leaving.leave_ipv4_multicast(iface, group, source));
    dev.wait_until_blocked();
    let joining = stack.clone();
    let join = std::thread::spawn(move || joining.join_ipv4_multicast(iface, group, source));
    wait_for_generation(|| stack.v4_mcast.lock()[&iface][0].generation, initial + 2);
    dev.release();
    leave.join().unwrap().unwrap();
    join.join().unwrap().unwrap();

    assert_eq!(dev.records(), alloc::vec![
        crate::igmp::IGMP_V3_RECORD_CHANGE_TO_INCLUDE,
        crate::igmp::IGMP_V3_RECORD_CHANGE_TO_EXCLUDE,
    ]);
}

#[test]
fn mld_leave_blocked_in_xmit_precedes_concurrent_rejoin() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = Arc::new(NetStack::new());
    let dev = Arc::new(OrderedXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x3344]);
    let source = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    finish_initial_v6(&stack, iface, group, source);
    let initial = stack.v6_mcast.lock()[&iface][0].generation;

    dev.arm();
    let leaving = stack.clone();
    let leave = std::thread::spawn(move || leaving.leave_ipv6_multicast(iface, group, source));
    dev.wait_until_blocked();
    let joining = stack.clone();
    let join = std::thread::spawn(move || joining.join_ipv6_multicast(iface, group, source));
    wait_for_generation(|| stack.v6_mcast.lock()[&iface][0].generation, initial + 2);
    dev.release();
    leave.join().unwrap().unwrap();
    join.join().unwrap().unwrap();

    assert_eq!(dev.records(), alloc::vec![
        crate::icmpv6::MLDV2_RECORD_CHANGE_TO_INCLUDE,
        crate::icmpv6::MLDV2_RECORD_CHANGE_TO_EXCLUDE,
    ]);
}

#[test]
fn teardown_during_blocked_xmit_removes_v4_and_v6_state() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = Arc::new(NetStack::new());
    let dev = Arc::new(OrderedXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let group4 = Ipv4Addr::new(239, 7, 8, 41);
    let source4 = Ipv4Addr::new(10, 0, 0, 1);
    let group6 = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x3345]);
    let source6 = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    finish_initial_v4(&stack, iface, group4, source4);
    finish_initial_v6(&stack, iface, group6, source6);

    dev.arm();
    let leaving = stack.clone();
    let leave = std::thread::spawn(move || leaving.leave_ipv4_multicast(iface, group4, source4));
    dev.wait_until_blocked();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let removing = stack.clone();
    std::thread::spawn(move || { let _ = done_tx.send(removing.unregister_iface(iface)); });
    assert_eq!(done_rx.recv_timeout(Duration::from_millis(20)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout));
    dev.release();
    assert_eq!(done_rx.recv_timeout(WAIT), Ok(true));
    leave.join().unwrap().unwrap();
    assert!(!stack.v4_mcast.lock().contains_key(&iface));
    assert!(!stack.v6_mcast.lock().contains_key(&iface));
}

#[test]
fn igmp_xmit_reentry_emits_leave_then_correction_without_deadlock() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = Arc::new(NetStack::new());
    let dev = Arc::new(OrderedXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let group = Ipv4Addr::new(239, 7, 8, 42);
    let source = Ipv4Addr::new(10, 0, 0, 1);
    finish_initial_v4(&stack, iface, group, source);
    dev.reenter(Reentry::V4 { stack: Arc::downgrade(&stack), iface, group, source });

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let leaving = stack.clone();
    std::thread::spawn(move || {
        let _ = done_tx.send(leaving.leave_ipv4_multicast(iface, group, source));
    });
    assert_eq!(done_rx.recv_timeout(WAIT), Ok(Ok(())));
    assert_eq!(dev.records(), alloc::vec![
        crate::igmp::IGMP_V3_RECORD_CHANGE_TO_INCLUDE,
        crate::igmp::IGMP_V3_RECORD_CHANGE_TO_EXCLUDE,
    ]);
}

#[test]
fn mld_xmit_reentry_emits_leave_then_correction_without_deadlock() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = Arc::new(NetStack::new());
    let dev = Arc::new(OrderedXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x3346]);
    let source = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    finish_initial_v6(&stack, iface, group, source);
    dev.reenter(Reentry::V6 { stack: Arc::downgrade(&stack), iface, group, source });

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let leaving = stack.clone();
    std::thread::spawn(move || {
        let _ = done_tx.send(leaving.leave_ipv6_multicast(iface, group, source));
    });
    assert_eq!(done_rx.recv_timeout(WAIT), Ok(Ok(())));
    assert_eq!(dev.records(), alloc::vec![
        crate::icmpv6::MLDV2_RECORD_CHANGE_TO_INCLUDE,
        crate::icmpv6::MLDV2_RECORD_CHANGE_TO_EXCLUDE,
    ]);
}

fn concurrent_deadline(stack: Arc<NetStack>, dev: Arc<OrderedXmitDev>) {
    const WORKERS: usize = 4;
    let barrier = Arc::new(Barrier::new(WORKERS + 1));
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    for _ in 0..WORKERS {
        let worker = stack.clone();
        let start = barrier.clone();
        let done = done_tx.clone();
        std::thread::spawn(move || {
            start.wait();
            worker.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
            let _ = done.send(());
        });
    }
    dev.arm();
    barrier.wait();
    dev.wait_until_blocked();
    dev.release();
    for _ in 0..WORKERS { done_rx.recv_timeout(WAIT).unwrap(); }
}

#[test]
fn concurrent_igmp_timers_consume_one_deadline_attempt() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = Arc::new(NetStack::new());
    let dev = Arc::new(OrderedXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let group = Ipv4Addr::new(239, 7, 8, 43);
    let source = Ipv4Addr::new(10, 0, 0, 1);
    stack.join_ipv4_multicast(iface, group, source).unwrap();
    concurrent_deadline(stack, dev.clone());
    assert_eq!(dev.records(), alloc::vec![crate::igmp::IGMP_V3_RECORD_CHANGE_TO_EXCLUDE]);
}

#[test]
fn concurrent_mld_timers_consume_one_deadline_attempt() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = Arc::new(NetStack::new());
    let dev = Arc::new(OrderedXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x3347]);
    let source = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    stack.join_ipv6_multicast(iface, group, source).unwrap();
    concurrent_deadline(stack, dev.clone());
    assert_eq!(dev.records(), alloc::vec![crate::icmpv6::MLDV2_RECORD_CHANGE_TO_EXCLUDE]);
}

#[test]
fn stale_igmp_query_waiting_on_report_serializer_is_dropped() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = Arc::new(NetStack::new());
    let dev = Arc::new(OrderedXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let ingress = stack.ifaces.acquire_ingress(iface).unwrap();
    let group = Ipv4Addr::new(239, 7, 8, 49);
    let host = Ipv4Addr::new(10, 0, 0, 1);
    let source = Ipv4Addr::new(10, 0, 0, 9);
    let filter = crate::mcast_filter::SourceFilter {
        mode: crate::mcast_filter::FilterMode::Include, sources: alloc::vec![source],
    };
    stack.set_ipv4_multicast(7, iface, group, host, Some(&filter)).unwrap();

    dev.arm();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let retrying = stack.clone();
    std::thread::spawn(move || {
        retrying.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
        let _ = done_tx.send(());
    });
    dev.wait_until_blocked();
    let query = crate::igmp::build_igmpv3_query(group, 10, &[]);
    stack.handle_igmp(&ingress, Ipv4Addr::new(10, 0, 0, 2), group, &query).unwrap();
    assert_eq!(stack.v4_mcast.lock()[&iface][0].queries.len(), 1);
    stack.release_ipv4_multicast(7, iface, group, host);
    assert!(stack.v4_mcast.lock()[&iface][0].queries.is_empty());
    dev.release();
    done_rx.recv_timeout(WAIT).unwrap();

    assert_eq!(dev.records(), alloc::vec![
        crate::igmp::IGMP_V3_RECORD_CHANGE_TO_INCLUDE,
        crate::igmp::IGMP_V3_RECORD_BLOCK_OLD_SOURCES,
    ]);
}

#[test]
fn stale_mld_query_waiting_on_report_serializer_is_dropped() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = Arc::new(NetStack::new());
    let dev = Arc::new(OrderedXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let ingress = stack.ifaces.acquire_ingress(iface).unwrap();
    let group = Ipv6Addr::from_segments([0xff3e,0,0,0,0,0,0,0x3349]);
    let host = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let source = Ipv6Addr::from_segments([0x2001,0xdb8,0,0,0,0,0,9]);
    let filter = crate::mcast_filter::SourceFilter6 {
        mode: crate::mcast_filter::FilterMode::Include, sources: alloc::vec![source],
    };
    stack.set_ipv6_multicast(7, iface, group, host, Some(&filter)).unwrap();

    dev.arm();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let retrying = stack.clone();
    std::thread::spawn(move || {
        retrying.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
        let _ = done_tx.send(());
    });
    dev.wait_until_blocked();
    stack.respond_mld_query(&ingress, group, crate::icmpv6::Mldv1Query {
        max_resp_delay: 1000, group, sources: alloc::vec::Vec::new(), qrv: 2, qqic: 125,
    }, false).unwrap();
    assert_eq!(stack.v6_mcast.lock()[&iface][0].queries.len(), 1);
    stack.release_ipv6_multicast(7, iface, group, host);
    assert!(stack.v6_mcast.lock()[&iface][0].queries.is_empty());
    dev.release();
    done_rx.recv_timeout(WAIT).unwrap();

    assert_eq!(dev.records(), alloc::vec![
        crate::icmpv6::MLDV2_RECORD_CHANGE_TO_INCLUDE,
        crate::icmpv6::MLDV2_RECORD_BLOCK_OLD_SOURCES,
    ]);
}

#[test]
fn igmp_failed_reported_retransmission_corrects_from_router_baseline() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = Arc::new(NetStack::new());
    let dev = Arc::new(OrderedXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let group = Ipv4Addr::new(239, 7, 8, 44);
    let source = Ipv4Addr::new(10, 0, 0, 1);
    stack.join_ipv4_multicast(iface, group, source).unwrap();
    let generation = {
        let state = stack.v4_mcast.lock();
        let entry = &state[&iface][0];
        assert!(entry.change.as_ref().is_some_and(|change| change.reported));
        entry.generation
    };

    dev.arm_failure();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let retrying = stack.clone();
    std::thread::spawn(move || {
        retrying.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
        let _ = done_tx.send(());
    });
    dev.wait_until_blocked();
    stack.leave_ipv4_multicast(iface, group, source).unwrap();
    assert_eq!(stack.v4_mcast.lock()[&iface][0].generation, generation + 1);
    dev.release();
    done_rx.recv_timeout(WAIT).unwrap();

    assert_eq!(dev.records(), alloc::vec![
        crate::igmp::IGMP_V3_RECORD_CHANGE_TO_EXCLUDE,
        crate::igmp::IGMP_V3_RECORD_CHANGE_TO_INCLUDE,
    ]);
    assert!(stack.v4_mcast.lock()[&iface][0].change.as_ref().is_some_and(|change| {
        matches!(change.report, crate::mcast_state::V4Report::Tomb)
            && change.reported && change.remaining == 1
    }));
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS * 2);
    assert_eq!(dev.records(), alloc::vec![
        crate::igmp::IGMP_V3_RECORD_CHANGE_TO_EXCLUDE,
        crate::igmp::IGMP_V3_RECORD_CHANGE_TO_INCLUDE,
        crate::igmp::IGMP_V3_RECORD_CHANGE_TO_INCLUDE,
    ]);
    assert!(!stack.v4_mcast.lock().contains_key(&iface));
}

#[test]
fn mld_failed_reported_retransmission_corrects_from_router_baseline() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = Arc::new(NetStack::new());
    let dev = Arc::new(OrderedXmitDev::new());
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x3348]);
    let source = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    stack.join_ipv6_multicast(iface, group, source).unwrap();
    let generation = {
        let state = stack.v6_mcast.lock();
        let entry = &state[&iface][0];
        assert!(entry.change.as_ref().is_some_and(|change| change.reported));
        entry.generation
    };

    dev.arm_failure();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let retrying = stack.clone();
    std::thread::spawn(move || {
        retrying.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
        let _ = done_tx.send(());
    });
    dev.wait_until_blocked();
    stack.leave_ipv6_multicast(iface, group, source).unwrap();
    assert_eq!(stack.v6_mcast.lock()[&iface][0].generation, generation + 1);
    dev.release();
    done_rx.recv_timeout(WAIT).unwrap();

    assert_eq!(dev.records(), alloc::vec![
        crate::icmpv6::MLDV2_RECORD_CHANGE_TO_EXCLUDE,
        crate::icmpv6::MLDV2_RECORD_CHANGE_TO_INCLUDE,
    ]);
    assert!(stack.v6_mcast.lock()[&iface][0].change.as_ref().is_some_and(|change| {
        matches!(change.report, crate::mcast_state::V6Report::Tomb)
            && change.reported && change.remaining == 1
    }));
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS * 2);
    assert_eq!(dev.records(), alloc::vec![
        crate::icmpv6::MLDV2_RECORD_CHANGE_TO_EXCLUDE,
        crate::icmpv6::MLDV2_RECORD_CHANGE_TO_INCLUDE,
        crate::icmpv6::MLDV2_RECORD_CHANGE_TO_INCLUDE,
    ]);
    assert!(!stack.v6_mcast.lock().contains_key(&iface));
}
