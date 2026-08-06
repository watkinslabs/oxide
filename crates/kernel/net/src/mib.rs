// Per-namespace SNMP counters, as `/proc/net/snmp` reports them.
//
// The file used to be a hardcoded table of zeroes. That is worse than absent:
// a reader cannot tell a counter that has not moved from one nothing keeps,
// and `Ip: InReceives 0 OutRequests 0` on a guest that had moved packets read
// as a dead stack during a live investigation. Every value here is now counted
// where its event happens, so a zero means the event has not occurred.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ops::Deref;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Socket as MibLockClass, Spinlock};

const INITIAL_NET_NS: u64 = 0;

/// One counted event. Named for the `/proc/net/snmp` column it feeds, so a
/// call site says which line of the file it moves.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Mib {
    IpInReceives,
    IpInHdrErrors,
    IpInAddrErrors,
    IpForwDatagrams,
    IpInUnknownProtos,
    IpInDiscards,
    IpInDelivers,
    IpOutRequests,
    IpOutNoRoutes,
    IpFragOks,
    IpFragFails,
    IpFragCreates,
    IcmpInMsgs,
    IcmpInErrors,
    IcmpOutMsgs,
    IcmpInEchos,
    IcmpInEchoReps,
    IcmpOutEchos,
    IcmpOutEchoReps,
    IcmpInDestUnreachs,
    IcmpOutDestUnreachs,
    TcpActiveOpens,
    TcpPassiveOpens,
    TcpAttemptFails,
    TcpEstabResets,
    TcpInSegs,
    TcpOutSegs,
    TcpRetransSegs,
    TcpInErrs,
    TcpOutRsts,
    UdpInDatagrams,
    UdpNoPorts,
    UdpInErrors,
    UdpOutDatagrams,
    UdpRcvbufErrors,
    UdpSndbufErrors,
    UdpInCsumErrors,
}

/// Number of distinct counters, and the index each `Mib` occupies.
const COUNTERS: usize = 37;

/// One extended TCP event reported by `/proc/net/netstat`'s `TcpExt` row.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TcpExt {
    TcpFastOpenPassive,
    TcpFastOpenPassiveFail,
    TcpFastOpenPassiveAltKey,
    TcpFastOpenCookieReqd,
    TcpFastOpenListenOverflow,
}

const TCP_EXT_COUNTERS: usize = 5;

impl TcpExt {
    /// # C: O(1)
    const fn index(self) -> usize { self as usize }
}

impl Mib {
    /// # C: O(1)
    const fn index(self) -> usize { self as usize }
}

struct Counters {
    snmp: [AtomicU64; COUNTERS],
    tcp_ext: [AtomicU64; TCP_EXT_COUNTERS],
}

impl Counters {
    const fn new() -> Self {
        Self {
            snmp: [const { AtomicU64::new(0) }; COUNTERS],
            tcp_ext: [const { AtomicU64::new(0) }; TCP_EXT_COUNTERS],
        }
    }
}

/// Dynamic namespace state is read from NET_RX and changed by namespace
/// teardown. Keep Linux `spin_lock_bh` semantics in the type so no caller can
/// take the table lock while allowing the receive bottom half to interrupt it.
struct MibNamespaceLock(Spinlock<BTreeMap<u64, alloc::sync::Arc<Counters>>, MibLockClass>);

impl MibNamespaceLock {
    const fn new() -> Self { Self(Spinlock::new(BTreeMap::new())) }

    fn lock(&self) -> sync::LockBhGuard<'_, BTreeMap<u64, alloc::sync::Arc<Counters>>,
        MibLockClass, sched::bh::SchedBh>
    {
        self.0.lock_bh::<sched::bh::SchedBh>()
    }
}

static INITIAL_COUNTERS: Counters = Counters::new();
static NAMESPACES: MibNamespaceLock = MibNamespaceLock::new();

enum CounterRef {
    Initial(&'static Counters),
    Dynamic(alloc::sync::Arc<Counters>),
}

impl Deref for CounterRef {
    type Target = Counters;
    fn deref(&self) -> &Counters {
        match self { Self::Initial(c) => c, Self::Dynamic(c) => c }
    }
}

fn counters(net_ns: u64) -> CounterRef {
    // The initial namespace is immortal and owns virtually all production
    // traffic. Linux reaches its per-net MIB storage through a direct pointer;
    // do the same here instead of taking a global BTreeMap lock per packet.
    if net_ns == INITIAL_NET_NS { return CounterRef::Initial(&INITIAL_COUNTERS); }
    CounterRef::Dynamic(NAMESPACES.lock().entry(net_ns)
        .or_insert_with(|| alloc::sync::Arc::new(Counters::new())).clone())
}

/// Count one event in `net_ns`. # C: O(log N namespaces)
pub fn bump(net_ns: u64, which: Mib) {
    counters(net_ns).snmp[which.index()].fetch_add(1, Ordering::Relaxed);
}

/// Count `n` occurrences of one event in `net_ns`. # C: O(log N namespaces)
pub fn add(net_ns: u64, which: Mib, n: u64) {
    counters(net_ns).snmp[which.index()].fetch_add(n, Ordering::Relaxed);
}

/// Current value of one counter in `net_ns`. # C: O(log N namespaces)
pub fn get(net_ns: u64, which: Mib) -> u64 {
    counters(net_ns).snmp[which.index()].load(Ordering::Relaxed)
}

/// Every counter of `net_ns`, in `Mib` order. # C: O(COUNTERS)
pub fn snapshot(net_ns: u64) -> Vec<u64> {
    let c = counters(net_ns);
    c.snmp.iter().map(|v| v.load(Ordering::Relaxed)).collect()
}

/// Count one extended TCP event in `net_ns`. # C: O(log N namespaces)
pub fn bump_tcp_ext(net_ns: u64, which: TcpExt) {
    counters(net_ns).tcp_ext[which.index()].fetch_add(1, Ordering::Relaxed);
}

/// Current value of one extended TCP event in `net_ns`. # C: O(log N namespaces)
pub fn get_tcp_ext(net_ns: u64, which: TcpExt) -> u64 {
    counters(net_ns).tcp_ext[which.index()].load(Ordering::Relaxed)
}

/// Drop a namespace's counters when it goes away. # C: O(log N)
pub fn forget(net_ns: u64) {
    if net_ns != INITIAL_NET_NS { NAMESPACES.lock().remove(&net_ns); }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: u64 = 0x5150;

    #[test]
    fn every_variant_has_its_own_slot() {
        // A shared slot would make one event move another's column.
        let all = [
            Mib::IpInReceives, Mib::IpInHdrErrors, Mib::IpInAddrErrors, Mib::IpForwDatagrams,
            Mib::IpInUnknownProtos, Mib::IpInDiscards, Mib::IpInDelivers, Mib::IpOutRequests,
            Mib::IpOutNoRoutes, Mib::IpFragOks, Mib::IpFragFails, Mib::IpFragCreates,
            Mib::IcmpInMsgs, Mib::IcmpInErrors, Mib::IcmpOutMsgs, Mib::IcmpInEchos,
            Mib::IcmpInEchoReps, Mib::IcmpOutEchos, Mib::IcmpOutEchoReps,
            Mib::IcmpInDestUnreachs, Mib::IcmpOutDestUnreachs,
            Mib::TcpActiveOpens, Mib::TcpPassiveOpens, Mib::TcpAttemptFails,
            Mib::TcpEstabResets, Mib::TcpInSegs, Mib::TcpOutSegs, Mib::TcpRetransSegs,
            Mib::TcpInErrs, Mib::TcpOutRsts,
            Mib::UdpInDatagrams, Mib::UdpNoPorts, Mib::UdpInErrors, Mib::UdpOutDatagrams,
            Mib::UdpRcvbufErrors, Mib::UdpSndbufErrors, Mib::UdpInCsumErrors,
        ];
        assert_eq!(all.len(), COUNTERS, "every counter is listed");
        let mut seen = alloc::vec![false; COUNTERS];
        for m in all {
            assert!(!seen[m.index()], "{m:?} shares a slot");
            seen[m.index()] = true;
        }
    }

    #[test]
    fn initial_namespace_updates_bypass_the_dynamic_table() {
        assert!(!NAMESPACES.lock().contains_key(&INITIAL_NET_NS));
        bump(INITIAL_NET_NS, Mib::IpInReceives);
        assert!(!NAMESPACES.lock().contains_key(&INITIAL_NET_NS));
    }

    #[test]
    fn a_counted_event_moves_only_its_own_column() {
        forget(NS);
        bump(NS, Mib::IpInReceives);
        bump(NS, Mib::IpInReceives);
        add(NS, Mib::UdpOutDatagrams, 5);
        assert_eq!(get(NS, Mib::IpInReceives), 2);
        assert_eq!(get(NS, Mib::UdpOutDatagrams), 5);
        assert_eq!(get(NS, Mib::IpOutRequests), 0, "an event that never happened reads zero");
        forget(NS);
    }

    #[test]
    fn namespaces_count_separately() {
        forget(1); forget(2);
        bump(1, Mib::IpInReceives);
        assert_eq!(get(1, Mib::IpInReceives), 1);
        assert_eq!(get(2, Mib::IpInReceives), 0);
        forget(1); forget(2);
    }

    #[test]
    fn a_forgotten_namespace_starts_over() {
        forget(NS);
        bump(NS, Mib::TcpInSegs);
        assert_eq!(get(NS, Mib::TcpInSegs), 1);
        forget(NS);
        assert_eq!(get(NS, Mib::TcpInSegs), 0);
    }

    #[test]
    fn a_snapshot_reports_every_counter_in_order() {
        forget(NS);
        bump(NS, Mib::IpInReceives);
        add(NS, Mib::UdpInDatagrams, 3);
        let snap = snapshot(NS);
        assert_eq!(snap.len(), COUNTERS);
        assert_eq!(snap[Mib::IpInReceives.index()], 1);
        assert_eq!(snap[Mib::UdpInDatagrams.index()], 3);
        forget(NS);
    }
}

/// Linux `IPDEFTTL`, reported as `/proc/net/snmp`'s `DefaultTTL`.
const IPV4_DEFAULT_TTL: u8 = 64;

/// Render `/proc/net/snmp` for one namespace.
///
/// Lives here rather than in procfs because the procfs half is compiled only
/// for the kernel: a test written beside it is never built and never runs.
/// `forwarding` and `established` are the two values the file reports that are
/// state rather than counted events.
/// # C: O(COUNTERS)
pub fn render_proc_snmp(net_ns: u64, forwarding: bool, established: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let v = |m: Mib| get(net_ns, m);
    let mut s = alloc::string::String::new();
    let _ = writeln!(s, "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors \
ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes \
ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates");
    let _ = writeln!(s, "Ip: {} {} {} {} {} {} {} {} {} {} 0 {} 0 0 0 0 {} {} {}",
        // The reference reports 1 for a forwarding host and 2 for a host that
        // does not forward.
        if forwarding { 1 } else { 2 }, IPV4_DEFAULT_TTL,
        v(Mib::IpInReceives), v(Mib::IpInHdrErrors), v(Mib::IpInAddrErrors),
        v(Mib::IpForwDatagrams), v(Mib::IpInUnknownProtos), v(Mib::IpInDiscards),
        v(Mib::IpInDelivers), v(Mib::IpOutRequests), v(Mib::IpOutNoRoutes),
        v(Mib::IpFragOks), v(Mib::IpFragFails), v(Mib::IpFragCreates));
    let _ = writeln!(s, "Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds \
InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps \
InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs \
OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps \
OutAddrMasks OutAddrMaskReps");
    let _ = writeln!(s, "Icmp: {} {} 0 {} 0 0 0 0 {} {} 0 0 0 0 {} 0 {} 0 0 0 0 {} {} 0 0 0 0",
        v(Mib::IcmpInMsgs), v(Mib::IcmpInErrors), v(Mib::IcmpInDestUnreachs),
        v(Mib::IcmpInEchos), v(Mib::IcmpInEchoReps),
        v(Mib::IcmpOutMsgs), v(Mib::IcmpOutDestUnreachs),
        v(Mib::IcmpOutEchos), v(Mib::IcmpOutEchoReps));
    let _ = writeln!(s, "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens \
AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors");
    let _ = writeln!(s, "Tcp: 1 200 120000 -1 {} {} {} {} {} {} {} {} {} {} 0",
        v(Mib::TcpActiveOpens), v(Mib::TcpPassiveOpens), v(Mib::TcpAttemptFails),
        v(Mib::TcpEstabResets), established,
        v(Mib::TcpInSegs), v(Mib::TcpOutSegs), v(Mib::TcpRetransSegs),
        v(Mib::TcpInErrs), v(Mib::TcpOutRsts));
    let _ = writeln!(s, "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors \
SndbufErrors InCsumErrors IgnoredMulti");
    let _ = writeln!(s, "Udp: {} {} {} {} {} {} {} 0",
        v(Mib::UdpInDatagrams), v(Mib::UdpNoPorts), v(Mib::UdpInErrors),
        v(Mib::UdpOutDatagrams), v(Mib::UdpRcvbufErrors), v(Mib::UdpSndbufErrors),
        v(Mib::UdpInCsumErrors));
    s.into_bytes()
}

/// Render `/proc/net/netstat` for one namespace. # C: O(TCP_EXT_COUNTERS)
pub fn render_proc_netstat(net_ns: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let v = |m: TcpExt| get_tcp_ext(net_ns, m);
    let mut s = alloc::string::String::new();
    let _ = writeln!(s, "TcpExt: TCPFastOpenPassive TCPFastOpenPassiveFail \
TCPFastOpenPassiveAltKey TCPFastOpenCookieReqd TCPFastOpenListenOverflow");
    let _ = writeln!(s, "TcpExt: {} {} {} {} {}",
        v(TcpExt::TcpFastOpenPassive), v(TcpExt::TcpFastOpenPassiveFail),
        v(TcpExt::TcpFastOpenPassiveAltKey), v(TcpExt::TcpFastOpenCookieReqd),
        v(TcpExt::TcpFastOpenListenOverflow));
    s.into_bytes()
}

#[cfg(test)]
mod render_tests {
    use super::*;

    // Tests run in parallel in one binary, so each owns a distinct namespace:
    // sharing one makes a `forget` in one test erase another's counters.
    const NS_COLUMNS: u64 = 0x5309;
    const NS_SHAPE: u64 = 0x530a;
    const NS_ISOLATION: u64 = 0x530b;
    const NS_STATE: u64 = 0x530d;

    fn body_of(ns: u64) -> alloc::string::String {
        alloc::string::String::from_utf8(render_proc_snmp(ns, false, 0)).unwrap()
    }

    fn column(text: &str, row: &str, name: &str) -> i64 {
        let mut lines = text.lines().filter(|l| l.starts_with(row));
        let header: Vec<&str> = lines.next().unwrap().split_whitespace().collect();
        let values: Vec<&str> = lines.next().unwrap().split_whitespace().collect();
        let at = header.iter().position(|h| *h == name).expect("column present");
        values[at].parse().expect("a number")
    }

    /// The file used to be a hardcoded table of zeroes, which reads as a dead
    /// stack on a guest that has moved packets — and did, during a live
    /// investigation. Every value is counted where its event happens.
    #[test]
    fn a_counted_event_appears_in_its_column() {
        const NS: u64 = NS_COLUMNS;
        forget(NS);
        for _ in 0..3 { bump(NS, Mib::IpInReceives); }
        bump(NS, Mib::UdpInDatagrams);
        bump(NS, Mib::IcmpInEchos);
        let text = body_of(NS);
        assert_eq!(column(&text, "Ip:", "InReceives"), 3);
        assert_eq!(column(&text, "Udp:", "InDatagrams"), 1);
        assert_eq!(column(&text, "Icmp:", "InEchos"), 1);
        // An event that has not happened reads zero, truthfully.
        assert_eq!(column(&text, "Ip:", "OutRequests"), 0);
        forget(NS);
    }

    #[test]
    fn every_row_has_one_value_per_header_name() {
        const NS: u64 = NS_SHAPE;
        forget(NS);
        let text = body_of(NS);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 8, "four protocols, a header and a value row each");
        for pair in lines.chunks(2) {
            assert_eq!(pair[0].split_whitespace().count(), pair[1].split_whitespace().count(),
                "row {:?} has a name/value mismatch", pair[0].split_whitespace().next().unwrap());
        }
        forget(NS);
    }

    #[test]
    fn the_counters_are_per_namespace() {
        const NS: u64 = NS_ISOLATION;
        forget(NS); forget(NS + 1);
        bump(NS, Mib::IpInReceives);
        assert_eq!(column(&body_of(NS), "Ip:", "InReceives"), 1);
        let other = alloc::string::String::from_utf8(render_proc_snmp(NS + 1, false, 0)).unwrap();
        assert_eq!(column(&other, "Ip:", "InReceives"), 0);
        forget(NS); forget(NS + 1);
    }

    #[test]
    fn forwarding_and_established_are_reported_as_state_not_counts() {
        const NS: u64 = NS_STATE;
        forget(NS);
        assert_eq!(column(&body_of(NS), "Ip:", "Forwarding"), 2, "2 = does not forward");
        let on = alloc::string::String::from_utf8(render_proc_snmp(NS, true, 7)).unwrap();
        assert_eq!(column(&on, "Ip:", "Forwarding"), 1);
        assert_eq!(column(&on, "Tcp:", "CurrEstab"), 7);
        forget(NS);
    }

    #[test]
    fn tcp_fast_open_events_render_in_their_tcp_ext_columns() {
        const NS: u64 = 0x530e;
        forget(NS);
        bump_tcp_ext(NS, TcpExt::TcpFastOpenPassive);
        bump_tcp_ext(NS, TcpExt::TcpFastOpenPassiveAltKey);
        let text = alloc::string::String::from_utf8(render_proc_netstat(NS)).unwrap();
        assert_eq!(column(&text, "TcpExt:", "TCPFastOpenPassive"), 1);
        assert_eq!(column(&text, "TcpExt:", "TCPFastOpenPassiveAltKey"), 1);
        assert_eq!(column(&text, "TcpExt:", "TCPFastOpenCookieReqd"), 0);
        forget(NS);
    }
}
