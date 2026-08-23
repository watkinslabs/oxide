//! Lookups an expression needs from a subsystem outside the interpreter.
//!
//! Every method defaults to "the source is not available". An expression
//! whose input is absent breaks the rule, which is what the reference does
//! when the same lookup fails — it never substitutes a fabricated value.

extern crate alloc;
use alloc::sync::Arc;

use conntrack::tuple::{InetAddr, Tuple};

use crate::nft_expr::limits::IFNAMSIZ;

/// Connection-tracking view of the packet under evaluation.
pub trait CtAccess {
    /// Conntrack-info class the packet carries. # C: O(1)
    fn ctinfo(&self) -> u8;
    /// Whether an entry is attached; false still permits a `state` read.
    /// # C: O(1)
    fn attached(&self) -> bool { false }
    /// Whether the attached entry is a template rather than a real flow.
    /// # C: O(1)
    fn template(&self) -> bool { false }
    /// # C: O(1)
    fn status(&self) -> u32 { 0 }
    /// # C: O(1)
    fn mark(&self) -> u32 { 0 }
    /// # C: O(1)
    fn set_mark(&self, _value: u32) {}
    /// # C: O(1)
    fn secmark(&self) -> u32 { 0 }
    /// # C: O(1)
    fn set_secmark(&self, _value: u32) {}
    /// Remaining lifetime in milliseconds. # C: O(1)
    fn expiration_ms(&self) -> u32 { 0 }
    /// Helper name, zero-padded; false when no helper is attached. # C: O(1)
    fn helper(&self, _out: &mut [u8]) -> bool { false }
    /// # C: O(1)
    fn labels(&self, _out: &mut [u8]) -> bool { false }
    /// # C: O(1)
    fn set_labels(&self, _value: &[u8]) {}
    /// # C: O(1)
    fn eventmask(&self) -> u32 { 0 }
    /// # C: O(1)
    fn set_eventmask(&self, _value: u32) {}
    /// Packets and bytes seen in one direction. # C: O(1)
    fn counters(&self, _dir: u8) -> (u64, u64) { (0, 0) }
    /// # C: O(1)
    fn tuple(&self, _dir: u8) -> Option<Tuple> { None }
    /// # C: O(1)
    fn zone(&self) -> u16 { 0 }
    /// Attach a zone template when nothing is attached yet. # C: O(1)
    fn set_zone(&self, _zone: u16) {}
    /// # C: O(1)
    fn id(&self) -> u32 { 0 }
    /// Whether the entry may be handed to a software flow table: confirmed,
    /// established, no helper, no sequence adjustment, not already offloaded.
    /// # C: O(1)
    fn offloadable(&self) -> bool { false }
    /// Number of tracked connections sharing this flow's source, after adding
    /// the current packet. `None` when the count cannot be maintained.
    /// # C: O(N conns on the list)
    fn connlimit_count(&self, _index: usize) -> Option<u32> { None }
    /// The canonical connection object, when the packet is tracked. # C: O(1)
    fn flow(&self) -> Option<Arc<conntrack::Conn>> { None }
    /// Attach a named helper through the owning conntrack registry. # C: O(N helpers)
    fn set_helper(&self, _name: &str, _l4proto: u8) -> bool { false }
    /// Install a protocol timeout extension on the unconfirmed flow.
    fn set_timeout_policy(&self, _l3num: u16, _l4proto: u8, _values: &[u32; 14], _now: u64) -> bool { false }
    /// Announce a related flow through the owning expectation table.
    fn set_expectation(&self, _l3num: u16, _l4proto: u8, _dport: u16,
                       _timeout_ms: u32, _size: u8, _now: u64) -> bool { false }
}

/// One route lookup's answer.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct FibEntry {
    /// Absent for a locally delivered route, which has no output interface.
    pub oif: Option<u32>,
    pub oifname: [u8; IFNAMSIZ],
    pub addrtype: u32,
}

/// What a `fib` expression asks the routing table.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct FibKey {
    pub family: u8,
    pub addr: InetAddr,
    pub mark: u32,
    pub dscp: u8,
    pub iif: Option<u32>,
    pub oif: Option<u32>,
}

/// Routing state attached to the packet.
pub trait RouteAccess {
    /// # C: O(1)
    fn classid(&self) -> Option<u32> { None }
    /// # C: O(1)
    fn nexthop4(&self) -> Option<[u8; 4]> { None }
    /// # C: O(1)
    fn nexthop6(&self) -> Option<[u8; 16]> { None }
    /// Advertisable maximum segment size for the path. # C: O(1)
    fn tcpmss(&self) -> Option<u16> { None }
    /// Whether the route carries a transform. # C: O(1)
    fn transformed(&self) -> bool { false }
    /// Source address routing chose for the egress interface — what a
    /// masquerade maps onto. # C: O(1)
    fn src_addr(&self) -> Option<InetAddr> { None }
    /// Primary address of the interface a redirected packet arrived on.
    /// # C: O(1)
    fn iface_addr(&self) -> Option<InetAddr> { None }
    /// # C: O(log N routes)
    fn fib(&self, _key: &FibKey) -> Option<FibEntry> { None }
}

/// Socket owning, or listening for, the packet.
pub trait SocketAccess {
    /// # C: O(1)
    fn present(&self) -> bool { false }
    /// Whether the socket is a full socket rather than a request or
    /// time-wait stub — the mark and wildcard keys need one. # C: O(1)
    fn full(&self) -> bool { false }
    /// # C: O(1)
    fn transparent(&self) -> bool { false }
    /// # C: O(1)
    fn mark(&self) -> u32 { 0 }
    /// Whether the socket is bound to the any-address. # C: O(1)
    fn wildcard(&self) -> bool { false }
    /// Control-group id at an ancestor level. # C: O(level)
    fn cgroup_id(&self, _level: u32) -> Option<u64> { None }
    /// Whether a transparent socket exists for a redirected target.
    /// # C: O(log N sockets)
    fn tproxy_transparent(&self, _addr: &InetAddr, _port: u16) -> bool { false }
}

/// One transform on the packet's security path or its route.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct XfrmState {
    pub family: u8,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub reqid: u32,
    pub spi: u32,
    /// Address keys are only meaningful for a tunnel-like mode.
    pub tunnel_mode: bool,
}

/// Transform state reachable from the packet.
pub trait XfrmAccess {
    /// State at `spnum` on the inbound security path, or on the outbound
    /// route's transform chain. # C: O(spnum)
    fn state(&self, _dir: u32, _spnum: u32) -> Option<XfrmState> { None }
}

/// Tunnel metadata attached to the packet.
pub trait TunnelAccess {
    /// Whether metadata is present for the requested direction. # C: O(1)
    fn present(&self, _mode: u32) -> bool { false }
    /// # C: O(1)
    fn id(&self, _mode: u32) -> Option<u32> { None }
}

/// Passive operating-system fingerprint matcher.
pub trait OsfAccess {
    /// Genre string for the packet, zero-padded into `out`. # C: O(N prints)
    fn genre(&self, _ttl: u8, _with_version: bool, _out: &mut [u8]) -> bool { false }
}

/// Cookie machinery a `synproxy` needs to complete a handshake on behalf of
/// the protected host.
pub trait SynproxyAccess {
    /// Window scale encoded in the acknowledged cookie, or `None` when the
    /// cookie does not verify. # C: O(1)
    fn cookie_valid(&self, _seq: u32, _ack: u32) -> Option<u16> { None }
}

/// Stateful objects a rule may reference by name or through a set element.
pub trait ObjectAccess {
    /// Run the named object's own evaluation, returning the verdict it set,
    /// or `None` when no such object exists. # C: O(cost of the object)
    fn eval(&self, _family: u8, _table: &str, _obj_type: u32, _name: &str,
            _pkt_len: u64, _now_ns: u64, _ct: Option<&dyn CtAccess>) -> Option<i32> { None }
    /// Run an object with access to packet effects needed by object types that
    /// own an action, while retaining the simple hook above for objects that
    /// only return a verdict.
    fn eval_with(&self, family: u8, table: &str, obj_type: u32, name: &str,
                 _pkt: &[u8], pkt_len: u64, now_ns: u64,
                 ct: Option<&dyn CtAccess>, _synproxy: Option<&dyn SynproxyAccess>,
                 _actions: &mut alloc::vec::Vec<crate::nft_expr::action::Action>) -> Option<i32> {
        self.eval(family, table, obj_type, name, pkt_len, now_ns, ct)
    }
    /// Object an element of `set` points at, keyed by the register bytes.
    /// # C: O(cost of the set lookup)
    fn eval_from_set(&self, _family: u8, _table: &str, _set_id: Option<usize>,
                     _set: &str, _key: &[u8], _pkt_len: u64, _now_ns: u64,
                     _ct: Option<&dyn CtAccess>) -> Option<i32> {
        None
    }

    fn eval_from_set_with(&self, family: u8, table: &str, set_id: Option<usize>,
                          set: &str, key: &[u8], _pkt: &[u8], pkt_len: u64, now_ns: u64,
                          ct: Option<&dyn CtAccess>, _synproxy: Option<&dyn SynproxyAccess>,
                          _actions: &mut alloc::vec::Vec<crate::nft_expr::action::Action>) -> Option<i32> {
        self.eval_from_set(family, table, set_id, set, key, pkt_len, now_ns, ct)
    }
}
