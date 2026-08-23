//! Evaluation context: everything a rule walk may read about the packet
//! beyond its bytes, plus the effects it records.

extern crate alloc;
use alloc::vec::Vec;

use crate::nft_expr::access::{CtAccess, ObjectAccess, OsfAccess, RouteAccess,
                              SocketAccess, SynproxyAccess, TunnelAccess, XfrmAccess};
use crate::nft_expr::action::Action;
use crate::nft_expr::limits::{ETH_ALEN, IFNAMSIZ};
use crate::nft_expr::stateful::ExprStates;
use crate::nft_expr::uapi::NFPROTO_IPV4;

/// Set-membership callback: set id, set name and the key bytes taken from the
/// source register. The caller owns table/family resolution.
pub type SetLookupFn<'a> = &'a dyn Fn(Option<usize>, &str, &[u8]) -> bool;

/// One interface as the meta keys see it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IfInfo {
    pub index: u32,
    pub name: [u8; IFNAMSIZ],
    /// Driver family name, the `kind` keys report.
    pub kind: [u8; IFNAMSIZ],
    pub iftype: u16,
    pub group: u32,
}

impl Default for IfInfo {
    fn default() -> Self {
        Self { index: 0, name: [0; IFNAMSIZ], kind: [0; IFNAMSIZ], iftype: 0, group: 0 }
    }
}

/// Packet properties the meta keys read. An absent field breaks any rule
/// asking for it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct PktMeta {
    /// Link-layer protocol of the packet, network order value in host form.
    pub protocol: Option<u16>,
    pub l4proto: Option<u8>,
    pub priority: u32,
    pub iif: Option<IfInfo>,
    pub oif: Option<IfInfo>,
    pub sdif: Option<IfInfo>,
    pub bri_iif: Option<IfInfo>,
    pub bri_oif: Option<IfInfo>,
    pub bri_iif_pvid: Option<u16>,
    pub bri_iif_vproto: Option<u16>,
    pub bri_iif_hwaddr: Option<[u8; ETH_ALEN]>,
    pub bri_broute: Option<u8>,
    pub skuid: Option<u32>,
    pub skgid: Option<u32>,
    pub rtclassid: Option<u32>,
    pub secmark: u32,
    pub pkttype: Option<u8>,
    pub cpu: u32,
    pub cgroup: Option<u32>,
    pub prandom: u32,
    pub secpath: bool,
    pub nftrace: bool,
    /// Wall-clock nanoseconds, and the local day and second-of-day derived
    /// from it. Absent when the clock is not available.
    pub time_ns: Option<u64>,
    pub time_day: Option<u8>,
    pub time_hour: Option<u32>,
    /// Fragment offset; a non-zero value hides the transport header.
    pub fragoff: u16,
}

/// One rule evaluation's inputs, mutable packet state and recorded effects.
pub struct EvalCtx<'a> {
    pub pkt: &'a [u8],
    /// Link-layer header, when the hook runs where one is still present.
    pub ll: &'a [u8],
    /// Decapsulated inner packet, for the inner-header payload base.
    pub inner: &'a [u8],
    pub family: u8,
    pub hook: u8,
    pub mark: u32,
    pub meta: PktMeta,
    pub ct: Option<&'a dyn CtAccess>,
    pub route: Option<&'a dyn RouteAccess>,
    pub socket: Option<&'a dyn SocketAccess>,
    pub xfrm: Option<&'a dyn XfrmAccess>,
    pub tunnel: Option<&'a dyn TunnelAccess>,
    pub osf: Option<&'a dyn OsfAccess>,
    pub synproxy: Option<&'a dyn SynproxyAccess>,
    pub objects: Option<&'a dyn ObjectAccess>,
    pub set_lookup: Option<SetLookupFn<'a>>,
    /// Monotonic nanoseconds; the token bucket and `last` read it.
    pub now_ns: u64,
    /// Random word the random number generator and the prandom key consume.
    pub random: u32,
    /// Processor the packet is being handled on.
    pub cpu: u32,
    /// Per-rule state for the expressions that count between packets.
    pub states: &'a ExprStates,
    pub actions: Vec<Action>,
    /// Raw-priority `notrack` state, consumed before the conntrack hook.
    pub notrack: bool,
    pub packets: u64,
    pub bytes: u64,
}

impl<'a> EvalCtx<'a> {
    /// Context in which no subsystem lookup is available: every expression
    /// reading one breaks, and nothing is fabricated. # C: O(1)
    pub fn new(pkt: &'a [u8], family: u8, states: &'a ExprStates) -> Self {
        Self {
            pkt, ll: &[], inner: &[], family, hook: 0, mark: 0, meta: PktMeta::default(),
            ct: None, route: None, socket: None, xfrm: None, tunnel: None, osf: None,
            synproxy: None, objects: None,
            set_lookup: None, now_ns: 0, random: 0, cpu: 0, states,
            actions: Vec::new(), packets: 0, bytes: 0,
            notrack: false,
        }
    }

    /// Context for an IPv4 packet with no subsystem lookups. # C: O(1)
    pub fn ipv4(pkt: &'a [u8], states: &'a ExprStates) -> Self {
        Self::new(pkt, NFPROTO_IPV4, states)
    }

    /// Length the length-valued keys and the byte-rate accounting report.
    /// # C: O(1)
    pub fn pkt_len(&self) -> u32 { self.pkt.len() as u32 }
}
