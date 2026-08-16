//! `/proc/sys/net/netfilter/` tunables. Every value here changes what the
//! tracker accepts, so each one is a policy knob with a security consequence,
//! not a performance hint.

use crate::proto::icmp::{GenericSysctl, IcmpSysctl};
use crate::proto::tcp::TcpSysctl;
use crate::proto::tcp_state::*;
use crate::proto::udp::{UDP_CT_REPLIED, UDP_CT_UNREPLIED, UdpSysctl};

/// Whole per-namespace tunable set.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CtSysctl {
    pub tcp: TcpSysctl,
    pub udp: UdpSysctl,
    pub icmp: IcmpSysctl,
    pub icmpv6: IcmpSysctl,
    pub generic: GenericSysctl,
    /// Verify L4 checksums on the input path before tracking.
    pub checksum: bool,
    /// Deliver ctnetlink events at all.
    pub events: bool,
    /// Log packets the trackers reject.
    pub log_invalid: u8,
    /// Attach helpers automatically by port. Off by default because a helper
    /// bound purely on a port number is a payload parser an attacker chooses.
    pub helper: bool,
    /// Accept the accounting extension's per-direction counters.
    pub acct: bool,
    /// Entry ceiling.
    pub max: u64,
    /// Bucket count, read-only after construction.
    pub buckets: u32,
}

impl Default for CtSysctl {
    fn default() -> Self {
        Self {
            tcp: TcpSysctl::default(),
            udp: UdpSysctl::default(),
            icmp: IcmpSysctl::default(),
            icmpv6: IcmpSysctl::default(),
            generic: GenericSysctl::default(),
            checksum: true,
            events: true,
            log_invalid: 0,
            helper: false,
            acct: false,
            max: crate::limits::CT_MAX_DEFAULT,
            buckets: crate::limits::CT_HASH_BUCKETS as u32,
        }
    }
}

/// One tunable's name, as it appears under `/proc/sys/net/netfilter/`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Knob {
    TcpTimeoutSynSent, TcpTimeoutSynRecv, TcpTimeoutEstablished, TcpTimeoutFinWait,
    TcpTimeoutCloseWait, TcpTimeoutLastAck, TcpTimeoutTimeWait, TcpTimeoutClose,
    TcpTimeoutSynSent2, TcpTimeoutMaxRetrans, TcpTimeoutUnacknowledged,
    TcpLoose, TcpBeLiberal, TcpIgnoreInvalidRst, TcpMaxRetrans,
    UdpTimeout, UdpTimeoutStream,
    IcmpTimeout, Icmpv6Timeout, GenericTimeout,
    Checksum, Events, LogInvalid, Helper, Acct, Max, Buckets,
}

/// Every tunable, with the name the proc surface uses. Order matches the
/// enum so a reader can index either way.
pub const KNOBS: &[(&str, Knob)] = &[
    ("nf_conntrack_tcp_timeout_syn_sent",       Knob::TcpTimeoutSynSent),
    ("nf_conntrack_tcp_timeout_syn_recv",       Knob::TcpTimeoutSynRecv),
    ("nf_conntrack_tcp_timeout_established",    Knob::TcpTimeoutEstablished),
    ("nf_conntrack_tcp_timeout_fin_wait",       Knob::TcpTimeoutFinWait),
    ("nf_conntrack_tcp_timeout_close_wait",     Knob::TcpTimeoutCloseWait),
    ("nf_conntrack_tcp_timeout_last_ack",       Knob::TcpTimeoutLastAck),
    ("nf_conntrack_tcp_timeout_time_wait",      Knob::TcpTimeoutTimeWait),
    ("nf_conntrack_tcp_timeout_close",          Knob::TcpTimeoutClose),
    ("nf_conntrack_tcp_timeout_syn_sent2",      Knob::TcpTimeoutSynSent2),
    ("nf_conntrack_tcp_timeout_max_retrans",    Knob::TcpTimeoutMaxRetrans),
    ("nf_conntrack_tcp_timeout_unacknowledged", Knob::TcpTimeoutUnacknowledged),
    ("nf_conntrack_tcp_loose",                  Knob::TcpLoose),
    ("nf_conntrack_tcp_be_liberal",             Knob::TcpBeLiberal),
    ("nf_conntrack_tcp_ignore_invalid_rst",     Knob::TcpIgnoreInvalidRst),
    ("nf_conntrack_tcp_max_retrans",            Knob::TcpMaxRetrans),
    ("nf_conntrack_udp_timeout",                Knob::UdpTimeout),
    ("nf_conntrack_udp_timeout_stream",         Knob::UdpTimeoutStream),
    ("nf_conntrack_icmp_timeout",               Knob::IcmpTimeout),
    ("nf_conntrack_icmpv6_timeout",             Knob::Icmpv6Timeout),
    ("nf_conntrack_generic_timeout",            Knob::GenericTimeout),
    ("nf_conntrack_checksum",                   Knob::Checksum),
    ("nf_conntrack_events",                     Knob::Events),
    ("nf_conntrack_log_invalid",                Knob::LogInvalid),
    ("nf_conntrack_helper",                     Knob::Helper),
    ("nf_conntrack_acct",                       Knob::Acct),
    ("nf_conntrack_max",                        Knob::Max),
    ("nf_conntrack_buckets",                    Knob::Buckets),
];

/// Resolve a proc name to its knob. # C: O(N_knobs)
pub fn knob_by_name(name: &str) -> Option<Knob> {
    KNOBS.iter().find(|(n, _)| *n == name).map(|(_, k)| *k)
}

impl CtSysctl {
    /// Current value of one knob. # C: O(1)
    pub fn get(&self, k: Knob) -> u64 {
        let t = &self.tcp.timeouts;
        match k {
            Knob::TcpTimeoutSynSent    => t[TCP_CONNTRACK_SYN_SENT as usize] as u64,
            Knob::TcpTimeoutSynRecv    => t[TCP_CONNTRACK_SYN_RECV as usize] as u64,
            Knob::TcpTimeoutEstablished => t[TCP_CONNTRACK_ESTABLISHED as usize] as u64,
            Knob::TcpTimeoutFinWait    => t[TCP_CONNTRACK_FIN_WAIT as usize] as u64,
            Knob::TcpTimeoutCloseWait  => t[TCP_CONNTRACK_CLOSE_WAIT as usize] as u64,
            Knob::TcpTimeoutLastAck    => t[TCP_CONNTRACK_LAST_ACK as usize] as u64,
            Knob::TcpTimeoutTimeWait   => t[TCP_CONNTRACK_TIME_WAIT as usize] as u64,
            Knob::TcpTimeoutClose      => t[TCP_CONNTRACK_CLOSE as usize] as u64,
            Knob::TcpTimeoutSynSent2   => t[TCP_CONNTRACK_SYN_SENT2 as usize] as u64,
            Knob::TcpTimeoutMaxRetrans => t[TCP_CONNTRACK_RETRANS as usize] as u64,
            Knob::TcpTimeoutUnacknowledged => t[TCP_CONNTRACK_UNACK as usize] as u64,
            Knob::TcpLoose             => self.tcp.loose as u64,
            Knob::TcpBeLiberal         => self.tcp.be_liberal as u64,
            Knob::TcpIgnoreInvalidRst  => self.tcp.ignore_invalid_rst as u64,
            Knob::TcpMaxRetrans        => self.tcp.max_retrans as u64,
            Knob::UdpTimeout           => self.udp.timeouts[UDP_CT_UNREPLIED] as u64,
            Knob::UdpTimeoutStream     => self.udp.timeouts[UDP_CT_REPLIED] as u64,
            Knob::IcmpTimeout          => self.icmp.timeout as u64,
            Knob::Icmpv6Timeout        => self.icmpv6.timeout as u64,
            Knob::GenericTimeout       => self.generic.timeout as u64,
            Knob::Checksum             => self.checksum as u64,
            Knob::Events               => self.events as u64,
            Knob::LogInvalid           => self.log_invalid as u64,
            Knob::Helper               => self.helper as u64,
            Knob::Acct                 => self.acct as u64,
            Knob::Max                  => self.max,
            Knob::Buckets              => self.buckets as u64,
        }
    }

    /// Apply a write. `false` means the value is out of range for the knob and
    /// the old one stands — a rejected write must not leave a partially
    /// applied tunable. # C: O(1)
    pub fn set(&mut self, k: Knob, v: u64) -> bool {
        let Ok(v32) = u32::try_from(v) else {
            if matches!(k, Knob::Max) { self.max = v; return true; }
            return false;
        };
        let t = &mut self.tcp.timeouts;
        match k {
            Knob::TcpTimeoutSynSent    => t[TCP_CONNTRACK_SYN_SENT as usize] = v32,
            Knob::TcpTimeoutSynRecv    => t[TCP_CONNTRACK_SYN_RECV as usize] = v32,
            Knob::TcpTimeoutEstablished => t[TCP_CONNTRACK_ESTABLISHED as usize] = v32,
            Knob::TcpTimeoutFinWait    => t[TCP_CONNTRACK_FIN_WAIT as usize] = v32,
            Knob::TcpTimeoutCloseWait  => t[TCP_CONNTRACK_CLOSE_WAIT as usize] = v32,
            Knob::TcpTimeoutLastAck    => t[TCP_CONNTRACK_LAST_ACK as usize] = v32,
            Knob::TcpTimeoutTimeWait   => t[TCP_CONNTRACK_TIME_WAIT as usize] = v32,
            Knob::TcpTimeoutClose      => t[TCP_CONNTRACK_CLOSE as usize] = v32,
            Knob::TcpTimeoutSynSent2   => t[TCP_CONNTRACK_SYN_SENT2 as usize] = v32,
            Knob::TcpTimeoutMaxRetrans => t[TCP_CONNTRACK_RETRANS as usize] = v32,
            Knob::TcpTimeoutUnacknowledged => t[TCP_CONNTRACK_UNACK as usize] = v32,
            Knob::TcpLoose             => self.tcp.loose = v32 != 0,
            Knob::TcpBeLiberal         => self.tcp.be_liberal = v32 != 0,
            Knob::TcpIgnoreInvalidRst  => self.tcp.ignore_invalid_rst = v32 != 0,
            Knob::TcpMaxRetrans        => match u8::try_from(v32) {
                Ok(n) => self.tcp.max_retrans = n,
                Err(_) => return false,
            },
            Knob::UdpTimeout           => self.udp.timeouts[UDP_CT_UNREPLIED] = v32,
            Knob::UdpTimeoutStream     => self.udp.timeouts[UDP_CT_REPLIED] = v32,
            Knob::IcmpTimeout          => self.icmp.timeout = v32,
            Knob::Icmpv6Timeout        => self.icmpv6.timeout = v32,
            Knob::GenericTimeout       => self.generic.timeout = v32,
            Knob::Checksum             => self.checksum = v32 != 0,
            Knob::Events               => self.events = v32 != 0,
            Knob::LogInvalid           => match u8::try_from(v32) {
                Ok(n) => self.log_invalid = n,
                Err(_) => return false,
            },
            Knob::Helper               => self.helper = v32 != 0,
            Knob::Acct                 => self.acct = v32 != 0,
            Knob::Max                  => self.max = v,
            // The bucket count is fixed at table construction; accepting a
            // write would report a size the hash does not have.
            Knob::Buckets              => return false,
        }
        true
    }
}
