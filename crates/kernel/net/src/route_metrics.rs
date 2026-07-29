//! Linux-visible IPv4 route metric state.

use crate::TcpCongestionControl;

pub const RTAX_MTU: u16 = 2;
pub const RTAX_CWND: u16 = 7;
pub const RTAX_RTO_MIN: u16 = 13;
pub const RTAX_CC_ALGO: u16 = 16;

pub const RTAX_FEATURE_ECN: u32 = 1 << 0;
pub const RTAX_FEATURE_SACK: u32 = 1 << 1;
pub const RTAX_FEATURE_TIMESTAMP: u32 = 1 << 2;
pub const RTAX_FEATURE_ALLFRAG: u32 = 1 << 3;
pub const RTAX_FEATURE_TCP_USEC_TS: u32 = 1 << 4;

/// Complete IPv4 route metric state carried by `RTA_METRICS`.
///
/// A zero scalar has the same meaning as an absent nested attribute. `lock`
/// uses the ABI metric number as its bit position.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RouteMetrics {
    pub lock: u32,
    pub mtu: u32,
    pub window: u32,
    pub rtt_ms: u32,
    pub rttvar_ms: u32,
    pub ssthresh: u32,
    pub cwnd: u32,
    pub advmss: u32,
    pub reordering: u32,
    pub hoplimit: u32,
    pub initcwnd: u32,
    pub features: u32,
    pub rto_min_ms: u32,
    pub initrwnd: u32,
    pub quickack: u32,
    pub cc_algo: Option<TcpCongestionControl>,
    pub fastopen_no_cookie: u32,
}

impl RouteMetrics {
    pub const NONE: Self = Self {
        lock: 0,
        mtu: 0,
        window: 0,
        rtt_ms: 0,
        rttvar_ms: 0,
        ssthresh: 0,
        cwnd: 0,
        advmss: 0,
        reordering: 0,
        hoplimit: 0,
        initcwnd: 0,
        features: 0,
        rto_min_ms: 0,
        initrwnd: 0,
        quickack: 0,
        cc_algo: None,
        fastopen_no_cookie: 0,
    };

    /// Linux `dst_metric_locked`: RTAX_LOCK bit positions are metric ids. # C: O(1)
    pub const fn locked(self, metric: u16) -> bool {
        metric < u32::BITS as u16 && self.lock & (1u32 << metric) != 0
    }

    /// Route-configured MTU bounded by the actual output device. # C: O(1)
    pub const fn bounded_mtu(self, link_mtu: u32) -> u32 {
        if self.mtu == 0 || self.mtu > link_mtu { link_mtu } else { self.mtu }
    }

    /// Route hoplimit or the namespace's current IPv4 default. # C: O(1)
    pub const fn ipv4_hoplimit(self, default: u8) -> u8 {
        if self.hoplimit == 0 { default } else { self.hoplimit as u8 }
    }

    /// Whether any metric would be emitted in an `RTA_METRICS` nest. # C: O(1)
    pub const fn is_empty(self) -> bool {
        self.lock == 0
            && self.mtu == 0
            && self.window == 0
            && self.rtt_ms == 0
            && self.rttvar_ms == 0
            && self.ssthresh == 0
            && self.cwnd == 0
            && self.advmss == 0
            && self.reordering == 0
            && self.hoplimit == 0
            && self.initcwnd == 0
            && self.features == 0
            && self.rto_min_ms == 0
            && self.initrwnd == 0
            && self.quickack == 0
            && self.cc_algo.is_none()
            && self.fastopen_no_cookie == 0
    }
}

impl Default for RouteMetrics {
    fn default() -> Self { Self::NONE }
}
