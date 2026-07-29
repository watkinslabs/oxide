//! New-TCB policy derived from the selected IPv4 route.

use crate::route_metrics::{RTAX_CC_ALGO, RTAX_CWND, RTAX_RTO_MIN};
use crate::{RouteMetrics, TcpConn};

const TCP_RTO_MIN_NS: u64 = 200_000_000;

impl TcpConn {
    /// Apply Linux route metrics before emitting an active SYN or passive SYN-ACK.
    /// Scalar congestion metrics are expressed in MSS units by the route ABI.
    /// # C: O(1)
    pub fn apply_route_metrics(&mut self, metrics: RouteMetrics) {
        if metrics.advmss != 0 {
            let advmss = metrics.advmss.min(u16::MAX as u32) as u16;
            self.own_mss = if self.own_mss == 0 { advmss } else { self.own_mss.min(advmss) };
        }
        let mss = u32::from(if self.own_mss == 0 {
            crate::tcp_conn::OWN_MSS_DEFAULT
        } else { self.own_mss });
        if metrics.window != 0 { self.window_clamp = metrics.window; }
        if metrics.initrwnd != 0 {
            self.rcv_buf_cap = self.rcv_buf_cap.min(metrics.initrwnd.saturating_mul(mss));
        }
        if metrics.rtt_ms != 0 {
            self.srtt_ns = u64::from(metrics.rtt_ms).saturating_mul(1_000_000);
        }
        if metrics.rttvar_ms != 0 {
            self.rttvar_ns = u64::from(metrics.rttvar_ms).saturating_mul(1_000_000);
        }
        if metrics.rto_min_ms != 0 {
            let configured = u64::from(metrics.rto_min_ms).saturating_mul(1_000_000);
            self.rto_min_locked = metrics.locked(RTAX_RTO_MIN);
            self.rto_min_ns = if self.rto_min_locked {
                configured
            } else {
                configured.max(TCP_RTO_MIN_NS)
            };
        }
        if self.srtt_ns != 0 {
            let variance = self.rttvar_ns.saturating_mul(4);
            self.rto_ns = self.srtt_ns.saturating_add(variance.max(10_000_000))
                .max(self.rto_min_ns).min(60_000_000_000);
        }
        if metrics.ssthresh != 0 {
            self.ssthresh = metrics.ssthresh.saturating_mul(mss);
        }
        if metrics.initcwnd != 0 {
            self.cwnd = metrics.initcwnd.saturating_mul(mss);
        }
        if metrics.cwnd != 0 && metrics.locked(RTAX_CWND) {
            self.cwnd_clamp = metrics.cwnd.saturating_mul(mss);
            self.cwnd = self.cwnd.min(self.cwnd_clamp);
        }
        if metrics.reordering != 0 { self.reordering = metrics.reordering; }
        self.route_features = metrics.features;
        self.quickack = metrics.quickack != 0;
        self.fastopen_no_cookie = metrics.fastopen_no_cookie != 0;
        if let Some(congestion) = metrics.cc_algo {
            self.congestion = congestion;
            self.cc_locked = metrics.locked(RTAX_CC_ALGO);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{IpAddr, Ipv4Addr};
    use crate::tcp_conn::{Endpoint, TcpCongestionControl};

    fn conn() -> TcpConn {
        TcpConn::new_client(
            Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 1 },
            Endpoint { ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port: 2 },
            1,
        )
    }

    #[test]
    fn selected_metrics_seed_active_tcb() {
        let mut conn = conn();
        conn.own_mss = 1_400;
        conn.apply_route_metrics(RouteMetrics {
            lock: (1 << RTAX_CWND) | (1 << RTAX_RTO_MIN) | (1 << RTAX_CC_ALGO),
            window: 32_000,
            rtt_ms: 40,
            rttvar_ms: 5,
            ssthresh: 20,
            cwnd: 8,
            advmss: 1_200,
            reordering: 5,
            initcwnd: 12,
            rto_min_ms: 30,
            initrwnd: 4,
            quickack: 1,
            cc_algo: Some(TcpCongestionControl::Reno),
            fastopen_no_cookie: 1,
            ..RouteMetrics::NONE
        });
        assert_eq!((conn.own_mss, conn.congestion, conn.cc_locked),
            (1_200, TcpCongestionControl::Reno, true));
        assert_eq!((conn.cwnd, conn.cwnd_clamp, conn.ssthresh), (9_600, 9_600, 24_000));
        assert_eq!((conn.srtt_ns, conn.rttvar_ns, conn.rto_ns),
            (40_000_000, 5_000_000, 60_000_000));
        assert_eq!((conn.reordering, conn.window_clamp, conn.rcv_buf_cap), (5, 32_000, 4_800));
        assert!(conn.quickack && conn.fastopen_no_cookie && conn.rto_min_locked);
    }

    #[test]
    fn route_selected_reno_uses_configured_reordering_threshold_and_clamp() {
        let mut conn = conn();
        conn.own_mss = 1_000;
        conn.congestion = TcpCongestionControl::Reno;
        conn.reordering = 5;
        conn.cwnd = 20_000;
        conn.cwnd_clamp = 30_000;
        for _ in 0..4 { conn.cc_on_ack(0, 0); }
        assert_eq!((conn.cwnd, conn.ssthresh), (20_000, u32::MAX));
        conn.cc_on_ack(0, 0);
        assert_eq!((conn.cwnd, conn.ssthresh), (15_000, 10_000));
        conn.cc_on_ack(1_000, 0);
        assert!(conn.cwnd <= conn.cwnd_clamp);
    }
}
