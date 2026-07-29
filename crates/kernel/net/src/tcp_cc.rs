// F185 + F187: TCP congestion control. Reno + CUBIC live here so
// tcp_conn.rs stays under the 1000-line cap (docs/08§7). Public
// entry points: `on_ack`, `on_rto`, `icbrt`.

use crate::tcp_conn::{TcpCongestionControl, TcpConn, OWN_MSS_DEFAULT, tcp_now_ms};

/// Effective MSS for cwnd math (own_mss + peer hint). # C: O(1)
pub fn cc_mss(c: &TcpConn) -> u32 {
    let m = if c.own_mss != 0 { c.own_mss } else { OWN_MSS_DEFAULT };
    let m = if c.peer_mss != 0 { core::cmp::min(m, c.peer_mss) } else { m };
    m as u32
}

/// Integer cube-root via Newton iteration. # C: O(log x)
pub fn icbrt(x: u64) -> u64 {
    if x < 2 { return x; }
    let mut r = 1u64 << ((64 - x.leading_zeros() as u64) / 3 + 1);
    loop {
        let r2 = r.saturating_mul(r);
        let nr = (2 * r + x / core::cmp::max(r2, 1)) / 3;
        if nr >= r { return r; }
        r = nr;
    }
}

/// Route-selected congestion-control ACK processing. # C: O(1) amortized
pub fn on_ack(c: &mut TcpConn, acked: u32, payload_len: u32) {
    match c.congestion {
        TcpCongestionControl::Reno => reno_on_ack(c, acked, payload_len),
        TcpCongestionControl::Cubic => cubic_on_ack(c, acked, payload_len),
    }
    c.cwnd = c.cwnd.min(c.cwnd_clamp);
}

/// CUBIC on-ACK (RFC 8312). Slow-start is shared with Reno; CA follows
/// the concave-then-convex cubic curve around W_max. # C: O(1) amortized
fn cubic_on_ack(c: &mut TcpConn, acked: u32, payload_len: u32) {
    let mss = cc_mss(c);
    if acked > 0 {
        c.dup_acks = 0;
        if c.cwnd < c.ssthresh {
            let inc = core::cmp::min(acked, mss);
            c.cwnd = c.cwnd.saturating_add(inc);
        } else {
            let now = tcp_now_ms();
            if c.cubic_epoch_ms == 0 {
                c.cubic_epoch_ms = if now == 0 { 1 } else { now };
                if c.cubic_w_max == 0 || c.cwnd >= c.cubic_w_max {
                    c.cubic_w_max = c.cwnd;
                    c.cubic_k_ms = 0;
                } else {
                    let diff_mss = (c.cubic_w_max - c.cwnd) as u64
                        / core::cmp::max(mss as u64, 1);
                    // K ≈ ∛(diff_mss · 2500)  [C scaled so K is in ms]
                    let k = icbrt(diff_mss.saturating_mul(2500));
                    c.cubic_k_ms = k as u32;
                }
            }
            let t = now.wrapping_sub(c.cubic_epoch_ms) as i64;
            let dt = t - c.cubic_k_ms as i64;
            let dt3 = (dt as i128).saturating_mul(dt as i128).saturating_mul(dt as i128);
            let delta = (dt3 * mss as i128 / 2_500_000) as i64;
            let target = (c.cubic_w_max as i64).saturating_add(delta);
            let target = core::cmp::max(target, mss as i64) as u32;
            if target > c.cwnd {
                let step_acks = core::cmp::max(c.cwnd / mss, 1);
                let step = core::cmp::max((target - c.cwnd) / step_acks, 1);
                c.cwnd = c.cwnd.saturating_add(step);
            }
        }
        return;
    }
    if payload_len == 0 {
        c.dup_acks = c.dup_acks.saturating_add(1);
        let threshold = c.reordering.clamp(1, u8::MAX as u32) as u8;
        if c.dup_acks == threshold {
            cubic_on_loss(c);
            c.cwnd = c.ssthresh.saturating_add(u32::from(threshold) * mss);
        } else if c.dup_acks > threshold {
            c.cwnd = c.cwnd.saturating_add(mss);
        }
    }
}

/// Reno slow start, additive increase, and duplicate-ACK recovery. # C: O(1)
fn reno_on_ack(c: &mut TcpConn, acked: u32, payload_len: u32) {
    let mss = cc_mss(c);
    if acked > 0 {
        c.dup_acks = 0;
        if c.cwnd < c.ssthresh {
            c.cwnd = c.cwnd.saturating_add(acked.min(mss));
        } else {
            let increase = (u64::from(mss) * u64::from(acked)
                / u64::from(c.cwnd.max(1))).max(1) as u32;
            c.cwnd = c.cwnd.saturating_add(increase);
        }
        return;
    }
    if payload_len == 0 {
        c.dup_acks = c.dup_acks.saturating_add(1);
        let threshold = c.reordering.clamp(1, u8::MAX as u32) as u8;
        if c.dup_acks == threshold {
            reno_on_loss(c);
            c.cwnd = c.ssthresh.saturating_add(u32::from(threshold) * mss);
        } else if c.dup_acks > threshold {
            c.cwnd = c.cwnd.saturating_add(mss);
        }
    }
}

/// Shared loss handler — β=0.7 reduction + reset epoch. # C: O(1)
fn cubic_on_loss(c: &mut TcpConn) {
    let mss = cc_mss(c);
    c.cubic_w_max = c.cwnd;
    c.ssthresh = core::cmp::max(
        ((c.cwnd as u64 * 717) / 1024) as u32,
        2 * mss,
    );
    c.cubic_epoch_ms = 0;
}

/// Reno multiplicative decrease. # C: O(1)
fn reno_on_loss(c: &mut TcpConn) {
    let mss = cc_mss(c);
    c.ssthresh = core::cmp::max(c.cwnd / 2, 2 * mss);
}

/// F190: ECN-Echo congestion signal. Treat as one loss event per
/// RTT (rate-limited via ecn_last_reduce_ms). Cubic β reduction;
/// keep cwnd ≥ ssthresh (no slow-start restart, per RFC 3168 §6.1.2).
/// # C: O(1)
pub fn on_ece(c: &mut TcpConn) {
    if c.congestion == TcpCongestionControl::Reno {
        if c.ssthresh != u32::MAX && c.cwnd <= c.ssthresh { return; }
        reno_on_loss(c);
        c.cwnd = c.ssthresh.min(c.cwnd_clamp);
        c.send_cwr = true;
        return;
    }
    // Same-RTT echo guard: if cwnd is already at-or-below the
    // post-reduction level we'd compute now, skip — this ECE is
    // the peer still telling us about the same CE.
    if c.cubic_w_max != 0
        && c.cwnd <= ((c.cubic_w_max as u64 * 8 / 10) as u32)
    { return; }
    cubic_on_loss(c);
    c.cwnd = c.ssthresh;
    c.ecn_last_reduce_ms = {
        let n = crate::tcp_conn::tcp_now_ms();
        if n == 0 { 1 } else { n }
    };
    c.send_cwr = true;
}

/// RTO loss event for the selected congestion algorithm; cwnd → MSS. # C: O(1)
pub fn on_rto(c: &mut TcpConn) {
    let mss = cc_mss(c);
    match c.congestion {
        TcpCongestionControl::Reno => reno_on_loss(c),
        TcpCongestionControl::Cubic => cubic_on_loss(c),
    }
    c.cwnd = mss;
    c.dup_acks = 0;
}

/// F193: keepalive probe scheduler. Returns Some(probe) when due;
/// bumps ka_count. Caller aborts when ka_count > ka_cnt_max; exhaustion does
/// not emit an additional probe.
/// # C: O(1)
pub fn keepalive_due(c: &mut TcpConn, now_ns: u64) -> Option<alloc::vec::Vec<u8>> {
    use crate::tcp_state::TcpState;
    if !c.ka_enabled { return None; }
    if !matches!(c.state, TcpState::Established | TcpState::CloseWait) { return None; }
    let idle = now_ns.saturating_sub(c.last_rx_ns);
    if c.ka_count == 0 {
        if idle < c.ka_idle_ns { return None; }
    } else if now_ns < c.next_ka_ns {
        return None;
    }
    if c.ka_count >= c.ka_cnt_max {
        c.ka_count = c.ka_cnt_max.saturating_add(1);
        return None;
    }
    c.ka_count = c.ka_count.saturating_add(1);
    c.next_ka_ns = now_ns.saturating_add(c.ka_intvl_ns);
    Some(c.build_keepalive_probe())
}
