use super::*;

pub(crate) fn tcp_transmit_ready(conn: &TcpConn, sndbuf_cap: usize) -> bool {
    let in_flight: usize = conn.retx_q.iter().map(|segment| segment.payload.len()).sum();
    conn.send_buf.len().saturating_add(in_flight) < sndbuf_cap
}

/// Report whether TCP state forbids additional stream payload. # C: O(1)
pub(crate) fn tcp_send_closed(state: crate::tcp_state::TcpState) -> bool {
    matches!(state, crate::tcp_state::TcpState::Closed
        | crate::tcp_state::TcpState::LastAck
        | crate::tcp_state::TcpState::Closing | crate::tcp_state::TcpState::TimeWait
        | crate::tcp_state::TcpState::FinWait1 | crate::tcp_state::TcpState::FinWait2)
}

/// F159: monotonic time source visible to net crate. On
/// `oxide-kernel` builds uses the per-arch HAL timer; hosted tests
/// return 0 so retx_tick is a no-op without a real clock.
/// # C: O(1)
pub(crate) fn monotonic_ns_safe() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        use hal::TimerOps;
        return hal_x86_64::X86TimerOps::monotonic_ns().0;
    }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    {
        use hal::TimerOps;
        return hal_aarch64::ArmTimerOps::monotonic_ns().0;
    }
    #[allow(unreachable_code)]
    0
}

/// F159: stamp the last `n` entries of `entry`'s retx_q with the
/// current monotonic ns. Called immediately after the corresponding
/// segments are handed to the iface for xmit so retx_tick has a
/// real baseline to compare RTO against. No-op on n == 0 / empty
/// queue.
/// # C: O(n)
/// F190: TOS byte for an outbound TCP segment — ECT(0)=0x02 when
/// the conn negotiated ECN, else 0. # C: O(1)
pub(crate) fn ecn_tos(c: &TcpConn) -> u8 {
    if c.ecn_enabled { 0x02 } else { 0 }
}

/// Bridge to tcp_conn::ka_now_ns from stack code. # C: O(1)
pub(crate) fn net_now_ns() -> u64 { crate::tcp_conn::ka_now_ns() }

/// # C: O(n)
pub(crate) fn stamp_last_sent(entry: &TcpEntry, n: usize) {
    if n == 0 { return; }
    let now = monotonic_ns_safe();
    if now == 0 { return; } // hosted tests / pre-timer boot
    let mut c = entry.conn.lock();
    let len = c.retx_q.len();
    let start = len.saturating_sub(n);
    for i in start..len {
        c.retx_q[i].last_sent_ns = now;
    }
    c.note_delivery_sent_at(start, now);
    c.note_info_data_sent_at(now);
}

/// # C: O(n)
pub(crate) fn stamp_last_sent_public(entry: &TcpEntry, n: usize) {
    stamp_last_sent(entry, n);
}
