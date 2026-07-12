// F188: getsockopt(IPPROTO_TCP, TCP_INFO) — Linux struct tcp_info
// readback. apps like nginx + monitoring agents query this for
// RTT / cwnd / retransmit stats. Layout matches uapi/linux/tcp.h
// (Linux 6.x; older fields only — newer ones default to 0).

use net::sock::{InetSocket, SockKind};

/// Minimal Linux tcp_info subset (104 bytes — fields up through
/// tcpi_total_retrans). Newer additions zeroed. Field order +
/// widths must match uapi/linux/tcp.h byte-for-byte.
#[repr(C)]
#[derive(Default, Copy, Clone)]
struct TcpInfo {
    tcpi_state:           u8,
    tcpi_ca_state:        u8,
    tcpi_retransmits:     u8,
    tcpi_probes:          u8,
    tcpi_backoff:         u8,
    tcpi_options:         u8,
    tcpi_snd_wscale_rcv:  u8,   // packed: hi nibble = snd, lo = rcv
    tcpi_delivery_rate_app_limited: u8,
    tcpi_rto:             u32,
    tcpi_ato:             u32,
    tcpi_snd_mss:         u32,
    tcpi_rcv_mss:         u32,
    tcpi_unacked:         u32,
    tcpi_sacked:          u32,
    tcpi_lost:            u32,
    tcpi_retrans:         u32,
    tcpi_fackets:         u32,
    tcpi_last_data_sent:  u32,
    tcpi_last_ack_sent:   u32,
    tcpi_last_data_recv:  u32,
    tcpi_last_ack_recv:   u32,
    tcpi_pmtu:            u32,
    tcpi_rcv_ssthresh:    u32,
    tcpi_rtt:             u32,  // microseconds
    tcpi_rttvar:          u32,
    tcpi_snd_ssthresh:    u32,
    tcpi_snd_cwnd:        u32,  // segments, not bytes (Linux quirk)
    tcpi_advmss:          u32,
    tcpi_reordering:      u32,
    tcpi_rcv_rtt:         u32,
    tcpi_rcv_space:       u32,
    tcpi_total_retrans:   u32,
}

const TCP_INFO_LEN: usize = core::mem::size_of::<TcpInfo>();

/// # C: O(1)
pub fn write_tcp_info(sock: &InetSocket, optval: u64, optlen_p: u64) -> i64 {
    if let Err(rv) = crate::userbuf::validate_user_buf(optlen_p, 4, 1) { return rv; }
    // SAFETY: optlen_p was validated as a readable 4-byte user span; scalar load permits unaligned user storage.
    let optlen = unsafe { core::ptr::read_unaligned(optlen_p as *const u32) } as usize;
    let writelen = core::cmp::min(optlen, TCP_INFO_LEN);
    if writelen > 0 {
        if let Err(rv) = crate::userbuf::validate_user_buf_writable(optval, writelen as u64, 1) { return rv; }
    }
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(optlen_p, 4, 1) { return rv; }
    let mut info = TcpInfo::default();
    populate(sock, &mut info);
    // SAFETY: copy spans were validated above; byte stores and u32 optlen store permit unaligned user storage.
    unsafe {
        let src = &info as *const TcpInfo as *const u8;
        for i in 0..writelen {
            core::ptr::write_unaligned((optval + i as u64) as *mut u8, *src.add(i));
        }
        core::ptr::write_unaligned(optlen_p as *mut u32, writelen as u32);
    }
    0
}

fn populate(sock: &InetSocket, info: &mut TcpInfo) {
    let entry = match &*sock.kind.lock() {
        SockKind::TcpConn(e) => e.clone(),
        SockKind::TcpListener(_) => { info.tcpi_state = state_to_byte(net::tcp_state::TcpState::Listen); return; }
        _ => { info.tcpi_state = state_to_byte(net::tcp_state::TcpState::Closed); return; }
    };
    let c = entry.conn.lock();
    info.tcpi_state = state_to_byte(c.state);
    info.tcpi_retransmits = c.retx_q.iter().map(|s| s.retries).max().unwrap_or(0) as u8;
    info.tcpi_snd_wscale_rcv = (c.snd_wscale << 4) | (c.rcv_wscale & 0x0F);
    info.tcpi_rto = (c.rto_ns / 1_000) as u32;  // µs
    let snd_mss = if c.own_mss != 0 { c.own_mss as u32 } else { 1460 };
    info.tcpi_snd_mss = snd_mss;
    info.tcpi_rcv_mss = if c.peer_mss != 0 { c.peer_mss as u32 } else { snd_mss };
    info.tcpi_advmss = snd_mss;
    info.tcpi_unacked = c.retx_q.len() as u32;
    info.tcpi_retrans = c.retx_q.iter().map(|s| s.retries).sum::<u32>();
    info.tcpi_total_retrans = info.tcpi_retrans;
    info.tcpi_rtt = (c.srtt_ns / 1_000) as u32;       // µs
    info.tcpi_rttvar = (c.rttvar_ns / 1_000) as u32;
    info.tcpi_snd_ssthresh = c.ssthresh;
    // Linux quirk: snd_cwnd in *segments*, not bytes.
    info.tcpi_snd_cwnd = c.cwnd / core::cmp::max(snd_mss, 1);
    info.tcpi_rcv_space = c.rcv_buf_cap;
}

fn state_to_byte(s: net::tcp_state::TcpState) -> u8 {
    use net::tcp_state::TcpState::*;
    match s {
        Established => 1,
        SynSent     => 2,
        SynRecv     => 3,
        FinWait1    => 4,
        FinWait2    => 5,
        TimeWait    => 6,
        Closed      => 7,
        CloseWait   => 8,
        LastAck     => 9,
        Listen      => 10,
        Closing     => 11,
    }
}
