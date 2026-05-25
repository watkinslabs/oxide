// F188: getsockopt(IPPROTO_TCP, TCP_INFO) — Linux struct tcp_info
// readback. apps like nginx + monitoring agents query this for
// RTT / cwnd / retransmit stats. Layout matches uapi/linux/tcp.h
// (Linux 6.x; older fields only — newer ones default to 0).

use hal::USER_VA_END;
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
    if optval == 0 || optval >= USER_VA_END
        || optlen_p == 0 || optlen_p >= USER_VA_END { return 0; }
    // SAFETY: optlen_p validated < USER_VA_END; CPL=0 read through caller's AS.
    let optlen = unsafe { core::ptr::read_volatile(optlen_p as *const u32) } as usize;
    if optlen < 4 { return 0; }
    let writelen = core::cmp::min(optlen, TCP_INFO_LEN);
    let mut info = TcpInfo::default();
    populate(sock, &mut info);
    // SAFETY: bytewise copy of POD into validated user range; len bounded.
    unsafe {
        let src = &info as *const TcpInfo as *const u8;
        for i in 0..writelen {
            core::ptr::write_volatile((optval + i as u64) as *mut u8, *src.add(i));
        }
        core::ptr::write_volatile(optlen_p as *mut u32, writelen as u32);
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
