// Linux getsockopt(IPPROTO_TCP, TCP_INFO) ABI and copyout owner.

#[cfg(target_os = "oxide-kernel")]
use net::sock::{InetSocket, SockKind};

/// Linux `struct tcp_info`, including every current UAPI extension.
#[repr(C)]
#[derive(Default, Copy, Clone)]
struct TcpInfo {
    tcpi_state: u8, tcpi_ca_state: u8, tcpi_retransmits: u8, tcpi_probes: u8,
    tcpi_backoff: u8, tcpi_options: u8, tcpi_snd_wscale_rcv: u8,
    tcpi_delivery_rate_app_limited: u8,
    tcpi_rto: u32, tcpi_ato: u32, tcpi_snd_mss: u32, tcpi_rcv_mss: u32,
    tcpi_unacked: u32, tcpi_sacked: u32, tcpi_lost: u32, tcpi_retrans: u32,
    tcpi_fackets: u32, tcpi_last_data_sent: u32, tcpi_last_ack_sent: u32,
    tcpi_last_data_recv: u32, tcpi_last_ack_recv: u32, tcpi_pmtu: u32,
    tcpi_rcv_ssthresh: u32, tcpi_rtt: u32, tcpi_rttvar: u32,
    tcpi_snd_ssthresh: u32, tcpi_snd_cwnd: u32, tcpi_advmss: u32,
    tcpi_reordering: u32, tcpi_rcv_rtt: u32, tcpi_rcv_space: u32,
    tcpi_total_retrans: u32, tcpi_pacing_rate: u64, tcpi_max_pacing_rate: u64,
    tcpi_bytes_acked: u64, tcpi_bytes_received: u64, tcpi_segs_out: u32,
    tcpi_segs_in: u32, tcpi_notsent_bytes: u32, tcpi_min_rtt: u32,
    tcpi_data_segs_in: u32, tcpi_data_segs_out: u32, tcpi_delivery_rate: u64,
    tcpi_busy_time: u64, tcpi_rwnd_limited: u64, tcpi_sndbuf_limited: u64,
    tcpi_delivered: u32, tcpi_delivered_ce: u32, tcpi_bytes_sent: u64,
    tcpi_bytes_retrans: u64, tcpi_dsack_dups: u32, tcpi_reord_seen: u32,
    tcpi_rcv_ooopack: u32, tcpi_snd_wnd: u32, tcpi_rcv_wnd: u32,
    tcpi_rehash: u32, tcpi_total_rto: u16, tcpi_total_rto_recoveries: u16,
    tcpi_total_rto_time: u32,
}

/// Width and position of `tcpi_fastopen_client_fail` inside the bitfield byte
/// `tcpi_delivery_rate_app_limited` opens.
const FASTOPEN_CLIENT_FAIL_MASK: u8 = 0x3;
const FASTOPEN_CLIENT_FAIL_SHIFT: u32 = 1;

const TCPI_OPT_TIMESTAMPS: u8 = 1;
const TCPI_OPT_SACK: u8 = 2;
const TCPI_OPT_WSCALE: u8 = 4;
const TCPI_OPT_ECN: u8 = 8;

const TCP_INFO_LEN: usize = core::mem::size_of::<TcpInfo>();
/// Short-buffer boundary the copyout tests cut at: everything before
/// `tcpi_pacing_rate` is the pre-3.15 `struct tcp_info` prefix.
#[cfg(test)]
const TCP_INFO_PREFIX_LEN: usize = core::mem::offset_of!(TcpInfo, tcpi_pacing_rate);

fn tcp_info_bytes(info: &TcpInfo) -> &[u8] {
    // SAFETY: TcpInfo is repr(C), fully initialized, and exposed only as its exact object-size byte span.
    unsafe { core::slice::from_raw_parts((info as *const TcpInfo).cast::<u8>(), TCP_INFO_LEN) }
}

fn copy_tcp_info<E>(info: &TcpInfo, requested: usize,
    copy_value: impl FnOnce(&[u8]) -> Result<(), E>, copy_len: impl FnOnce(u32) -> Result<(), E>) -> Result<(), E>
{
    let written = core::cmp::min(requested, TCP_INFO_LEN);
    copy_value(&tcp_info_bytes(info)[..written])?;
    copy_len(written as u32)
}

#[cfg(target_os = "oxide-kernel")]
/// # C: O(TCP_INFO_LEN)
pub fn write_tcp_info(sock: &InetSocket, optval: u64, optlen_p: u64) -> i64 {
    let len_bytes = core::mem::size_of::<u32>() as u64;
    if let Err(rv) = crate::userbuf::validate_user_buf(optlen_p, len_bytes, 1) { return rv; }
    // SAFETY: optlen_p was validated as a readable u32 user span before this unaligned scalar load.
    let requested = unsafe { core::ptr::read_unaligned(optlen_p as *const u32) } as usize;
    let written = core::cmp::min(requested, TCP_INFO_LEN);
    if written > 0 {
        if let Err(rv) = crate::userbuf::validate_user_buf_writable(optval, written as u64, 1) { return rv; }
    }
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(optlen_p, len_bytes, 1) { return rv; }
    let mut info = TcpInfo::default();
    populate(sock, &mut info);
    match copy_tcp_info(&info, requested,
        |bytes| uaccess::copy_to_user(optval, bytes).map_err(|_| -(syscall::errno::Errno::Efault.as_i32() as i64)),
        |len| uaccess::copy_to_user(optlen_p, &len.to_ne_bytes()).map_err(|_| -(syscall::errno::Errno::Efault.as_i32() as i64)))
    { Ok(()) => 0, Err(rv) => rv }
}

#[cfg(target_os = "oxide-kernel")]
fn populate(sock: &InetSocket, info: &mut TcpInfo) {
    populate_max_pacing_rate(&sock.opts.generic, info);
    let entry = match &*sock.kind.lock() {
        SockKind::TcpConn(e) => e.clone(),
        SockKind::TcpListener(_) => { info.tcpi_state = state_to_byte(net::tcp_state::TcpState::Listen); return; }
        _ => { info.tcpi_state = state_to_byte(net::tcp_state::TcpState::Closed); return; }
    };
    let c = entry.conn.lock();
    populate_conn_at(&c, net::tcp_conn::ka_now_ns(), info);
}

fn populate_max_pacing_rate(opts: &net::sock_opts::sol_socket::GenericSockOpts, info: &mut TcpInfo) {
    info.tcpi_max_pacing_rate = opts.max_pacing_rate();
}

#[cfg(test)]
fn populate_conn(c: &net::tcp_conn::TcpConn, info: &mut TcpInfo) {
    populate_conn_at(c, net::tcp_conn::ka_now_ns(), info);
}

fn tcp_info_age_ms(now_ns: u64, then_ns: u64) -> u32 {
    if now_ns == 0 || then_ns == 0 { return 0; }
    core::cmp::min(now_ns.saturating_sub(then_ns) / 1_000_000, u64::from(u32::MAX)) as u32
}

fn populate_conn_at(c: &net::tcp_conn::TcpConn, now_ns: u64, info: &mut TcpInfo) {
    info.tcpi_state = state_to_byte(c.state);
    info.tcpi_options = tcp_info_options(c);
    info.tcpi_retransmits = c.retx_q.iter().map(|s| s.retries).max().unwrap_or(0) as u8;
    info.tcpi_snd_wscale_rcv = (c.snd_wscale << 4) | (c.rcv_wscale & 0x0F);
    info.tcpi_rto = (c.rto_ns / 1_000) as u32;
    info.tcpi_ato = (c.delack_ato_ns() / 1_000).min(u64::from(u32::MAX)) as u32;
    let snd_mss = if c.own_mss != 0 { c.own_mss as u32 } else { 1460 };
    info.tcpi_snd_mss = snd_mss;
    info.tcpi_rcv_mss = c.rcv_mss() as u32;
    info.tcpi_advmss = snd_mss;
    info.tcpi_pmtu = c.path_mtu;
    info.tcpi_unacked = c.retx_q.len() as u32;
    info.tcpi_retrans = c.retx_q.iter().map(|s| s.retries).sum::<u32>();
    info.tcpi_total_retrans = info.tcpi_retrans;
    info.tcpi_last_data_sent = tcp_info_age_ms(now_ns, c.last_data_sent_ns);
    info.tcpi_last_data_recv = tcp_info_age_ms(now_ns, c.last_data_recv_ns);
    info.tcpi_last_ack_recv = tcp_info_age_ms(now_ns, c.last_ack_recv_ns);
    info.tcpi_rtt = (c.srtt_ns / 1_000) as u32;
    info.tcpi_rttvar = (c.rttvar_ns / 1_000) as u32;
    info.tcpi_snd_ssthresh = c.ssthresh / core::cmp::max(snd_mss, 1);
    info.tcpi_snd_cwnd = c.cwnd / core::cmp::max(snd_mss, 1);
    info.tcpi_reordering = c.reordering;
    info.tcpi_rcv_ssthresh = c.rcv_ssthresh;
    info.tcpi_rcv_rtt = (c.rcv_rtt_ns / 1_000).min(u64::from(u32::MAX)) as u32;
    info.tcpi_rcv_space = c.rcv_space;
    info.tcpi_bytes_received = c.bytes_received;
    info.tcpi_bytes_acked = c.bytes_acked;
    info.tcpi_segs_out = c.segs_out;
    info.tcpi_segs_in = c.segs_in;
    info.tcpi_notsent_bytes = c.notsent_bytes();
    info.tcpi_data_segs_in = c.data_segs_in;
    info.tcpi_data_segs_out = c.data_segs_out;
    info.tcpi_bytes_sent = c.bytes_sent;
    info.tcpi_bytes_retrans = c.bytes_retrans;
    info.tcpi_rcv_ooopack = c.rcv_ooopack;
    info.tcpi_snd_wnd = c.snd_wnd;
    info.tcpi_rcv_wnd = c.advertised_rcv_wnd();
    // Linux packs this byte as `delivery_rate_app_limited:1,
    // fastopen_client_fail:2`, so the reason rides bits 1-2.
    info.tcpi_delivery_rate_app_limited =
        (c.fastopen_client_fail & FASTOPEN_CLIENT_FAIL_MASK) << FASTOPEN_CLIENT_FAIL_SHIFT;
}

fn tcp_info_options(c: &net::tcp_conn::TcpConn) -> u8 {
    let mut options = 0;
    if c.ts_enabled { options |= TCPI_OPT_TIMESTAMPS; }
    if c.sack_ok { options |= TCPI_OPT_SACK; }
    if c.wscale_ok { options |= TCPI_OPT_WSCALE; }
    if c.ecn_enabled { options |= TCPI_OPT_ECN; }
    options
}

fn state_to_byte(s: net::tcp_state::TcpState) -> u8 {
    use net::tcp_state::TcpState::*;
    match s {
        Established => 1, SynSent => 2, SynRecv => 3, FinWait1 => 4, FinWait2 => 5,
        TimeWait => 6, Closed => 7, CloseWait => 8, LastAck => 9, Listen => 10, Closing => 11,
    }
}

#[cfg(test)]
mod tests {
    use super::{copy_tcp_info, populate_conn, populate_conn_at, populate_max_pacing_rate, tcp_info_options, TcpInfo, TCPI_OPT_ECN,
        TCPI_OPT_SACK, TCPI_OPT_TIMESTAMPS, TCPI_OPT_WSCALE, TCP_INFO_LEN, TCP_INFO_PREFIX_LEN};

    fn conn() -> net::tcp_conn::TcpConn {
        let ip = net::addr::IpAddr::V4(net::addr::Ipv4Addr::LOOPBACK);
        let endpoint = |port| net::tcp_conn::Endpoint { ip, port };
        net::tcp_conn::TcpConn::new_client(endpoint(40_000), endpoint(80), 1)
    }

    #[test]
    fn options_project_only_the_connection_negotiation_bits() {
        let mut c = conn();
        assert_eq!(tcp_info_options(&c), 0);
        c.ts_enabled = true;
        c.sack_ok = true;
        c.wscale_ok = true;
        c.ecn_enabled = true;
        assert_eq!(tcp_info_options(&c), TCPI_OPT_TIMESTAMPS | TCPI_OPT_SACK
            | TCPI_OPT_WSCALE | TCPI_OPT_ECN);
    }

    #[test]
    fn populate_reads_the_connection_owned_receive_and_send_counters() {
        let mut conn = conn();
        conn.state = net::tcp_state::TcpState::Established;
        conn.segs_in = 7;
        conn.bytes_received = 91;
        conn.rcv_ooopack = 2;
        conn.bytes_acked = 73;
        conn.segs_out = 8;
        conn.data_segs_out = 5;
        conn.bytes_sent = 64;
        conn.bytes_retrans = 11;
        conn.snd_wnd = 12_345;
        conn.rcv_buf_cap = 32_768;
        conn.window_clamp = 32_768;
        conn.snd_wscale = 3;
        conn.ts_enabled = true;
        conn.sack_ok = true;
        conn.wscale_ok = true;
        conn.ecn_enabled = true;
        conn.path_mtu = 1_300;
        conn.send(b"unsent");
        let mut info = TcpInfo::default();
        populate_conn(&conn, &mut info);
        assert_eq!(info.tcpi_segs_in, 7);
        assert_eq!(info.tcpi_bytes_received, 91);
        assert_eq!(info.tcpi_rcv_ooopack, 2);
        assert_eq!(info.tcpi_bytes_acked, 73);
        assert_eq!(info.tcpi_segs_out, 8);
        assert_eq!(info.tcpi_data_segs_out, 5);
        assert_eq!(info.tcpi_bytes_sent, 64);
        assert_eq!(info.tcpi_bytes_retrans, 11);
        assert_eq!(info.tcpi_notsent_bytes, 6);
        assert_eq!(info.tcpi_snd_wnd, 12_345);
        assert_eq!(info.tcpi_rcv_wnd, 32_768);
        assert_eq!(info.tcpi_pmtu, 1_300);
        assert_eq!(info.tcpi_options, TCPI_OPT_TIMESTAMPS | TCPI_OPT_SACK
            | TCPI_OPT_WSCALE | TCPI_OPT_ECN);
    }

    #[test]
    fn activity_ages_are_derived_from_the_connection_owned_clocks() {
        let mut conn = conn();
        conn.last_data_sent_ns = 9_000_000;
        conn.last_data_recv_ns = 8_000_000;
        conn.last_ack_recv_ns = 7_000_000;
        let mut info = TcpInfo::default();
        populate_conn_at(&conn, 12_000_000, &mut info);
        assert_eq!(info.tcpi_last_data_sent, 3);
        assert_eq!(info.tcpi_last_data_recv, 4);
        assert_eq!(info.tcpi_last_ack_recv, 5);
    }

    #[test]
    fn receive_mss_projects_policy_and_validated_payload_observation() {
        let mut conn = conn();
        conn.own_mss = 1_200;
        conn.rcv_buf_cap = 400;
        conn.window_clamp = 400;
        let mut info = TcpInfo::default();
        populate_conn_at(&conn, 0, &mut info);
        assert_eq!(info.tcpi_rcv_mss, 200);
        conn.rcv_mss = 800;
        populate_conn_at(&conn, 0, &mut info);
        assert_eq!(info.tcpi_rcv_mss, 800);
    }

    #[test]
    fn delayed_ack_timeout_projects_the_connection_owned_interval() {
        let mut conn = conn();
        conn.delack_ato_ns = 40_000_000;
        conn.delack_max_ns = 20_000_000;
        let mut info = TcpInfo::default();
        populate_conn_at(&conn, 0, &mut info);
        assert_eq!(info.tcpi_ato, 20_000);
    }

    #[test]
    fn receiver_rtt_projects_the_receive_window_sample() {
        let mut conn = conn();
        conn.rcv_rtt_ns = 17_000;
        let mut info = TcpInfo::default();
        populate_conn_at(&conn, 0, &mut info);
        assert_eq!(info.tcpi_rcv_rtt, 17);
    }

    #[test]
    fn receiver_space_projects_the_application_copy_sample() {
        let mut conn = conn();
        conn.rcv_space = 4_096;
        let mut info = TcpInfo::default();
        populate_conn_at(&conn, 0, &mut info);
        assert_eq!(info.tcpi_rcv_space, 4_096);
    }

    #[test]
    fn receiver_ssthresh_projects_the_advertised_window_threshold() {
        let mut conn = conn();
        conn.rcv_ssthresh = 8_192;
        let mut info = TcpInfo::default();
        populate_conn_at(&conn, 0, &mut info);
        assert_eq!(info.tcpi_rcv_ssthresh, 8_192);
    }

    #[test]
    fn max_pacing_rate_projects_the_socket_owned_ceiling() {
        let opts = net::sock_opts::sol_socket::GenericSockOpts::default();
        let mut info = TcpInfo::default();
        populate_max_pacing_rate(&opts, &mut info);
        assert_eq!(info.tcpi_max_pacing_rate, u64::MAX);
        opts.set_max_pacing_rate(1 << 40);
        populate_max_pacing_rate(&opts, &mut info);
        assert_eq!(info.tcpi_max_pacing_rate, 1 << 40);
    }

    #[test]
    fn full_request_returns_full_linux_abi_and_zero_extension() {
        let info = TcpInfo::default();
        let mut value = [u8::MAX; TCP_INFO_LEN];
        let mut returned = None;
        copy_tcp_info(&info, TCP_INFO_LEN, |bytes| { value.copy_from_slice(bytes); Ok::<(), ()>(()) },
            |len| { returned = Some(len); Ok(()) }).unwrap();
        assert_eq!(returned, Some(TCP_INFO_LEN as u32));
        assert!(value[TCP_INFO_PREFIX_LEN..].iter().all(|byte| *byte == u8::MIN));
    }

    #[test]
    fn prefix_request_returns_only_requested_linux_prefix() {
        let info = TcpInfo::default();
        let mut value = [u8::MAX; TCP_INFO_PREFIX_LEN];
        let mut returned = None;
        copy_tcp_info(&info, TCP_INFO_PREFIX_LEN, |bytes| { value.copy_from_slice(bytes); Ok::<(), ()>(()) },
            |len| { returned = Some(len); Ok(()) }).unwrap();
        assert_eq!(returned, Some(TCP_INFO_PREFIX_LEN as u32));
        assert!(value.iter().all(|byte| *byte == u8::MIN));
    }

    #[test]
    fn value_copy_fault_precedes_optlen_copyout() {
        let mut wrote_length = false;
        let result = copy_tcp_info(&TcpInfo::default(), TCP_INFO_LEN,
            |_| Err::<(), _>(()), |_| { wrote_length = true; Ok(()) });
        assert!(result.is_err());
        assert!(!wrote_length);
    }
}
