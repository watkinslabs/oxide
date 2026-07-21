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

const TCP_INFO_LEN: usize = core::mem::size_of::<TcpInfo>();
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
    let entry = match &*sock.kind.lock() {
        SockKind::TcpConn(e) => e.clone(),
        SockKind::TcpListener(_) => { info.tcpi_state = state_to_byte(net::tcp_state::TcpState::Listen); return; }
        _ => { info.tcpi_state = state_to_byte(net::tcp_state::TcpState::Closed); return; }
    };
    let c = entry.conn.lock();
    info.tcpi_state = state_to_byte(c.state);
    info.tcpi_retransmits = c.retx_q.iter().map(|s| s.retries).max().unwrap_or(0) as u8;
    info.tcpi_snd_wscale_rcv = (c.snd_wscale << 4) | (c.rcv_wscale & 0x0F);
    info.tcpi_rto = (c.rto_ns / 1_000) as u32;
    let snd_mss = if c.own_mss != 0 { c.own_mss as u32 } else { 1460 };
    info.tcpi_snd_mss = snd_mss;
    info.tcpi_rcv_mss = if c.peer_mss != 0 { c.peer_mss as u32 } else { snd_mss };
    info.tcpi_advmss = snd_mss;
    info.tcpi_unacked = c.retx_q.len() as u32;
    info.tcpi_retrans = c.retx_q.iter().map(|s| s.retries).sum::<u32>();
    info.tcpi_total_retrans = info.tcpi_retrans;
    info.tcpi_rtt = (c.srtt_ns / 1_000) as u32;
    info.tcpi_rttvar = (c.rttvar_ns / 1_000) as u32;
    info.tcpi_snd_ssthresh = c.ssthresh;
    info.tcpi_snd_cwnd = c.cwnd / core::cmp::max(snd_mss, 1);
    info.tcpi_rcv_space = c.rcv_buf_cap;
}

#[cfg(target_os = "oxide-kernel")]
fn state_to_byte(s: net::tcp_state::TcpState) -> u8 {
    use net::tcp_state::TcpState::*;
    match s {
        Established => 1, SynSent => 2, SynRecv => 3, FinWait1 => 4, FinWait2 => 5,
        TimeWait => 6, Closed => 7, CloseWait => 8, LastAck => 9, Listen => 10, Closing => 11,
    }
}

#[cfg(test)]
mod tests {
    use super::{copy_tcp_info, TcpInfo, TCP_INFO_LEN, TCP_INFO_PREFIX_LEN};

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
