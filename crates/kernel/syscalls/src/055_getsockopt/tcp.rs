// `IPPROTO_TCP` value copyout for slot 55. The value table, length rules, and
// errno ordering live in `net::sock_opts::sol_tcp::get` (`docs/53§4`); this
// file only reads the live state that table answers from and moves bytes.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use net::sock::{InetSocket, SockKind};
use net::sock_opts::sol_tcp::{self as sol, CongestionAlgo};
use net::sock_opts::sol_tcp::get::{self, GetEnv, Read};
use net::tcp_conn::{TcpCongestionControl, DELACK_MAX_DEFAULT_NS, RTO_MAX_DEFAULT_NS};
use net::tcp_state::TcpState;

use super::out::OptOut;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The connection state the value table answers from, snapshotted under one
/// lock so no two option numbers can report inconsistent state.
struct Snapshot {
    state: TcpState,
    mss_cache: i32,
    mss_clamp: i32,
    algo: CongestionAlgo,
    write_seq: u32,
    rcv_nxt: u32,
    repair_window: sol::RepairWindow,
    rto_min_ticks: i32,
}

/// `getsockopt(fd, IPPROTO_TCP, ...)`. # C: O(value bytes)
pub(super) fn get(sock: &Arc<InetSocket>, optname: u64, out: &OptOut) -> i64 {
    // The zero-copy receive owns its own operand: it reads its length against
    // the versioned struct rather than the generic value screen, and it
    // publishes in place rather than through the value table.
    if optname == sol::TCP_ZEROCOPY_RECEIVE {
        return crate::tcp_zerocopy::receive::get(sock, out.optval, out.optlen_p);
    }
    let len = match out.requested_len() { Ok(len) => len, Err(rv) => return rv };
    let snap = snapshot(sock);
    let tcp = &sock.opts.tcp;
    let saved_syn: Option<Vec<u8>> = tcp.saved_syn.lock().clone();
    let fastopen_key: Option<Vec<u8>> = tcp.fastopen.keys().map(|ctx| ctx.bytes());
    let usec_ts = tcp.usec_ts.load(Ordering::Acquire);
    let now_ms = net::tcp_conn::tcp_now_ms() as i32;
    let env = GetEnv {
        state: snap.state,
        repair: tcp.repair.load(Ordering::Acquire),
        repair_queue: tcp.repair_queue.load(Ordering::Acquire),
        mss_cache: snap.mss_cache,
        user_mss: tcp.maxseg.load(Ordering::Acquire),
        mss_clamp: snap.mss_clamp,
        nodelay: sock.opts.tcp_nodelay.load(Ordering::Acquire) != 0,
        cork: sock.opts.tcp_cork.load(Ordering::Acquire) != 0,
        keepidle_s: sock.opts.tcp_keepidle_s.load(Ordering::Acquire),
        keepintvl_s: sock.opts.tcp_keepintvl_s.load(Ordering::Acquire),
        keepcnt: sock.opts.tcp_keepcnt.load(Ordering::Acquire),
        syncnt: tcp.syncnt.load(Ordering::Acquire),
        syncnt_default: sol::TCP_SYN_RETRIES,
        linger2_s: tcp.linger2_s.load(Ordering::Acquire),
        fin_timeout_default_s: sol::TCP_FIN_TIMEOUT_S,
        defer_accept: tcp.defer_accept.load(Ordering::Acquire),
        window_clamp: tcp.window_clamp.load(Ordering::Acquire),
        pingpong: tcp.pingpong.load(Ordering::Acquire),
        algo: snap.algo,
        // No upper-layer protocol is registered, so none is ever attached.
        ulp: None,
        thin_lto: tcp.thin_lto.load(Ordering::Acquire),
        user_timeout_ms: tcp.user_timeout_ms.load(Ordering::Acquire),
        fastopen_max_qlen: tcp.fastopen.max_qlen(),
        fastopen_connect: tcp.fastopen_connect.load(Ordering::Acquire),
        fastopen_no_cookie: tcp.fastopen_no_cookie.load(Ordering::Acquire),
        fastopen_key: fastopen_key.as_deref(),
        clock_ts: if usec_ts { now_ms.wrapping_mul(1000) } else { now_ms },
        tsoffset: tcp.tsoffset.load(Ordering::Acquire),
        usec_ts,
        notsent_lowat: tcp.notsent_lowat.load(Ordering::Acquire),
        recvmsg_inq: tcp.recvmsg_inq.load(Ordering::Acquire),
        tx_delay_us: tcp.tx_delay_us.load(Ordering::Acquire),
        save_syn: tcp.save_syn.load(Ordering::Acquire),
        saved_syn: saved_syn.as_deref(),
        write_seq: snap.write_seq,
        rcv_nxt: snap.rcv_nxt,
        repair_window: snap.repair_window,
        rto_max_ticks: tcp.rto_max_ticks.load(Ordering::Acquire),
        rto_min_ticks: tcp.rto_min_ticks.load(Ordering::Acquire),
        delack_max_ticks: tcp.delack_max_ticks.load(Ordering::Acquire),
        rto_max_default_ticks: ns_to_ticks(RTO_MAX_DEFAULT_NS),
        rto_min_default_ticks: snap.rto_min_ticks,
        delack_max_default_ticks: ns_to_ticks(DELACK_MAX_DEFAULT_NS),
        net_admin: net_admin(sock),
    };
    let required = get::saved_syn_required(&env);
    let value = match get::read(optname, len, env) { Ok(v) => v, Err(e) => return errno(e) };
    publish(sock, optname, out, len, value, required)
}

fn ns_to_ticks(ns: u64) -> i32 { (ns / sol::NS_PER_TICK) as i32 }

fn net_admin(sock: &InetSocket) -> bool {
    match sched::live::current() {
        Some(cur) => nscg::has_net_admin_for(cur, &sock.net_namespace),
        None => false,
    }
}

/// One consistent read of the connection state the value table needs.
/// # C: O(1)
fn snapshot(sock: &Arc<InetSocket>) -> Snapshot {
    let mut snap = Snapshot {
        state: TcpState::Closed,
        mss_cache: net::tcp_conn::OWN_MSS_DEFAULT as i32,
        mss_clamp: 0,
        algo: sock.opts.tcp.algo(),
        write_seq: 0,
        rcv_nxt: 0,
        repair_window: sol::RepairWindow::default(),
        rto_min_ticks: 0,
    };
    match &*sock.kind.lock() {
        SockKind::TcpListener(_) => snap.state = TcpState::Listen,
        SockKind::TcpConn(entry) => {
            let c = entry.conn.lock();
            snap.state = c.state;
            snap.mss_cache = net::tcp_cc::cc_mss(&c) as i32;
            snap.mss_clamp = c.mss_clamp as i32;
            snap.algo = match c.congestion {
                TcpCongestionControl::Reno => CongestionAlgo::Reno,
                TcpCongestionControl::Cubic => CongestionAlgo::Cubic,
            };
            snap.write_seq = c.snd_nxt;
            snap.rcv_nxt = c.rcv_nxt;
            snap.repair_window = net::sock_opts::sol_tcp::apply::repair_window_of(&c);
            snap.rto_min_ticks = (c.rto_min_ns / sol::NS_PER_TICK) as i32;
        }
        _ => {}
    }
    snap
}

/// Move the accepted value out under the shape its option publishes.
/// # C: O(value bytes)
fn publish(sock: &Arc<InetSocket>, optname: u64, out: &OptOut, len: usize, value: Read,
           required: Option<usize>) -> i64
{
    match value {
        Read::Info => crate::tcp_info::write_tcp_info(sock, out.optval, out.optlen_p),
        Read::Clipped(bytes) => out.bytes(&bytes),
        Read::Fixed(bytes) => out.value_only(&bytes),
        Read::Consume(bytes) => {
            if len < bytes.len() {
                // Publishing the size the value needs is what lets the caller
                // size a second buffer instead of guessing.
                let _ = out.length_only(required.unwrap_or(bytes.len()));
                return errno(Errno::Einval);
            }
            let rv = out.bytes(&bytes);
            if rv == 0 && optname == sol::TCP_SAVED_SYN {
                // The recorded handshake is handed over once.
                *sock.opts.tcp.saved_syn.lock() = None;
            }
            rv
        }
    }
}
