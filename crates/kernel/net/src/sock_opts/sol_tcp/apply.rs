// Installation of accepted `IPPROTO_TCP` option state: the store into the
// socket's option block, and the push of that block into a live connection.
// Nothing here decides admission — `set` already did — so every function is a
// total transform from an accepted `Action` to observable transport state.

use core::sync::atomic::Ordering;
use alloc::vec::Vec;
use crate::sock::SockOpts;
use crate::tcp_conn::TcpConn;
use super::*;
use super::set::Action;
use super::repair::RepairEffect;

/// What the shim must do to the live connection after a store. Each flag names
/// a transport action the option cannot perform from the option block alone.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Effects {
    /// Flush what the cork held back.
    pub uncork: bool,
    /// Release a held acknowledgement.
    pub push_ack: bool,
    /// Probe the peer's window after leaving repair.
    pub window_probe: bool,
    /// Re-evaluate write readiness against the new unsent-bytes limit.
    pub write_space: bool,
    /// Reload the connection's copy of the option block.
    pub reload: bool,
    /// Reload a live listener's applied copies of the request-sock options.
    pub listener: bool,
}

impl Effects {
    fn reload() -> Self { Self { reload: true, ..Self::default() } }
}

/// Store one accepted write into the socket's option block. # C: O(1)
pub fn store(opts: &SockOpts, action: &Action) -> Effects {
    let tcp = &opts.tcp;
    match action {
        Action::Accept => Effects::default(),
        Action::Nodelay(on) => {
            opts.tcp_nodelay.store(*on as i32, Ordering::Release);
            // Naming no-delay pushes what is already queued even while the
            // cork is set, so the write is not held for a full segment.
            Effects { uncork: *on, ..Effects::reload() }
        }
        Action::Cork(on) => {
            let old = opts.tcp_cork.swap(*on as i32, Ordering::AcqRel);
            Effects { uncork: old != 0 && !*on, ..Effects::reload() }
        }
        Action::KeepIdle(v) => { opts.tcp_keepidle_s.store(*v, Ordering::Release); Effects::reload() }
        Action::KeepIntvl(v) => { opts.tcp_keepintvl_s.store(*v, Ordering::Release); Effects::reload() }
        Action::KeepCnt(v) => { opts.tcp_keepcnt.store(*v, Ordering::Release); Effects::reload() }
        Action::MaxSeg(v) => { tcp.maxseg.store(*v, Ordering::Release); Effects::reload() }
        Action::SynCnt(v) => {
            tcp.syncnt.store(*v, Ordering::Release);
            // The ceiling reaches a listener's half-open requests too, which
            // have no connection to reload it into.
            Effects { listener: true, ..Effects::reload() }
        }
        Action::Linger2(v) => { tcp.linger2_s.store(*v, Ordering::Release); Effects::reload() }
        Action::DeferAccept(v) => {
            tcp.defer_accept.store(*v, Ordering::Release);
            Effects { listener: true, ..Effects::default() }
        }
        Action::WindowClamp(v) => { tcp.window_clamp.store(*v, Ordering::Release); Effects::reload() }
        Action::QuickAck { pingpong, push_ack } => {
            tcp.pingpong.store(*pingpong, Ordering::Release);
            Effects { push_ack: *push_ack, ..Effects::reload() }
        }
        Action::Congestion(algo) => {
            tcp.congestion.store(algo.as_u8(), Ordering::Release);
            tcp.congestion_setsockopt.store(true, Ordering::Release);
            Effects::reload()
        }
        Action::ThinLto(on) => { tcp.thin_lto.store(*on, Ordering::Release); Effects::reload() }
        Action::UserTimeout(v) => {
            tcp.user_timeout_ms.store(*v, Ordering::Release); Effects::reload()
        }
        Action::Repair { on, window_probe } => {
            tcp.repair.store(*on, Ordering::Release);
            if *on { tcp.repair_queue.store(TCP_NO_QUEUE, Ordering::Release); }
            Effects { window_probe: *window_probe, ..Effects::reload() }
        }
        Action::RepairQueue(v) => {
            tcp.repair_queue.store(*v, Ordering::Release); Effects::default()
        }
        Action::QueueSeq { .. } | Action::RepairWindow(_) | Action::RepairOptions { .. } =>
            Effects::default(),
        Action::SaveSyn(v) => { tcp.save_syn.store(*v, Ordering::Release); Effects::default() }
        Action::Fastopen(v) => {
            tcp.fastopen_max_qlen.store(*v, Ordering::Release); Effects::default()
        }
        Action::FastopenConnect(on) => {
            tcp.fastopen_connect.store(*on, Ordering::Release); Effects::default()
        }
        Action::FastopenNoCookie(on) => {
            tcp.fastopen_no_cookie.store(*on, Ordering::Release); Effects::reload()
        }
        Action::FastopenKey { primary, backup } => {
            let mut key: Vec<u8> = primary.to_vec();
            if let Some(backup) = backup { key.extend_from_slice(backup); }
            *tcp.fastopen_key.lock() = Some(key);
            Effects::default()
        }
        Action::Timestamp { tsoffset, usec_ts } => {
            tcp.tsoffset.store(*tsoffset, Ordering::Release);
            tcp.usec_ts.store(*usec_ts, Ordering::Release);
            Effects::reload()
        }
        Action::NotsentLowat(v) => {
            tcp.notsent_lowat.store(*v, Ordering::Release);
            Effects { write_space: true, ..Effects::reload() }
        }
        Action::Inq(on) => { tcp.recvmsg_inq.store(*on, Ordering::Release); Effects::default() }
        Action::TxDelay(v) => { tcp.tx_delay_us.store(*v, Ordering::Release); Effects::reload() }
        Action::RtoMaxTicks(v) => { tcp.rto_max_ticks.store(*v, Ordering::Release); Effects::reload() }
        Action::RtoMinTicks(v) => { tcp.rto_min_ticks.store(*v, Ordering::Release); Effects::reload() }
        Action::DelackMaxTicks(v) => {
            tcp.delack_max_ticks.store(*v, Ordering::Release); Effects::reload()
        }
    }
}

/// Install the option block on a live connection. Called after every accepted
/// write and once when a connection is bound to the socket, so the connection
/// never disagrees with the option block. # C: O(1)
pub fn to_conn(opts: &SockOpts, conn: &mut TcpConn) {
    let tcp = &opts.tcp;
    let maxseg = tcp.maxseg.load(Ordering::Acquire);
    if maxseg != 0 { conn.own_mss = maxseg as u16; }
    conn.syn_retries = match tcp.syncnt.load(Ordering::Acquire) {
        0 => TCP_SYN_RETRIES as u32,
        v => v as u32,
    };
    conn.linger2_ns = match tcp.linger2_s.load(Ordering::Acquire) {
        v if v < 0 => 0,
        0 => TCP_FIN_TIMEOUT_S as u64 * NS_PER_S,
        v => v as u64 * NS_PER_S,
    };
    conn.window_clamp = match tcp.window_clamp.load(Ordering::Acquire) {
        0 => u32::MAX,
        v => v as u32,
    };
    conn.quickack = !tcp.pingpong.load(Ordering::Acquire);
    if tcp.congestion_setsockopt.load(Ordering::Acquire) && !conn.cc_locked {
        conn.congestion = match tcp.algo() {
            CongestionAlgo::Reno => crate::tcp_conn::TcpCongestionControl::Reno,
            CongestionAlgo::Cubic => crate::tcp_conn::TcpCongestionControl::Cubic,
        };
    }
    conn.thin_lto = tcp.thin_lto.load(Ordering::Acquire);
    conn.user_timeout_ns =
        tcp.user_timeout_ms.load(Ordering::Acquire).max(0) as u64 * NS_PER_MS;
    conn.repair = tcp.repair.load(Ordering::Acquire);
    conn.notsent_lowat = tcp.notsent_lowat.load(Ordering::Acquire);
    conn.fastopen_no_cookie = tcp.fastopen_no_cookie.load(Ordering::Acquire);
    if conn.repair { conn.ts_off = tcp.tsoffset.load(Ordering::Acquire) as u32; }
    // A caller-declared one-way delay lengthens the path the moment it is
    // named, so the smoothed estimate and the retransmit timer move by the
    // change — not by the whole delay on every later sample, which would
    // compound without bound.
    let tx_delay_ns = tcp.tx_delay_us.load(Ordering::Acquire).max(0) as u64 * 1_000;
    let delta = tx_delay_ns as i64 - conn.tx_delay_ns as i64;
    conn.tx_delay_ns = tx_delay_ns;
    if delta != 0 && conn.srtt_ns != 0 {
        conn.srtt_ns = conn.srtt_ns.saturating_add_signed(delta).max(1);
        conn.rto_ns = conn.rto_ns.saturating_add_signed(delta).max(1);
    }
    let ticks = |v: i32, default: u64| if v == 0 { default } else { v as u64 * NS_PER_TICK };
    conn.rto_max_ns = ticks(tcp.rto_max_ticks.load(Ordering::Acquire),
        crate::tcp_conn::RTO_MAX_DEFAULT_NS);
    conn.rto_min_ns = ticks(tcp.rto_min_ticks.load(Ordering::Acquire), conn.rto_min_ns);
    conn.delack_max_ns = ticks(tcp.delack_max_ticks.load(Ordering::Acquire),
        crate::tcp_conn::DELACK_MAX_DEFAULT_NS);
    if conn.rto_ns > conn.rto_max_ns { conn.rto_ns = conn.rto_max_ns; }
}

/// Install a repair write on the connection. Repair addresses the sequence and
/// window state directly, which no option block can carry. # C: O(effects)
pub fn repair_to_conn(conn: &mut TcpConn, action: &Action) {
    match action {
        Action::QueueSeq { queue, seq } => {
            if *queue == TCP_SEND_QUEUE {
                conn.snd_una = *seq;
                conn.snd_nxt = *seq;
            } else {
                conn.rcv_nxt = *seq;
                conn.rcv_read_seq = *seq;
            }
        }
        Action::RepairWindow(w) => {
            conn.snd_wl1 = w.snd_wl1;
            conn.snd_wnd = w.snd_wnd;
            conn.max_window = w.max_window;
            conn.rcv_wnd = w.rcv_wnd;
            conn.rcv_wup = w.rcv_wup;
        }
        Action::RepairOptions { effects, .. } => {
            for effect in effects {
                match effect {
                    RepairEffect::MssClamp(mss) => {
                        conn.mss_clamp = *mss;
                        conn.peer_mss = *mss;
                    }
                    RepairEffect::WindowScale { snd, rcv } => {
                        conn.snd_wscale = *snd;
                        conn.rcv_wscale = *rcv;
                    }
                    RepairEffect::SackPerm => conn.sack_ok = true,
                    RepairEffect::Timestamps => conn.ts_enabled = true,
                    RepairEffect::Ignored => {}
                }
            }
        }
        _ => {}
    }
}

/// Release the acknowledgement a ping-pong-mode socket was holding. Setting
/// `TCP_QUICKACK` must put a real segment on the wire, not merely change a
/// mode, or the peer stays blocked on the window this side already opened.
/// It is also how a socket leaving repair reopens the peer's window.
/// # C: O(sack blocks)
pub fn push_pending_ack(entry: &crate::stack::TcpEntry) {
    let segment = {
        let mut c = entry.conn.lock();
        if !matches!(c.state, crate::tcp_state::TcpState::Established
            | crate::tcp_state::TcpState::CloseWait) { return; }
        c.ack_pending = false;
        c.ack_deadline_ns = 0;
        c.rcv_wup = c.rcv_nxt;
        (c.build_ack_with_sack(), c.local.ip, c.remote.ip)
    };
    let (bytes, src, dst) = segment;
    let _ = crate::sock::stack().send_tcp_entry_segment_in(entry, src, dst, &bytes, 0);
    crate::sock::drain_loopback();
}

/// Re-evaluate write readiness after `TCP_NOTSENT_LOWAT` moved the watermark,
/// so a writer parked under the old one is released. # C: O(1)
pub fn notify_write_space(entry: &crate::stack::TcpEntry) {
    entry.notify_writable();
}

/// Install the option block's request-sock state on a live listener, so an
/// option set after `listen` reaches the requests that arrive next. Both are
/// stored in the unit the option stores, not a derived one. # C: O(1)
pub fn to_listener(opts: &SockOpts, listener: &crate::stack::TcpListenEntry) {
    listener.defer_accept.store(
        opts.tcp.defer_accept.load(Ordering::Acquire), Ordering::Release);
    listener.synack_retries.store(
        opts.tcp.syncnt.load(Ordering::Acquire).clamp(0, u8::MAX as i32) as u8,
        Ordering::Release);
}

/// Hand the handshake packet the connection was opened by to the accepted
/// socket, if that socket's inherited `TCP_SAVE_SYN` mode asked for one. A
/// socket that did not ask drops the record rather than carrying it for the
/// life of the connection. # C: O(saved bytes)
pub fn collect_saved_syn(opts: &SockOpts, conn: &mut TcpConn) {
    let recorded = conn.syn_bytes.take();
    if opts.tcp.save_syn.load(Ordering::Acquire) == 0 { return; }
    *opts.tcp.saved_syn.lock() = recorded;
}

/// The window a `TCP_REPAIR_WINDOW` read publishes. # C: O(1)
pub fn repair_window_of(conn: &TcpConn) -> RepairWindow {
    RepairWindow {
        snd_wl1: conn.snd_wl1,
        snd_wnd: conn.snd_wnd,
        max_window: conn.max_window,
        rcv_wnd: conn.rcv_wnd,
        rcv_wup: conn.rcv_wup,
    }
}
