// Operand windows, value transforms, and the read direction's length rules.

use syscall::errno::Errno;
use alloc::vec::Vec;
use crate::sock_opts::sol_tcp::*;
use crate::sock_opts::sol_tcp::set::{self, Action, Arg, SetEnv};
use crate::sock_opts::sol_tcp::get::{self, GetEnv, Read};
use crate::tcp_state::TcpState;

fn set(optname: u64, val: i32) -> Result<Action, Errno> {
    set::admit(optname, Arg::Int(val), SetEnv::default())
}

fn set_in(optname: u64, val: i32, env: SetEnv) -> Result<Action, Errno> {
    set::admit(optname, Arg::Int(val), env)
}

fn genv<'a>() -> GetEnv<'a> {
    GetEnv {
        state: TcpState::Established, repair: false, repair_queue: TCP_NO_QUEUE,
        mss_cache: 1460, user_mss: 0, mss_clamp: 0, nodelay: false, cork: false,
        keepidle_s: 7200, keepintvl_s: 75, keepcnt: 9,
        syncnt: 0, syncnt_default: TCP_SYN_RETRIES,
        linger2_s: 0, fin_timeout_default_s: TCP_FIN_TIMEOUT_S,
        defer_accept: 0, window_clamp: 0, pingpong: false, algo: ca::DEFAULT, ulp: None,
        thin_lto: false, user_timeout_ms: 0, fastopen_max_qlen: 0, fastopen_connect: false,
        fastopen_no_cookie: false, fastopen_key: None,
        clock_ts: 0, tsoffset: 0, usec_ts: false, notsent_lowat: u32::MAX,
        recvmsg_inq: false, tx_delay_us: 0, save_syn: 0, saved_syn: None,
        write_seq: 0, rcv_nxt: 0, repair_window: RepairWindow::default(),
        rto_max_ticks: 0, rto_min_ticks: 0, delack_max_ticks: 0,
        rto_max_default_ticks: 120_000, rto_min_default_ticks: 200,
        delack_max_default_ticks: 200, net_admin: false,
    }
}

fn read_int(optname: u64, env: GetEnv<'_>) -> Result<i32, Errno> {
    match get::read(optname, 4, env)? {
        Read::Clipped(bytes) if bytes.len() == 4 =>
            Ok(i32::from_ne_bytes(bytes[..4].try_into().unwrap())),
        other => panic!("{optname} did not publish an int: {other:?}"),
    }
}

#[test]
fn the_keepalive_counters_have_upper_bounds_not_just_a_positivity_check() {
    for (optname, max) in [(TCP_KEEPIDLE, MAX_TCP_KEEPIDLE),
                           (TCP_KEEPINTVL, MAX_TCP_KEEPINTVL),
                           (TCP_KEEPCNT, MAX_TCP_KEEPCNT)] {
        assert_eq!(set(optname, 0), Err(Errno::Einval), "{optname} floor");
        assert_eq!(set(optname, -1), Err(Errno::Einval), "{optname} negative");
        assert!(set(optname, 1).is_ok(), "{optname} at the floor");
        assert!(set(optname, max).is_ok(), "{optname} at the ceiling");
        assert_eq!(set(optname, max + 1), Err(Errno::Einval), "{optname} ceiling");
    }
}

#[test]
fn the_syn_retransmit_count_is_bounded_at_both_ends() {
    assert_eq!(set(TCP_SYNCNT, 0), Err(Errno::Einval));
    assert_eq!(set(TCP_SYNCNT, MAX_TCP_SYNCNT + 1), Err(Errno::Einval));
    assert_eq!(set(TCP_SYNCNT, MAX_TCP_SYNCNT), Ok(Action::SynCnt(MAX_TCP_SYNCNT)));
}

#[test]
fn a_segment_size_of_zero_clears_the_request_but_a_tiny_one_is_refused() {
    assert_eq!(set(TCP_MAXSEG, 0), Ok(Action::MaxSeg(0)));
    assert_eq!(set(TCP_MAXSEG, TCP_MIN_MSS - 1), Err(Errno::Einval));
    assert_eq!(set(TCP_MAXSEG, TCP_MIN_MSS), Ok(Action::MaxSeg(TCP_MIN_MSS)));
    assert_eq!(set(TCP_MAXSEG, MAX_TCP_WINDOW), Ok(Action::MaxSeg(MAX_TCP_WINDOW)));
    assert_eq!(set(TCP_MAXSEG, MAX_TCP_WINDOW + 1), Err(Errno::Einval));
}

#[test]
fn the_orphan_lifetime_saturates_rather_than_failing() {
    assert_eq!(set(TCP_LINGER2, -5), Ok(Action::Linger2(-1)));
    assert_eq!(set(TCP_LINGER2, 30), Ok(Action::Linger2(30)));
    assert_eq!(set(TCP_LINGER2, TCP_FIN_TIMEOUT_MAX_S + 100),
        Ok(Action::Linger2(TCP_FIN_TIMEOUT_MAX_S)));
}

#[test]
fn the_orphan_lifetime_reads_back_the_namespace_default_when_unset() {
    assert_eq!(read_int(TCP_LINGER2, genv()), Ok(TCP_FIN_TIMEOUT_S));
    assert_eq!(read_int(TCP_LINGER2, GetEnv { linger2_s: 30, ..genv() }), Ok(30));
    // The "leave at once" sentinel is reported as itself, not as a timeout.
    assert_eq!(read_int(TCP_LINGER2, GetEnv { linger2_s: -1, ..genv() }), Ok(-1));
}

#[test]
fn deferred_accept_is_stored_as_a_retransmit_count_and_reads_back_as_seconds() {
    // A seconds request becomes the retransmit count that covers it, so the
    // value read back is the window that count actually spans.
    assert_eq!(set(TCP_DEFER_ACCEPT, 0), Ok(Action::DeferAccept(0)));
    let Ok(Action::DeferAccept(n)) = set(TCP_DEFER_ACCEPT, 5) else { panic!() };
    assert!(n > 0);
    let seconds = retrans_to_secs(n, TCP_TIMEOUT_INIT_S, TCP_RTO_MAX_SEC);
    assert!(seconds >= 5, "the stored count must cover the requested window");
    assert_eq!(read_int(TCP_DEFER_ACCEPT, GetEnv { defer_accept: n, ..genv() }), Ok(seconds));
    // The conversion is monotone and saturates at the count's own ceiling.
    assert_eq!(set(TCP_DEFER_ACCEPT, i32::MAX), Ok(Action::DeferAccept(u8::MAX)));
}

#[test]
fn a_zero_window_clamp_is_only_accepted_before_the_socket_connects() {
    assert_eq!(set(TCP_WINDOW_CLAMP, 0), Ok(Action::WindowClamp(0)));
    assert_eq!(set_in(TCP_WINDOW_CLAMP, 0,
        SetEnv { state: TcpState::Established, ..SetEnv::default() }), Err(Errno::Einval));
}

#[test]
fn a_small_window_clamp_is_raised_to_the_floor_not_refused() {
    let floor = window_clamp_floor();
    assert_eq!(set(TCP_WINDOW_CLAMP, 1), Ok(Action::WindowClamp(floor)));
    assert_eq!(set(TCP_WINDOW_CLAMP, floor * 4), Ok(Action::WindowClamp(floor * 4)));
}

#[test]
fn quick_acknowledgement_mode_is_the_inverse_of_ping_pong() {
    // Clearing it parks the socket in ping-pong with nothing to send.
    assert_eq!(set(TCP_QUICKACK, 0), Ok(Action::QuickAck { pingpong: true, push_ack: false }));
    // Setting it leaves ping-pong; with an ACK owed, that ACK goes out.
    assert_eq!(set(TCP_QUICKACK, 1), Ok(Action::QuickAck { pingpong: false, push_ack: false }));
    let owed = SetEnv { state: TcpState::Established, ack_scheduled: true,
                        ..SetEnv::default() };
    assert_eq!(set_in(TCP_QUICKACK, 1, owed),
        Ok(Action::QuickAck { pingpong: false, push_ack: true }));
    // An even operand releases the held ACK but returns to ping-pong.
    assert_eq!(set_in(TCP_QUICKACK, 2, owed),
        Ok(Action::QuickAck { pingpong: true, push_ack: true }));
    assert_eq!(read_int(TCP_QUICKACK, GetEnv { pingpong: true, ..genv() }), Ok(0));
    assert_eq!(read_int(TCP_QUICKACK, GetEnv { pingpong: false, ..genv() }), Ok(1));
}

#[test]
fn the_boolean_options_reject_anything_outside_zero_and_one() {
    for optname in [TCP_THIN_LINEAR_TIMEOUTS, TCP_THIN_DUPACK, TCP_INQ] {
        assert_eq!(set(optname, 2), Err(Errno::Einval), "{optname}");
        assert_eq!(set(optname, -1), Err(Errno::Einval), "{optname}");
        assert!(set(optname, 1).is_ok(), "{optname}");
    }
    assert_eq!(set(TCP_SAVE_SYN, SAVE_SYN_MAX), Ok(Action::SaveSyn(SAVE_SYN_MAX)));
    assert_eq!(set(TCP_SAVE_SYN, SAVE_SYN_MAX + 1), Err(Errno::Einval));
}

#[test]
fn the_user_timeout_accepts_zero_but_not_a_negative_window() {
    assert_eq!(set(TCP_USER_TIMEOUT, -1), Err(Errno::Einval));
    assert_eq!(set(TCP_USER_TIMEOUT, 0), Ok(Action::UserTimeout(0)));
    assert_eq!(set(TCP_USER_TIMEOUT, 30_000), Ok(Action::UserTimeout(30_000)));
}

#[test]
fn the_transmit_delay_is_bounded_by_the_estimate_it_is_folded_into() {
    assert_eq!(set(TCP_TX_DELAY, -1), Err(Errno::Einval));
    assert_eq!(set(TCP_TX_DELAY, TX_DELAY_LIMIT), Err(Errno::Einval));
    assert_eq!(set(TCP_TX_DELAY, TX_DELAY_LIMIT - 1),
        Ok(Action::TxDelay(TX_DELAY_LIMIT - 1)));
}

#[test]
fn the_unsent_watermark_takes_any_value_including_the_disabled_sentinel() {
    assert_eq!(set(TCP_NOTSENT_LOWAT, 0), Ok(Action::NotsentLowat(0)));
    assert_eq!(set(TCP_NOTSENT_LOWAT, -1), Ok(Action::NotsentLowat(u32::MAX)));
    assert_eq!(read_int(TCP_NOTSENT_LOWAT, genv()), Ok(-1));
}

#[test]
fn the_timer_windows_are_bounded_by_the_tick_granularity() {
    // A window under two ticks cannot be represented, and neither can one
    // above the transport's own floor for the retransmit timer.
    assert_eq!(set(TCP_RTO_MIN_US, 1_000), Err(Errno::Einval));
    assert_eq!(set(TCP_RTO_MIN_US, 2_000),
        Ok(Action::RtoMinTicks(TCP_TIMEOUT_MIN_TICKS as i32)));
    assert_eq!(set(TCP_RTO_MIN_US, 200_000), Ok(Action::RtoMinTicks(TCP_RTO_MIN_TICKS as i32)));
    assert_eq!(set(TCP_RTO_MIN_US, 200_001), Err(Errno::Einval));

    assert_eq!(set(TCP_DELACK_MAX_US, 1_000), Err(Errno::Einval));
    assert_eq!(set(TCP_DELACK_MAX_US, 200_000),
        Ok(Action::DelackMaxTicks(TCP_DELACK_MAX_TICKS as i32)));
    assert_eq!(set(TCP_DELACK_MAX_US, 200_001), Err(Errno::Einval));

    assert_eq!(set(TCP_RTO_MAX_MS, 999), Err(Errno::Einval));
    assert_eq!(set(TCP_RTO_MAX_MS, 1_000), Ok(Action::RtoMaxTicks(1_000)));
    assert_eq!(set(TCP_RTO_MAX_MS, TCP_RTO_MAX_SEC * 1000 + 1), Err(Errno::Einval));
}

#[test]
fn the_timer_windows_read_back_in_the_unit_they_were_named_in() {
    assert_eq!(read_int(TCP_RTO_MIN_US, GetEnv { rto_min_ticks: 200, ..genv() }), Ok(200_000));
    assert_eq!(read_int(TCP_DELACK_MAX_US, GetEnv { delack_max_ticks: 50, ..genv() }),
        Ok(50_000));
    assert_eq!(read_int(TCP_RTO_MAX_MS, GetEnv { rto_max_ticks: 5_000, ..genv() }), Ok(5_000));
    // Unset, each reports the transport default rather than zero.
    assert_eq!(read_int(TCP_RTO_MAX_MS, genv()), Ok(120_000));
    assert_eq!(read_int(TCP_RTO_MIN_US, genv()), Ok(200_000));
}

#[test]
fn the_segment_size_read_prefers_the_caller_value_only_before_connecting() {
    let named = GetEnv { user_mss: 1000, mss_cache: 1460, ..genv() };
    assert_eq!(read_int(TCP_MAXSEG, named), Ok(1460), "an established socket reports the live size");
    assert_eq!(read_int(TCP_MAXSEG, GetEnv { state: TcpState::Closed, ..named }), Ok(1000));
    assert_eq!(read_int(TCP_MAXSEG, GetEnv { state: TcpState::Listen, ..named }), Ok(1000));
    // Under repair the restored clamp is what the connection will use.
    assert_eq!(read_int(TCP_MAXSEG, GetEnv { repair: true, mss_clamp: 1200, ..named }), Ok(1200));
}

#[test]
fn the_syn_retransmit_count_reads_back_the_default_when_unset() {
    assert_eq!(read_int(TCP_SYNCNT, genv()), Ok(TCP_SYN_RETRIES));
    assert_eq!(read_int(TCP_SYNCNT, GetEnv { syncnt: 3, ..genv() }), Ok(3));
}

#[test]
fn the_repair_queue_read_fails_when_the_socket_is_not_under_repair() {
    assert_eq!(get::read(TCP_REPAIR_QUEUE, 4, genv()), Err(Errno::Einval));
    assert_eq!(read_int(TCP_REPAIR_QUEUE, GetEnv { repair: true,
        repair_queue: TCP_SEND_QUEUE, ..genv() }), Ok(TCP_SEND_QUEUE));
}

#[test]
fn the_queue_sequence_read_reports_the_side_the_repair_queue_selects() {
    let env = GetEnv { write_seq: 111, rcv_nxt: 222, ..genv() };
    assert_eq!(get::read(TCP_QUEUE_SEQ, 4, env), Err(Errno::Einval));
    assert_eq!(read_int(TCP_QUEUE_SEQ, GetEnv { repair_queue: TCP_SEND_QUEUE, ..env }), Ok(111));
    assert_eq!(read_int(TCP_QUEUE_SEQ, GetEnv { repair_queue: TCP_RECV_QUEUE, ..env }), Ok(222));
}

#[test]
fn the_repair_window_read_screens_the_length_before_the_repair_state() {
    // Opposite order to the write direction, where repair is checked first.
    assert_eq!(get::read(TCP_REPAIR_WINDOW, 4, genv()), Err(Errno::Einval));
    assert_eq!(get::read(TCP_REPAIR_WINDOW, REPAIR_WINDOW_LEN, genv()), Err(Errno::Eperm));
    let w = RepairWindow { snd_wl1: 1, snd_wnd: 2, max_window: 3, rcv_wnd: 4, rcv_wup: 5 };
    assert_eq!(get::read(TCP_REPAIR_WINDOW, REPAIR_WINDOW_LEN,
        GetEnv { repair: true, repair_window: w, ..genv() }),
        Ok(Read::Fixed(w.to_bytes().to_vec())));
}

#[test]
fn the_congestion_control_name_is_published_at_the_full_buffer_width() {
    let Ok(Read::Clipped(bytes)) = get::read(TCP_CONGESTION, 16,
        GetEnv { algo: CongestionAlgo::Reno, ..genv() }) else { panic!() };
    assert_eq!(bytes.len(), CA_NAME_MAX);
    assert_eq!(&bytes[..4], b"reno");
}

#[test]
fn reads_with_nothing_to_report_succeed_at_zero_length() {
    // No ULP is attached, no algorithm keeps private statistics, and no
    // fast-open key was installed; each is a success with an empty value, not
    // an error.
    for optname in [TCP_ULP, TCP_CC_INFO, TCP_FASTOPEN_KEY, TCP_SAVED_SYN] {
        assert_eq!(get::read(optname, 64, genv()), Ok(Read::Clipped(Vec::new())), "{optname}");
    }
}

#[test]
fn a_recorded_handshake_is_published_only_into_a_buffer_that_fits_it() {
    let syn: Vec<u8> = (0..40u8).collect();
    let env = GetEnv { saved_syn: Some(&syn), ..genv() };
    assert_eq!(get::read(TCP_SAVED_SYN, 39, env), Err(Errno::Einval));
    assert_eq!(get::saved_syn_required(&env), Some(40));
    assert_eq!(get::read(TCP_SAVED_SYN, 40, env), Ok(Read::Consume(syn.clone())));
    assert_eq!(get::read(TCP_SAVED_SYN, 4096, env), Ok(Read::Consume(syn)));
}

#[test]
fn the_timestamp_read_carries_the_clock_resolution_in_its_low_bit() {
    let ms = GetEnv { clock_ts: 1000, tsoffset: 24, ..genv() };
    assert_eq!(read_int(TCP_TIMESTAMP, ms), Ok(1024));
    // An odd sum is forced even while the millisecond clock is selected.
    assert_eq!(read_int(TCP_TIMESTAMP, GetEnv { tsoffset: 25, ..ms }), Ok(1024));
    assert_eq!(read_int(TCP_TIMESTAMP, GetEnv { usec_ts: true, ..ms }), Ok(1025));
}

#[test]
fn an_unknown_read_is_enoprotoopt_and_the_unsupported_reads_say_so() {
    assert_eq!(get::read(9999, 4, genv()), Err(Errno::Enoprotoopt));
    for optname in [TCP_ZEROCOPY_RECEIVE, TCP_AO_GET_KEYS, TCP_AO_INFO] {
        assert_eq!(get::read(optname, 64, genv()), Err(Errno::Enoprotoopt), "{optname}");
    }
    // The authentication repair read still runs the capability ladder first.
    assert_eq!(get::read(TCP_AO_REPAIR, 64, genv()), Err(Errno::Eperm));
    assert_eq!(get::read(TCP_AO_REPAIR, 64, GetEnv { net_admin: true, ..genv() }),
        Err(Errno::Enoprotoopt));
}

#[test]
fn multipath_and_single_duplicate_recovery_report_themselves_off() {
    assert_eq!(read_int(TCP_IS_MPTCP, genv()), Ok(0));
    assert_eq!(read_int(TCP_THIN_DUPACK, genv()), Ok(0));
}

#[test]
fn every_writable_option_number_is_also_readable() {
    // A caller that set an option must be able to read it back; the only
    // write-side numbers without a read are the ones that carry no state.
    for optname in [TCP_NODELAY, TCP_MAXSEG, TCP_CORK, TCP_KEEPIDLE, TCP_KEEPINTVL,
                    TCP_KEEPCNT, TCP_SYNCNT, TCP_LINGER2, TCP_DEFER_ACCEPT,
                    TCP_WINDOW_CLAMP, TCP_QUICKACK, TCP_CONGESTION,
                    TCP_THIN_LINEAR_TIMEOUTS, TCP_THIN_DUPACK, TCP_USER_TIMEOUT,
                    TCP_REPAIR, TCP_FASTOPEN, TCP_TIMESTAMP, TCP_NOTSENT_LOWAT,
                    TCP_SAVE_SYN, TCP_FASTOPEN_CONNECT, TCP_ULP, TCP_FASTOPEN_KEY,
                    TCP_FASTOPEN_NO_COOKIE, TCP_INQ, TCP_TX_DELAY, TCP_RTO_MAX_MS,
                    TCP_RTO_MIN_US, TCP_DELACK_MAX_US]
    {
        assert!(get::read(optname, 64, GetEnv { repair: true, ..genv() }).is_ok(),
            "{optname} has no read");
    }
}
