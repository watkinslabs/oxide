// Errno ORDERING and capability ladders for `IPPROTO_TCP` writes. These pin
// which screen wins when several would fail — the part a caller can observe
// and the part that silently drifts.

use syscall::errno::Errno;
use crate::sock_opts::sol_tcp::*;
use crate::sock_opts::sol_tcp::set::{self, Action, Arg, ArgClass, SetEnv};
use crate::tcp_state::TcpState;

fn env() -> SetEnv { SetEnv::default() }

fn admin() -> SetEnv { SetEnv { net_admin: true, ..SetEnv::default() } }

fn set(optname: u64, val: i32, env: SetEnv) -> Result<Action, Errno> {
    set::admit(optname, Arg::Int(val), env)
}

#[test]
fn an_unknown_option_number_is_enoprotoopt() {
    assert_eq!(set(9999, 1, env()), Err(Errno::Enoprotoopt));
}

#[test]
fn only_the_string_and_key_options_escape_the_leading_int_screen() {
    // The shim runs the `int` screen for every other class, so an unknown
    // option number with a short buffer fails EINVAL, not ENOPROTOOPT.
    for optname in [TCP_CONGESTION, TCP_ULP] {
        assert_eq!(set::arg_class(optname), ArgClass::Name);
    }
    assert_eq!(set::arg_class(TCP_FASTOPEN_KEY), ArgClass::FastopenKey);
    assert_eq!(set::arg_class(TCP_REPAIR_WINDOW), ArgClass::RepairWindow);
    assert_eq!(set::arg_class(TCP_REPAIR_OPTIONS), ArgClass::RepairOptions);
    for optname in [TCP_NODELAY, TCP_MAXSEG, TCP_INQ, 9999] {
        assert_eq!(set::arg_class(optname), ArgClass::Int);
    }
}

#[test]
fn repair_needs_network_administration_and_refuses_a_listener() {
    assert_eq!(set(TCP_REPAIR, TCP_REPAIR_ON, env()), Err(Errno::Eperm));
    let listener = SetEnv { net_admin: true, state: TcpState::Listen, ..SetEnv::default() };
    assert_eq!(set(TCP_REPAIR, TCP_REPAIR_ON, listener), Err(Errno::Eperm));
    assert_eq!(set(TCP_REPAIR, TCP_REPAIR_ON, admin()),
        Ok(Action::Repair { on: true, window_probe: false }));
}

#[test]
fn the_repair_capability_ladder_precedes_the_operand_window() {
    assert_eq!(set(TCP_REPAIR, 42, env()), Err(Errno::Eperm));
    assert_eq!(set(TCP_REPAIR, 42, admin()), Err(Errno::Einval));
}

#[test]
fn leaving_repair_probes_the_window_unless_the_caller_declined() {
    assert_eq!(set(TCP_REPAIR, TCP_REPAIR_OFF, admin()),
        Ok(Action::Repair { on: false, window_probe: true }));
    assert_eq!(set(TCP_REPAIR, TCP_REPAIR_OFF_NO_WP, admin()),
        Ok(Action::Repair { on: false, window_probe: false }));
}

#[test]
fn repair_queue_needs_repair_before_it_screens_the_queue_number() {
    assert_eq!(set(TCP_REPAIR_QUEUE, TCP_SEND_QUEUE, env()), Err(Errno::Eperm));
    assert_eq!(set(TCP_REPAIR_QUEUE, 99, env()), Err(Errno::Eperm));
    let repairing = SetEnv { repair: true, ..SetEnv::default() };
    assert_eq!(set(TCP_REPAIR_QUEUE, 99, repairing), Err(Errno::Einval));
    assert_eq!(set(TCP_REPAIR_QUEUE, -1, repairing), Err(Errno::Einval),
        "the queue number is screened as unsigned");
    assert_eq!(set(TCP_REPAIR_QUEUE, TCP_SEND_QUEUE, repairing),
        Ok(Action::RepairQueue(TCP_SEND_QUEUE)));
}

#[test]
fn queue_seq_needs_a_closed_socket_before_it_looks_at_the_queue() {
    let open = SetEnv { state: TcpState::Established, repair_queue: TCP_SEND_QUEUE,
                        ..SetEnv::default() };
    assert_eq!(set(TCP_QUEUE_SEQ, 5, open), Err(Errno::Eperm));
    assert_eq!(set(TCP_QUEUE_SEQ, 5, env()), Err(Errno::Einval));
}

#[test]
fn queue_seq_refuses_to_move_a_sequence_with_data_still_in_flight() {
    let send = SetEnv { repair_queue: TCP_SEND_QUEUE, rtx_queue_empty: false,
                        ..SetEnv::default() };
    assert_eq!(set(TCP_QUEUE_SEQ, 5, send), Err(Errno::Eperm));
    assert_eq!(set(TCP_QUEUE_SEQ, 5, SetEnv { rtx_queue_empty: true, ..send }),
        Ok(Action::QueueSeq { queue: TCP_SEND_QUEUE, seq: 5 }));

    let recv = SetEnv { repair_queue: TCP_RECV_QUEUE, recv_queue_drained: false,
                        ..SetEnv::default() };
    assert_eq!(set(TCP_QUEUE_SEQ, 5, recv), Err(Errno::Eperm));
    assert_eq!(set(TCP_QUEUE_SEQ, 5, SetEnv { recv_queue_drained: true, ..recv }),
        Ok(Action::QueueSeq { queue: TCP_RECV_QUEUE, seq: 5 }));
}

#[test]
fn repair_options_fails_einval_without_repair_but_eperm_in_the_wrong_state() {
    let arg = Arg::RepairOptions(Ok(alloc::vec![]));
    assert_eq!(set::admit(TCP_REPAIR_OPTIONS, arg.clone(), env()), Err(Errno::Einval));
    let sent = SetEnv { repair: true, state: TcpState::Established, bytes_sent: true,
                        ..SetEnv::default() };
    assert_eq!(set::admit(TCP_REPAIR_OPTIONS, arg.clone(), sent), Err(Errno::Eperm));
    assert_eq!(set::admit(TCP_REPAIR_OPTIONS, arg, SetEnv { bytes_sent: false, ..sent }),
        Ok(Action::RepairOptions { effects: alloc::vec![], err: None }));
}

#[test]
fn repair_window_checks_repair_then_length_then_the_copy() {
    let faulted = Arg::RepairWindow { optlen: REPAIR_WINDOW_LEN as u32,
                                      value: Err(Errno::Efault) };
    assert_eq!(set::admit(TCP_REPAIR_WINDOW, faulted.clone(), env()), Err(Errno::Eperm));
    let repairing = SetEnv { repair: true, ..SetEnv::default() };
    let short = Arg::RepairWindow { optlen: 4, value: Ok(RepairWindow::default()) };
    assert_eq!(set::admit(TCP_REPAIR_WINDOW, short, repairing), Err(Errno::Einval));
    assert_eq!(set::admit(TCP_REPAIR_WINDOW, faulted, repairing), Err(Errno::Efault));
}

#[test]
fn the_timestamp_bias_may_only_be_installed_under_repair() {
    assert_eq!(set(TCP_TIMESTAMP, 1000, env()), Err(Errno::Eperm));
    let repairing = SetEnv { repair: true, clock_ts_ms: 400, clock_ts_us: 900,
                             ..SetEnv::default() };
    assert_eq!(set(TCP_TIMESTAMP, 1000, repairing),
        Ok(Action::Timestamp { tsoffset: 600, usec_ts: false }));
    // The low bit selects the microsecond clock, and the bias is taken
    // against that clock, not the millisecond one.
    assert_eq!(set(TCP_TIMESTAMP, 1001, repairing),
        Ok(Action::Timestamp { tsoffset: 101, usec_ts: true }));
}

#[test]
fn a_route_pinned_congestion_control_refuses_every_name() {
    let locked = SetEnv { cc_locked: true, net_admin: true, ..SetEnv::default() };
    assert_eq!(set::admit(TCP_CONGESTION, Arg::Name(b"reno".to_vec()), locked),
        Err(Errno::Eperm));
    // Even naming the algorithm already in use is refused while pinned.
    assert_eq!(set::admit(TCP_CONGESTION, Arg::Name(b"cubic".to_vec()), locked),
        Err(Errno::Eperm));
}

#[test]
fn an_unregistered_congestion_control_is_enoent_not_einval() {
    assert_eq!(set::admit(TCP_CONGESTION, Arg::Name(b"bbr".to_vec()), admin()),
        Err(Errno::Enoent));
}

#[test]
fn switching_to_a_restricted_algorithm_needs_network_administration() {
    let unpriv = SetEnv { current_algo: CongestionAlgo::Reno, ..SetEnv::default() };
    assert_eq!(set::admit(TCP_CONGESTION, Arg::Name(b"cubic".to_vec()), unpriv),
        Err(Errno::Eperm));
    assert_eq!(set::admit(TCP_CONGESTION, Arg::Name(b"cubic".to_vec()),
        SetEnv { net_admin: true, ..unpriv }), Ok(Action::Congestion(CongestionAlgo::Cubic)));
    // Naming the algorithm already in use never needs the capability.
    assert_eq!(set::admit(TCP_CONGESTION, Arg::Name(b"reno".to_vec()), unpriv),
        Ok(Action::Congestion(CongestionAlgo::Reno)));
    // The unrestricted algorithm is free to switch to.
    assert_eq!(set::admit(TCP_CONGESTION, Arg::Name(b"reno".to_vec()), env()),
        Ok(Action::Congestion(CongestionAlgo::Reno)));
}

#[test]
fn no_upper_layer_protocol_name_attaches() {
    // The registry is the only place a ULP may come from; with none
    // registered the answer is "no such protocol", never a stored name.
    for name in [&b"tls"[..], b"espintcp", b"anything"] {
        assert_eq!(set::admit(TCP_ULP, Arg::Name(name.to_vec()), admin()), Err(Errno::Enoent));
    }
}

#[test]
fn fast_open_connect_reports_the_feature_off_before_it_looks_at_state() {
    assert_eq!(set(TCP_FASTOPEN_CONNECT, 2, env()), Err(Errno::Einval));
    assert_eq!(set(TCP_FASTOPEN_CONNECT, 1, env()), Err(Errno::Eopnotsupp));
    let enabled = SetEnv { fastopen_sysctl: TFO_CLIENT_ENABLE, state: TcpState::Established,
                           ..SetEnv::default() };
    assert_eq!(set(TCP_FASTOPEN_CONNECT, 1, enabled), Err(Errno::Einval));
    assert_eq!(set(TCP_FASTOPEN_CONNECT, 1, SetEnv { state: TcpState::Closed, ..enabled }),
        Ok(Action::FastopenConnect(true)));
}

#[test]
fn fast_open_queue_tuning_only_applies_before_the_socket_is_connected() {
    for state in [TcpState::Closed, TcpState::Listen] {
        assert_eq!(set(TCP_FASTOPEN, 8, SetEnv { state, ..SetEnv::default() }),
            Ok(Action::Fastopen(8)));
    }
    assert_eq!(set(TCP_FASTOPEN, 8,
        SetEnv { state: TcpState::Established, ..SetEnv::default() }), Err(Errno::Einval));
    assert_eq!(set(TCP_FASTOPEN, -1, env()), Err(Errno::Einval));
    // The request is bounded by the namespace listen ceiling.
    assert_eq!(set(TCP_FASTOPEN, 9000, SetEnv { somaxconn: 4096, ..SetEnv::default() }),
        Ok(Action::Fastopen(4096)));
}

#[test]
fn fast_open_without_a_cookie_is_refused_once_the_socket_is_connected() {
    assert_eq!(set(TCP_FASTOPEN_NO_COOKIE, 2, env()), Err(Errno::Einval));
    assert_eq!(set(TCP_FASTOPEN_NO_COOKIE, 1,
        SetEnv { state: TcpState::Established, ..SetEnv::default() }), Err(Errno::Einval));
    assert_eq!(set(TCP_FASTOPEN_NO_COOKIE, 1, env()), Ok(Action::FastopenNoCookie(true)));
}

#[test]
fn the_authentication_options_report_no_such_option() {
    // Neither the signature nor the authentication option is carried on any
    // segment this transport emits, so no key can be attached.
    for optname in [TCP_MD5SIG, TCP_MD5SIG_EXT, TCP_AO_ADD_KEY, TCP_AO_DEL_KEY, TCP_AO_INFO] {
        assert_eq!(set(optname, 0, admin()), Err(Errno::Enoprotoopt));
    }
    // The repair variant still runs the repair capability ladder first.
    assert_eq!(set(TCP_AO_REPAIR, 0, env()), Err(Errno::Eperm));
    assert_eq!(set(TCP_AO_REPAIR, 0, admin()), Err(Errno::Enoprotoopt));
}

#[test]
fn the_read_only_option_numbers_refuse_writes() {
    for optname in [TCP_INFO, TCP_CC_INFO, TCP_SAVED_SYN, TCP_IS_MPTCP, TCP_AO_GET_KEYS,
                    TCP_ZEROCOPY_RECEIVE] {
        assert_eq!(set(optname, 0, admin()), Err(Errno::Enoprotoopt), "{optname}");
    }
}
