use super::*;
use super::get::{SockView, Value};
use super::set::{Action, Arg, ArgClass, SetEnv, admit, arg_class, bind_device_allowed,
    device_name_len, devmem_dontneed_tokens};
use syscall::errno::Errno;

const AF_UNIX_W: u16 = crate::socket_args::AF_UNIX as u16;
const AF_INET_W: u16 = crate::socket_args::AF_INET as u16;
const AF_NETLINK_W: u16 = crate::socket_args::AF_NETLINK as u16;
const AF_PACKET_W: u16 = crate::socket_args::AF_PACKET as u16;

fn tcp() -> OptSock { OptSock { family: AF_INET_W, stream: true, tcp: true, udp: false, peek_off_capable: false } }
fn udp() -> OptSock { OptSock { family: AF_INET_W, stream: false, tcp: false, udp: true, peek_off_capable: false } }
fn unix() -> OptSock { OptSock { family: AF_UNIX_W, stream: true, tcp: false, udp: false, peek_off_capable: true } }
fn unix_dgram() -> OptSock { OptSock { stream: false, ..unix() } }
fn packet() -> OptSock { OptSock { family: AF_PACKET_W, ..Default::default() } }

fn none() -> OptCaps { OptCaps::default() }
fn admin() -> OptCaps { OptCaps { net_admin: true, net_raw: false } }
fn raw() -> OptCaps { OptCaps { net_admin: false, net_raw: true } }

fn env(caps: OptCaps) -> SetEnv { SetEnv { caps, ..Default::default() } }

fn set(optname: u64, value: i32, sock: OptSock, caps: OptCaps) -> Result<Action, Errno> {
    admit(optname, Arg::Int(value), sock, env(caps))
}

#[test]
fn every_option_but_bindtodevice_reads_a_leading_int() {
    assert!(!reads_int_argument(SO_BINDTODEVICE));
    for optname in [SO_DEBUG, SO_LINGER, SO_RCVTIMEO_OLD, SO_TXTIME, SO_MAX_PACING_RATE, 0xdead] {
        assert!(reads_int_argument(optname), "optname {optname}");
    }
}

#[test]
fn unknown_option_is_enoprotoopt_only_after_the_int_argument() {
    // The caller screens the length first; the table itself never sees a
    // short buffer, so an unknown number can only fail as ENOPROTOOPT.
    assert_eq!(set(0xdead, 0, tcp(), admin()), Err(Errno::Enoprotoopt));
    assert_eq!(arg_class(0xdead), ArgClass::Int);
}

#[test]
fn identity_and_error_slots_are_not_settable() {
    for optname in [SO_TYPE, SO_PROTOCOL, SO_DOMAIN, SO_ERROR] {
        assert_eq!(set(optname, 1, tcp(), admin()), Err(Errno::Enoprotoopt), "{optname}");
    }
}

#[test]
fn forced_buffer_sizes_require_net_admin() {
    assert_eq!(set(SO_SNDBUFFORCE, 8192, tcp(), none()), Err(Errno::Eperm));
    assert_eq!(set(SO_RCVBUFFORCE, 8192, tcp(), none()), Err(Errno::Eperm));
    assert_eq!(set(SO_SNDBUFFORCE, 8192, tcp(), raw()), Err(Errno::Eperm));
    assert_eq!(set(SO_SNDBUFFORCE, 8192, tcp(), admin()), Ok(Action::SndBuf(16384)));
    assert_eq!(set(SO_RCVBUFFORCE, 8192, tcp(), admin()), Ok(Action::RcvBuf(16384)));
    // Unprivileged callers still reach the unforced options.
    assert_eq!(set(SO_SNDBUF, 8192, tcp(), none()), Ok(Action::SndBuf(16384)));
}

#[test]
fn buffer_sizes_double_clamp_to_the_sysctl_ceiling_and_floor_at_the_minimum() {
    assert_eq!(buf_value(0, SOCK_MIN_SNDBUF, DEFAULT_WMEM_MAX, false), SOCK_MIN_SNDBUF);
    assert_eq!(buf_value(1024, SOCK_MIN_RCVBUF, DEFAULT_RMEM_MAX, false), 2304);
    assert_eq!(buf_value(4096, SOCK_MIN_RCVBUF, DEFAULT_RMEM_MAX, false), 8192);
    // Above the ceiling the request is clamped before doubling.
    assert_eq!(buf_value(1 << 30, SOCK_MIN_SNDBUF, DEFAULT_WMEM_MAX, false),
        (DEFAULT_WMEM_MAX as i32) * 2);
    // The unforced path clamps as an unsigned quantity, so a negative request
    // saturates at the ceiling rather than collapsing to the minimum.
    assert_eq!(buf_value(-1, SOCK_MIN_SNDBUF, DEFAULT_WMEM_MAX, false),
        (DEFAULT_WMEM_MAX as i32) * 2);
    // The forced path clamps negatives to zero, so it lands on the minimum.
    assert_eq!(buf_value(-1, SOCK_MIN_SNDBUF, DEFAULT_WMEM_MAX, true), SOCK_MIN_SNDBUF);
    // The forced path ignores the ceiling entirely.
    assert_eq!(buf_value(1 << 29, SOCK_MIN_SNDBUF, DEFAULT_WMEM_MAX, true), 1 << 30);
    // Doubling never wraps into a negative size.
    assert!(buf_value(i32::MAX, SOCK_MIN_SNDBUF, u32::MAX, true) > 0);
}

#[test]
fn mark_requires_a_network_capability() {
    assert_eq!(set(SO_MARK, 7, tcp(), none()), Err(Errno::Eperm));
    assert_eq!(set(SO_MARK, 7, tcp(), raw()), Ok(Action::Mark(7)));
    assert_eq!(set(SO_MARK, 7, tcp(), admin()), Ok(Action::Mark(7)));
}

#[test]
fn priority_above_the_interactive_band_requires_a_network_capability() {
    assert_eq!(set(SO_PRIORITY, TC_PRIO_BESTEFFORT, tcp(), none()), Ok(Action::Priority(0)));
    assert_eq!(set(SO_PRIORITY, TC_PRIO_INTERACTIVE, tcp(), none()), Ok(Action::Priority(6)));
    assert_eq!(set(SO_PRIORITY, 7, tcp(), none()), Err(Errno::Eperm));
    assert_eq!(set(SO_PRIORITY, -1, tcp(), none()), Err(Errno::Eperm));
    assert_eq!(set(SO_PRIORITY, 7, tcp(), raw()), Ok(Action::Priority(7)));
    assert_eq!(set(SO_PRIORITY, 7, tcp(), admin()), Ok(Action::Priority(7)));
}

#[test]
fn debug_denies_without_net_admin_but_clearing_is_always_allowed() {
    assert_eq!(set(SO_DEBUG, 1, tcp(), none()), Err(Errno::Eacces));
    assert_eq!(set(SO_DEBUG, 0, tcp(), none()),
        Ok(Action::Flag { bit: flag::DEBUG, on: false }));
    assert_eq!(set(SO_DEBUG, 1, tcp(), admin()),
        Ok(Action::Flag { bit: flag::DEBUG, on: true }));
}

#[test]
fn reuseport_is_only_meaningful_on_inet_sockets() {
    assert_eq!(set(SO_REUSEPORT, 1, unix(), admin()), Err(Errno::Eopnotsupp));
    assert_eq!(set(SO_REUSEPORT, 1, tcp(), none()), Ok(Action::Reuseport(1)));
    // Clearing it is accepted everywhere.
    assert_eq!(set(SO_REUSEPORT, 0, unix(), none()), Ok(Action::Reuseport(0)));
}

#[test]
fn scm_options_are_gated_on_the_families_that_carry_them() {
    let netlink = OptSock { family: AF_NETLINK_W, ..Default::default() };
    assert_eq!(set(SO_PASSCRED, 1, unix(), none()), Ok(Action::Passcred(1)));
    assert_eq!(set(SO_PASSCRED, 1, netlink, none()), Ok(Action::Passcred(1)));
    assert_eq!(set(SO_PASSCRED, 1, tcp(), none()), Err(Errno::Eopnotsupp));
    assert_eq!(set(SO_PASSSEC, 1, tcp(), none()), Err(Errno::Eopnotsupp));
    // The pidfd and rights options are AF_UNIX only, not every SCM family.
    assert_eq!(set(SO_PASSPIDFD, 1, netlink, none()), Err(Errno::Eopnotsupp));
    assert_eq!(set(SO_PASSRIGHTS, 1, netlink, none()), Err(Errno::Eopnotsupp));
    assert_eq!(set(SO_PASSPIDFD, 1, unix(), none()),
        Ok(Action::Flag { bit: flag::SCM_PIDFD, on: true }));
    assert_eq!(set(SO_PASSRIGHTS, 1, unix(), none()),
        Ok(Action::Flag { bit: flag::SCM_RIGHTS_OFF, on: false }));
}

#[test]
fn timeouts_reject_a_denormalized_microsecond_field_with_edom() {
    assert_eq!(timeout_ns_from_timeval(0, -1), Err(Errno::Edom));
    assert_eq!(timeout_ns_from_timeval(0, 1_000_000), Err(Errno::Edom));
    assert_eq!(timeout_ns_from_timeval(1, 999_999), Ok(1_999_999_000));
    // An all-zero value clears the timeout.
    assert_eq!(timeout_ns_from_timeval(0, 0), Ok(0));
    // A negative second field asks for an immediate timeout, not an infinite
    // one, so it must not decode to the "wait forever" encoding.
    let immediate = timeout_ns_from_timeval(-1, 0).unwrap();
    assert_eq!(immediate, IMMEDIATE_TIMEOUT_NS);
    assert_ne!(immediate, 0);
    // The microsecond screen outranks the negative-second shortcut.
    assert_eq!(timeout_ns_from_timeval(-1, 1_000_000), Err(Errno::Edom));
    // A huge second field saturates instead of wrapping negative.
    assert!(timeout_ns_from_timeval(i64::MAX, 0).unwrap() > 0);
}

#[test]
fn timeout_admission_routes_send_and_receive_slots() {
    let arg = Arg::Timeval { sec: 2, usec: 500_000 };
    assert_eq!(admit(SO_SNDTIMEO_OLD, arg, tcp(), SetEnv { caps: none(), bound_device: false, ..Default::default() }),
        Ok(Action::Timeout { send: true, ns: 2_500_000_000 }));
    assert_eq!(admit(SO_SNDTIMEO_NEW, arg, tcp(), SetEnv { caps: none(), bound_device: false, ..Default::default() }),
        Ok(Action::Timeout { send: true, ns: 2_500_000_000 }));
    assert_eq!(admit(SO_RCVTIMEO_OLD, arg, tcp(), SetEnv { caps: none(), bound_device: false, ..Default::default() }),
        Ok(Action::Timeout { send: false, ns: 2_500_000_000 }));
    assert_eq!(admit(SO_RCVTIMEO_NEW, arg, tcp(), SetEnv { caps: none(), bound_device: false, ..Default::default() }),
        Ok(Action::Timeout { send: false, ns: 2_500_000_000 }));
    assert_eq!(admit(SO_RCVTIMEO_OLD, Arg::Timeval { sec: 0, usec: -5 }, tcp(), SetEnv { caps: none(), bound_device: false, ..Default::default() }),
        Err(Errno::Edom));
}

#[test]
fn timeout_readback_reports_zero_for_unset_and_immediate() {
    assert_eq!(timeval_from_timeout_ns(0), (0, 0));
    assert_eq!(timeval_from_timeout_ns(IMMEDIATE_TIMEOUT_NS), (0, 0));
    assert_eq!(timeval_from_timeout_ns(2_500_000_000), (2, 500_000));
}

#[test]
fn linger_stores_the_flag_separately_from_the_stored_seconds() {
    assert_eq!(admit(SO_LINGER, Arg::Linger { on: 0, seconds: 5 }, tcp(), SetEnv { caps: none(), bound_device: false, ..Default::default() }),
        Ok(Action::Linger { on: false, seconds: 5 }));
    assert_eq!(admit(SO_LINGER, Arg::Linger { on: 1, seconds: 5 }, tcp(), SetEnv { caps: none(), bound_device: false, ..Default::default() }),
        Ok(Action::Linger { on: true, seconds: 5 }));
    assert_eq!(arg_class(SO_LINGER), ArgClass::Linger);
    // Clearing the switch must not publish the caller's seconds: Linux only
    // updates the stored linger time when the switch is on.
    let state = GenericSockOpts::default();
    state.set_flag(flag::LINGER, true);
    state.set_scalar(Scalar::LingerSeconds, 9);
    state.set_flag(flag::LINGER, false);
    let view = SockView { sock: tcp(), ..Default::default() };
    assert_eq!(get::value(SO_LINGER, 8, &state, &view), Ok(Value::Linger { on: 0, seconds: 9 }));
}

#[test]
fn txtime_validates_flags_then_the_clock_capability_then_the_clock() {
    let ok = Arg::TxTime { clockid: set::CLOCK_MONOTONIC, flags: SOF_TXTIME_DEADLINE_MODE };
    assert_eq!(admit(SO_TXTIME, ok, tcp(), SetEnv { caps: none(), bound_device: false, ..Default::default() }), Ok(Action::TxTime {
        clockid: set::CLOCK_MONOTONIC, deadline_mode: true, report_errors: false }));
    assert_eq!(admit(SO_TXTIME, Arg::TxTime { clockid: set::CLOCK_MONOTONIC, flags: 0x8 },
        tcp(), SetEnv { caps: admin(), bound_device: false, ..Default::default() }), Err(Errno::Einval));
    // A non-monotonic clock needs CAP_NET_ADMIN before the clock is validated.
    assert_eq!(admit(SO_TXTIME, Arg::TxTime { clockid: 4242, flags: 0 }, tcp(), SetEnv { caps: none(), bound_device: false, ..Default::default() }),
        Err(Errno::Eperm));
    assert_eq!(admit(SO_TXTIME, Arg::TxTime { clockid: 4242, flags: 0 }, tcp(), SetEnv { caps: admin(), bound_device: false, ..Default::default() }),
        Err(Errno::Einval));
    assert!(admit(SO_TXTIME, Arg::TxTime { clockid: set::CLOCK_TAI, flags: 0 },
        tcp(), SetEnv { caps: admin(), bound_device: false, ..Default::default() }).is_ok());
}

#[test]
fn zerocopy_is_limited_to_tcp_and_udp_and_a_boolean_value() {
    assert_eq!(set(SO_ZEROCOPY, 1, tcp(), none()),
        Ok(Action::Flag { bit: flag::ZEROCOPY, on: true }));
    assert_eq!(set(SO_ZEROCOPY, 1, udp(), none()),
        Ok(Action::Flag { bit: flag::ZEROCOPY, on: true }));
    assert_eq!(set(SO_ZEROCOPY, 1, unix(), none()), Err(Errno::Eopnotsupp));
    assert_eq!(set(SO_ZEROCOPY, 1, packet(), none()), Err(Errno::Eopnotsupp));
    assert_eq!(set(SO_ZEROCOPY, 2, tcp(), none()), Err(Errno::Einval));
    let raw_inet = OptSock { family: AF_INET_W, ..Default::default() };
    assert_eq!(set(SO_ZEROCOPY, 1, raw_inet, none()), Err(Errno::Eopnotsupp));
}

#[test]
fn txrehash_is_tcp_only_and_maps_the_default_sentinel() {
    assert_eq!(set(SO_TXREHASH, 1, udp(), admin()), Err(Errno::Eopnotsupp));
    assert_eq!(set(SO_TXREHASH, 2, tcp(), admin()), Err(Errno::Einval));
    assert_eq!(set(SO_TXREHASH, -2, tcp(), admin()), Err(Errno::Einval));
    assert_eq!(set(SO_TXREHASH, -1, tcp(), admin()),
        Ok(Action::Scalar { slot: Scalar::TxRehash, value: 1 }));
    assert_eq!(set(SO_TXREHASH, 0, tcp(), admin()),
        Ok(Action::Scalar { slot: Scalar::TxRehash, value: 0 }));
}

#[test]
fn bounded_scalars_reject_out_of_range_requests() {
    assert_eq!(set(SO_BUSY_POLL, -1, tcp(), admin()), Err(Errno::Einval));
    assert_eq!(set(SO_RESERVE_MEM, -1, tcp(), admin()), Err(Errno::Einval));
    assert_eq!(set(SO_BUF_LOCK, 4, tcp(), admin()), Err(Errno::Einval));
    assert_eq!(set(SO_BUF_LOCK, SOCK_BUF_LOCK_MASK, tcp(), admin()),
        Ok(Action::Scalar { slot: Scalar::BufLock, value: SOCK_BUF_LOCK_MASK }));
    assert_eq!(set(SO_BINDTOIFINDEX, -1, tcp(), admin()), Err(Errno::Einval));
    assert_eq!(set(SO_BINDTOIFINDEX, 3, tcp(), none()), Ok(Action::BindToIfindex(3)));
}

#[test]
fn rcvlowat_normalizes_the_stored_watermark() {
    assert_eq!(set(SO_RCVLOWAT, -1, tcp(), none()),
        Ok(Action::Scalar { slot: Scalar::RcvLowat, value: i32::MAX }));
    assert_eq!(set(SO_RCVLOWAT, 0, tcp(), none()),
        Ok(Action::Scalar { slot: Scalar::RcvLowat, value: 1 }));
    assert_eq!(set(SO_RCVLOWAT, 64, tcp(), none()),
        Ok(Action::Scalar { slot: Scalar::RcvLowat, value: 64 }));
}

#[test]
fn peek_off_needs_a_socket_that_implements_it() {
    assert_eq!(set(SO_PEEK_OFF, 4, tcp(), admin()), Err(Errno::Eopnotsupp));
    assert_eq!(set(SO_PEEK_OFF, 4, unix(), none()),
        Ok(Action::Scalar { slot: Scalar::PeekOff, value: 4 }));
}

#[test]
fn pacing_rate_uses_the_wide_form_only_when_the_caller_supplies_one() {
    assert_eq!(arg_class(SO_MAX_PACING_RATE), ArgClass::PacingRate);
    assert_eq!(admit(SO_MAX_PACING_RATE, Arg::PacingRate(1 << 40), tcp(), SetEnv { caps: none(), bound_device: false, ..Default::default() }),
        Ok(Action::PacingRate(1 << 40)));
    assert_eq!(set(SO_MAX_PACING_RATE, 1000, tcp(), none()), Ok(Action::PacingRate(1000)));
    // The all-ones 32-bit request means "unlimited", not four billion.
    assert_eq!(set(SO_MAX_PACING_RATE, -1, tcp(), none()), Ok(Action::PacingRate(u64::MAX)));
}

#[test]
fn rebinding_a_device_needs_cap_net_raw_only_when_one_is_already_bound() {
    assert_eq!(bind_device_allowed(none(), false), Ok(()));
    assert_eq!(bind_device_allowed(none(), true), Err(Errno::Eperm));
    assert_eq!(bind_device_allowed(raw(), true), Ok(()));
    assert_eq!(admit(SO_BINDTOIFINDEX, Arg::Int(2), tcp(), SetEnv { caps: none(), bound_device: true, ..Default::default() }), Err(Errno::Eperm));
}

#[test]
fn device_names_are_truncated_not_rejected() {
    assert_eq!(device_name_len(0), 0);
    assert_eq!(device_name_len(4), 4);
    assert_eq!(device_name_len(15), 15);
    assert_eq!(device_name_len(16), 15);
    assert_eq!(device_name_len(4096), 15);
}

#[test]
fn timestamp_personalities_read_back_only_through_their_own_option() {
    let state = GenericSockOpts::default();
    let view = SockView { sock: tcp(), timestamping_flags: 0x11, ..Default::default() };
    let apply = |action: Action| {
        if let Action::RecvTimestamps { on, new, nanoseconds } = action {
            state.set_flag(flag::RCVTSTAMP, on);
            state.set_flag(flag::RCVTSTAMPNS, on && nanoseconds);
            if on { state.set_flag(flag::TSTAMP_NEW, new); }
        }
    };
    apply(set(SO_TIMESTAMP_OLD, 1, tcp(), none()).unwrap());
    assert_eq!(get::value(SO_TIMESTAMP_OLD, 4, &state, &view), Ok(Value::Int(1)));
    assert_eq!(get::value(SO_TIMESTAMP_NEW, 4, &state, &view), Ok(Value::Int(0)));
    assert_eq!(get::value(SO_TIMESTAMPNS_OLD, 4, &state, &view), Ok(Value::Int(0)));

    apply(set(SO_TIMESTAMPNS_NEW, 1, tcp(), none()).unwrap());
    assert_eq!(get::value(SO_TIMESTAMPNS_NEW, 4, &state, &view), Ok(Value::Int(1)));
    assert_eq!(get::value(SO_TIMESTAMPNS_OLD, 4, &state, &view), Ok(Value::Int(0)));
    assert_eq!(get::value(SO_TIMESTAMP_OLD, 4, &state, &view), Ok(Value::Int(0)));

    // SO_TIMESTAMPING_OLD always reports the stored flags; the new option
    // reports them only once the socket adopted the new personality.
    assert_eq!(get::value(SO_TIMESTAMPING_OLD, 8, &state, &view),
        Ok(Value::Timestamping { flags: 0x11, bind_phc: 0 }));
    assert_eq!(get::value(SO_TIMESTAMPING_NEW, 8, &state, &view),
        Ok(Value::Timestamping { flags: 0x11, bind_phc: 0 }));
    state.set_flag(flag::TSTAMP_NEW, false);
    assert_eq!(get::value(SO_TIMESTAMPING_NEW, 8, &state, &view),
        Ok(Value::Timestamping { flags: 0, bind_phc: 0 }));
}

#[test]
fn read_side_lengths_match_the_linux_natural_widths() {
    let state = GenericSockOpts::default();
    let view = SockView { sock: unix(), ..Default::default() };
    let cases: [(u64, usize); 6] = [
        (SO_DEBUG, 4), (SO_LINGER, 8), (SO_RCVTIMEO_OLD, 16),
        (SO_SNDTIMEO_NEW, 16), (SO_TXTIME, 8), (SO_TIMESTAMPING_OLD, 8),
    ];
    for (optname, want) in cases {
        let value = get::value(optname, 128, &state, &view).unwrap();
        assert_eq!(get::natural_len(&value), want, "optname {optname}");
        let mut out = [0u8; 16];
        assert_eq!(get::encode(&value, &mut out), want, "optname {optname}");
    }
}

#[test]
fn read_side_rejects_unknown_options_and_family_gated_ones() {
    let state = GenericSockOpts::default();
    let view = SockView { sock: tcp(), ..Default::default() };
    assert_eq!(get::value(0xdead, 4, &state, &view), Err(Errno::Enoprotoopt));
    assert_eq!(get::value(SO_PASSCRED, 4, &state, &view), Err(Errno::Eopnotsupp));
    assert_eq!(get::value(SO_PASSRIGHTS, 4, &state, &view), Err(Errno::Eopnotsupp));
    assert_eq!(get::value(SO_PEEK_OFF, 4, &state, &view), Err(Errno::Eopnotsupp));
    let udp_view = SockView { sock: udp(), ..Default::default() };
    assert_eq!(get::value(SO_TXREHASH, 4, &state, &udp_view), Err(Errno::Eopnotsupp));
}

#[test]
fn cookie_options_enforce_their_own_length_rules() {
    let state = GenericSockOpts::default();
    let view = SockView { sock: tcp(), netns_cookie: 7, socket_cookie: 9, ..Default::default() };
    assert_eq!(get::value(SO_COOKIE, 4, &state, &view), Err(Errno::Einval));
    assert_eq!(get::value(SO_COOKIE, 8, &state, &view), Ok(Value::U64(9)));
    assert_eq!(get::value(SO_COOKIE, 16, &state, &view), Ok(Value::U64(9)));
    // The namespace cookie demands an exact length, not merely enough room.
    assert_eq!(get::value(SO_NETNS_COOKIE, 16, &state, &view), Err(Errno::Einval));
    assert_eq!(get::value(SO_NETNS_COOKIE, 8, &state, &view), Ok(Value::U64(7)));
}

#[test]
fn pacing_rate_readback_width_follows_the_caller_buffer() {
    let state = GenericSockOpts::default();
    state.set_max_pacing_rate(1 << 40);
    let view = SockView { sock: tcp(), ..Default::default() };
    assert_eq!(get::value(SO_MAX_PACING_RATE, 8, &state, &view), Ok(Value::U64(1 << 40)));
    // A four-byte request gets the saturated 32-bit form.
    assert_eq!(get::value(SO_MAX_PACING_RATE, 4, &state, &view), Ok(Value::Int(-1)));
}

#[test]
fn sndlowat_is_fixed_and_unsettable() {
    let state = GenericSockOpts::default();
    let view = SockView { sock: tcp(), ..Default::default() };
    assert_eq!(get::value(SO_SNDLOWAT, 4, &state, &view), Ok(Value::Int(SNDLOWAT)));
    assert_eq!(set(SO_SNDLOWAT, 4096, tcp(), admin()), Err(Errno::Enoprotoopt));
}

#[test]
fn unix_sockets_start_with_scm_rights_enabled_and_a_one_byte_watermark() {
    let state = GenericSockOpts::default();
    let view = SockView { sock: unix(), ..Default::default() };
    assert_eq!(state.scalar(Scalar::RcvLowat), 1);
    assert_eq!(get::value(SO_RCVLOWAT, 4, &state, &view), Ok(Value::Int(1)));
    assert_eq!(get::value(SO_PASSRIGHTS, 4, &state, &view), Ok(Value::Int(1)));
    let off = admit(SO_PASSRIGHTS, Arg::Int(0), unix(), SetEnv { caps: none(), bound_device: false, ..Default::default() }).unwrap();
    assert_eq!(off, Action::Flag { bit: flag::SCM_RIGHTS_OFF, on: true });
    state.set_flag(flag::SCM_RIGHTS_OFF, true);
    assert_eq!(get::value(SO_PASSRIGHTS, 4, &state, &view), Ok(Value::Int(0)));
}

#[test]
fn socket_cookie_is_allocated_once() {
    let state = GenericSockOpts::default();
    let first = state.cookie(|| 41);
    let second = state.cookie(|| 99);
    assert_eq!(first, 41);
    assert_eq!(second, 41);
}

#[test]
fn prefer_busy_poll_enable_needs_net_admin_but_disable_does_not() {
    assert_eq!(set(SO_PREFER_BUSY_POLL, 1, tcp(), none()), Err(Errno::Eperm));
    assert_eq!(set(SO_PREFER_BUSY_POLL, 1, tcp(), raw()), Err(Errno::Eperm));
    assert_eq!(set(SO_PREFER_BUSY_POLL, 1, tcp(), admin()),
        Ok(Action::Flag { bit: flag::PREFER_BUSY_POLL, on: true }));
    assert_eq!(set(SO_PREFER_BUSY_POLL, 0, tcp(), none()),
        Ok(Action::Flag { bit: flag::PREFER_BUSY_POLL, on: false }));
    let state = GenericSockOpts::default();
    let view = SockView { sock: tcp(), ..Default::default() };
    assert_eq!(get::value(SO_PREFER_BUSY_POLL, 4, &state, &view), Ok(Value::Int(0)));
    state.set_flag(flag::PREFER_BUSY_POLL, true);
    assert_eq!(get::value(SO_PREFER_BUSY_POLL, 4, &state, &view), Ok(Value::Int(1)));
}

#[test]
fn busy_poll_budget_privilege_outranks_the_field_width_screen() {
    let budget = |caps, current, value| admit(SO_BUSY_POLL_BUDGET, Arg::Int(value), tcp(),
        SetEnv { caps, busy_poll_budget: current, ..Default::default() });
    // An unprivileged RAISE is EPERM even when the value is unrepresentable.
    assert_eq!(budget(none(), 8, BUSY_POLL_BUDGET_MAX + 1), Err(Errno::Eperm));
    assert_eq!(budget(none(), 8, 9), Err(Errno::Eperm));
    // Lowering, or staying put, needs no capability.
    assert_eq!(budget(none(), 8, 8), Ok(Action::Scalar { slot: Scalar::BusyPollBudget, value: 8 }));
    assert_eq!(budget(none(), 8, 0), Ok(Action::Scalar { slot: Scalar::BusyPollBudget, value: 0 }));
    // With the capability the width screen is what rejects an out-of-range value.
    assert_eq!(budget(admin(), 0, BUSY_POLL_BUDGET_MAX + 1), Err(Errno::Einval));
    assert_eq!(budget(admin(), 0, -1), Err(Errno::Einval));
    assert_eq!(budget(admin(), 0, BUSY_POLL_BUDGET_MAX),
        Ok(Action::Scalar { slot: Scalar::BusyPollBudget, value: BUSY_POLL_BUDGET_MAX }));
    // The budget has no read direction.
    let state = GenericSockOpts::default();
    let view = SockView { sock: tcp(), ..Default::default() };
    assert_eq!(get::value(SO_BUSY_POLL_BUDGET, 4, &state, &view), Err(Errno::Enoprotoopt));
}

#[test]
fn incoming_napi_id_aggregates_reserved_identifiers_to_zero() {
    let state = GenericSockOpts::default();
    let below = SockView { sock: tcp(), napi_id: MIN_NAPI_ID - 1, ..Default::default() };
    let valid = SockView { sock: tcp(), napi_id: MIN_NAPI_ID, ..Default::default() };
    assert_eq!(get::value(SO_INCOMING_NAPI_ID, 4, &state, &below), Ok(Value::Int(0)));
    assert_eq!(get::value(SO_INCOMING_NAPI_ID, 4, &state, &valid),
        Ok(Value::Int(MIN_NAPI_ID as i32)));
    // Read-only: the identifier is recorded by the receive path, never written.
    assert_eq!(set(SO_INCOMING_NAPI_ID, 9, tcp(), admin()), Err(Errno::Enoprotoopt));
}

#[test]
fn devmem_dontneed_is_stream_only_and_takes_whole_tokens() {
    assert_eq!(devmem_dontneed_tokens(udp(), DEVMEM_TOKEN_SIZE as u32), Err(Errno::Ebadf));
    assert_eq!(devmem_dontneed_tokens(unix(), DEVMEM_TOKEN_SIZE as u32), Err(Errno::Ebadf));
    // The socket-shape screen outranks the length screen.
    assert_eq!(devmem_dontneed_tokens(udp(), 5), Err(Errno::Ebadf));
    assert_eq!(devmem_dontneed_tokens(tcp(), 4), Err(Errno::Einval));
    assert_eq!(devmem_dontneed_tokens(tcp(),
        (DEVMEM_TOKEN_SIZE * (MAX_DONTNEED_TOKENS + 1)) as u32), Err(Errno::Einval));
    assert_eq!(devmem_dontneed_tokens(tcp(), 0), Ok(0));
    assert_eq!(devmem_dontneed_tokens(tcp(), (DEVMEM_TOKEN_SIZE * 3) as u32), Ok(3));
    assert_eq!(devmem_dontneed_tokens(tcp(),
        (DEVMEM_TOKEN_SIZE * MAX_DONTNEED_TOKENS) as u32), Ok(MAX_DONTNEED_TOKENS));
}

#[test]
fn buffer_writes_clamp_against_the_live_ceilings_not_a_compiled_constant() {
    let with = |wmem, rmem, optname, value| admit(optname, Arg::Int(value), tcp(),
        SetEnv { caps: admin(), ceilings: BufCeilings { wmem_max: wmem, rmem_max: rmem },
            ..Default::default() });
    // A lowered ceiling clamps the request before the doubling.
    assert_eq!(with(16_384, DEFAULT_RMEM_MAX, SO_SNDBUF, 1 << 20),
        Ok(Action::SndBuf(32_768)));
    assert_eq!(with(DEFAULT_WMEM_MAX, 16_384, SO_RCVBUF, 1 << 20),
        Ok(Action::RcvBuf(32_768)));
    // The forced variants ignore the ceiling entirely.
    assert_eq!(with(16_384, DEFAULT_RMEM_MAX, SO_SNDBUFFORCE, 1 << 20),
        Ok(Action::SndBuf(2 << 20)));
    assert_eq!(with(DEFAULT_WMEM_MAX, 16_384, SO_RCVBUFFORCE, 1 << 20),
        Ok(Action::RcvBuf(2 << 20)));
}

#[test]
fn options_with_their_own_argument_shape_never_reach_the_scalar_table() {
    for optname in [SO_ATTACH_REUSEPORT_CBPF, SO_ATTACH_REUSEPORT_EBPF, SO_DETACH_REUSEPORT_BPF] {
        assert_eq!(arg_class(optname), ArgClass::Reuseport);
        assert!(reads_int_argument(optname));
    }
    assert_eq!(arg_class(SO_DEVMEM_DONTNEED), ArgClass::Devmem);
    assert!(reads_int_argument(SO_DEVMEM_DONTNEED));
    let state = GenericSockOpts::default();
    let view = SockView { sock: tcp(), ..Default::default() };
    for optname in [SO_PEERSEC, SO_PEERGROUPS, SO_MEMINFO, SO_PEERNAME, SO_GET_FILTER] {
        assert_eq!(get::value(optname, 64, &state, &view), Err(Errno::Enoprotoopt));
    }
}

#[test]
fn so_inq_is_an_af_unix_stream_option_only() {
    // Every other socket shape reaches no implementation of it at all.
    assert_eq!(set(SO_INQ, 1, unix(), none()), Ok(Action::Scalar { slot: Scalar::Inq, value: 1 }));
    assert_eq!(set(SO_INQ, 0, unix(), none()), Ok(Action::Scalar { slot: Scalar::Inq, value: 0 }));
    assert_eq!(set(SO_INQ, 1, unix_dgram(), none()), Err(Errno::Enoprotoopt));
    assert_eq!(set(SO_INQ, 1, tcp(), admin()), Err(Errno::Enoprotoopt));
    assert_eq!(set(SO_INQ, 1, udp(), admin()), Err(Errno::Enoprotoopt));
    assert_eq!(set(SO_INQ, 1, packet(), admin()), Err(Errno::Enoprotoopt));
}

#[test]
fn so_inq_is_a_strict_boolean_and_the_family_screen_outranks_the_value_window() {
    assert_eq!(set(SO_INQ, 2, unix(), none()), Err(Errno::Einval));
    assert_eq!(set(SO_INQ, -1, unix(), none()), Err(Errno::Einval));
    // An out-of-window value on a socket that has no SO_INQ at all still
    // reports the missing option, not the bad value.
    assert_eq!(set(SO_INQ, 2, tcp(), none()), Err(Errno::Enoprotoopt));
}

#[test]
fn so_inq_screens_an_exact_int_where_every_other_option_screens_a_minimum() {
    assert!(exact_int_argument(SO_INQ));
    for optname in [SO_DEBUG, SO_RCVBUF, SO_LINGER, SO_TXTIME, SO_PASSCRED] {
        assert!(!exact_int_argument(optname), "optname {optname}");
    }
}

#[test]
fn so_inq_is_write_only_and_reads_back_as_a_missing_option() {
    // The option enables a control message; it is not itself readable, on any
    // family, including the one that accepts the write.
    let state = GenericSockOpts::default();
    for sock in [unix(), unix_dgram(), tcp()] {
        let view = SockView { sock, ..Default::default() };
        assert_eq!(get::value(SO_INQ, 4, &state, &view), Err(Errno::Enoprotoopt));
    }
}
