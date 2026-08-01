// SOL_SOCKET option coverage: core.

use super::*;

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
fn timeout_readback_reports_zero_for_unset_and_immediate() {
    assert_eq!(timeval_from_timeout_ns(0), (0, 0));
    assert_eq!(timeval_from_timeout_ns(IMMEDIATE_TIMEOUT_NS), (0, 0));
    assert_eq!(timeval_from_timeout_ns(2_500_000_000), (2, 500_000));
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
fn peek_off_needs_a_socket_that_implements_it() {
    assert_eq!(set(SO_PEEK_OFF, 4, tcp(), admin()), Err(Errno::Eopnotsupp));
    assert_eq!(set(SO_PEEK_OFF, 4, unix(), none()),
        Ok(Action::Scalar { slot: Scalar::PeekOff, value: 4 }));
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
fn sndlowat_is_fixed_and_unsettable() {
    let state = GenericSockOpts::default();
    let view = SockView { sock: tcp(), ..Default::default() };
    assert_eq!(get::value(SO_SNDLOWAT, 4, &state, &view), Ok(Value::Int(SNDLOWAT)));
    assert_eq!(set(SO_SNDLOWAT, 4096, tcp(), admin()), Err(Errno::Enoprotoopt));
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
