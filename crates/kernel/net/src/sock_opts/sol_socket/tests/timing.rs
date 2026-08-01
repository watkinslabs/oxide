// SOL_SOCKET option coverage: timing.

use super::*;

#[test]
fn every_option_but_bindtodevice_reads_a_leading_int() {
    assert!(!reads_int_argument(SO_BINDTODEVICE));
    for optname in [SO_DEBUG, SO_LINGER, SO_RCVTIMEO_OLD, SO_TXTIME, SO_MAX_PACING_RATE, 0xdead] {
        assert!(reads_int_argument(optname), "optname {optname}");
    }
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
fn pacing_rate_uses_the_wide_form_only_when_the_caller_supplies_one() {
    assert_eq!(arg_class(SO_MAX_PACING_RATE), ArgClass::PacingRate);
    assert_eq!(admit(SO_MAX_PACING_RATE, Arg::PacingRate(1 << 40), tcp(), SetEnv { caps: none(), bound_device: false, ..Default::default() }),
        Ok(Action::PacingRate(1 << 40)));
    assert_eq!(set(SO_MAX_PACING_RATE, 1000, tcp(), none()), Ok(Action::PacingRate(1000)));
    // The all-ones 32-bit request means "unlimited", not four billion.
    assert_eq!(set(SO_MAX_PACING_RATE, -1, tcp(), none()), Ok(Action::PacingRate(u64::MAX)));
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
fn pacing_rate_readback_width_follows_the_caller_buffer() {
    let state = GenericSockOpts::default();
    state.set_max_pacing_rate(1 << 40);
    let view = SockView { sock: tcp(), ..Default::default() };
    assert_eq!(get::value(SO_MAX_PACING_RATE, 8, &state, &view), Ok(Value::U64(1 << 40)));
    // A four-byte request gets the saturated 32-bit form.
    assert_eq!(get::value(SO_MAX_PACING_RATE, 4, &state, &view), Ok(Value::Int(-1)));
}
