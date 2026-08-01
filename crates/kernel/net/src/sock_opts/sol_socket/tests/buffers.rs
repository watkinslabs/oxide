// SOL_SOCKET option coverage: buffers.

use super::*;

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
fn so_inq_screens_an_exact_int_where_every_other_option_screens_a_minimum() {
    assert!(exact_int_argument(SO_INQ));
    for optname in [SO_DEBUG, SO_RCVBUF, SO_LINGER, SO_TXTIME, SO_PASSCRED] {
        assert!(!exact_int_argument(optname), "optname {optname}");
    }
}
