// SOL_SOCKET option coverage: identity.

use super::*;

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
fn rebinding_a_device_needs_cap_net_raw_only_when_one_is_already_bound() {
    assert_eq!(bind_device_allowed(none(), false), Ok(()));
    assert_eq!(bind_device_allowed(none(), true), Err(Errno::Eperm));
    assert_eq!(bind_device_allowed(raw(), true), Ok(()));
    assert_eq!(admit(SO_BINDTOIFINDEX, Arg::Int(2), tcp(), SetEnv { caps: none(), bound_device: true, ..Default::default() }), Err(Errno::Eperm));
}

#[test]
fn read_side_rejects_unknown_options_and_family_gated_ones() {
    let state = crate::sock_base::SockBase::default();
    let view = SockView { sock: tcp(), ..Default::default() };
    assert_eq!(get::value(0xdead, 4, &state, &view), Err(Errno::Enoprotoopt));
    assert_eq!(get::value(SO_PASSCRED, 4, &state, &view), Err(Errno::Eopnotsupp));
    assert_eq!(get::value(SO_PASSRIGHTS, 4, &state, &view), Err(Errno::Eopnotsupp));
    assert_eq!(get::value(SO_PEEK_OFF, 4, &state, &view), Err(Errno::Eopnotsupp));
    let udp_view = SockView { sock: udp(), ..Default::default() };
    assert_eq!(get::value(SO_TXREHASH, 4, &state, &udp_view), Err(Errno::Eopnotsupp));
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
fn so_inq_is_write_only_and_reads_back_as_a_missing_option() {
    // The option enables a control message; it is not itself readable, on any
    // family, including the one that accepts the write.
    let state = crate::sock_base::SockBase::default();
    for sock in [unix(), unix_dgram(), tcp()] {
        let view = SockView { sock, ..Default::default() };
        assert_eq!(get::value(SO_INQ, 4, &state, &view), Err(Errno::Enoprotoopt));
    }
}
