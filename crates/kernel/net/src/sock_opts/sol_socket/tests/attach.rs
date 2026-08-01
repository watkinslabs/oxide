// SOL_SOCKET option coverage: attach.

use super::*;

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
