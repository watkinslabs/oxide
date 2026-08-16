// Per-port LACP machines.

use crate::flags::{
    AD_PORT_BEGIN, AD_PORT_LACP_ENABLED, AD_PORT_READY, AD_PORT_SELECTED, AD_PORT_STANDBY,
    LACP_STATE_LACP_ACTIVITY, LACP_STATE_LACP_TIMEOUT, LACP_STATE_SYNCHRONIZATION,
};
use crate::lacp::sm::{
    churn_state, mux_machine, periodic_machine, rx_machine, tx_machine, PortSm,
};
use crate::lacp::{ChurnState, MuxState, PeriodicState, RxState, TxState};

fn enabled_port() -> PortSm {
    PortSm { vars: AD_PORT_LACP_ENABLED, enabled: true, rx: RxState::PortDisabled,
             ..PortSm::default() }
}

#[test]
fn a_reinitialised_port_restarts_the_receive_machine() {
    let mut p = PortSm { vars: AD_PORT_BEGIN | AD_PORT_LACP_ENABLED, enabled: true,
                         rx: RxState::Current, ..PortSm::default() };
    assert_eq!(rx_machine(&mut p, false), RxState::Initialize);
}

#[test]
fn a_disabled_port_parks_the_receive_machine() {
    let mut p = PortSm { vars: AD_PORT_LACP_ENABLED, enabled: false, rx: RxState::Current,
                         ..PortSm::default() };
    assert_eq!(rx_machine(&mut p, false), RxState::PortDisabled);
}

#[test]
fn an_enabled_port_leaves_the_parked_state_by_whether_aggregation_is_on() {
    let mut on = enabled_port();
    assert_eq!(rx_machine(&mut on, false), RxState::Expired);

    let mut off = PortSm { vars: 0, enabled: true, rx: RxState::PortDisabled,
                           ..PortSm::default() };
    assert_eq!(rx_machine(&mut off, false), RxState::LacpDisabled);
}

#[test]
fn an_arriving_frame_refreshes_the_receive_machine_and_clears_its_timer() {
    let mut p = PortSm { vars: AD_PORT_LACP_ENABLED, enabled: true, rx: RxState::Expired,
                         rx_timer: 5, ..PortSm::default() };
    assert_eq!(rx_machine(&mut p, true), RxState::Current);
    assert_eq!(p.rx_timer, 0);
}

#[test]
fn a_silent_partner_walks_current_to_expired_to_defaulted() {
    let mut p = PortSm { vars: AD_PORT_LACP_ENABLED, enabled: true, rx: RxState::Current,
                         rx_timer: 2, ..PortSm::default() };
    assert_eq!(rx_machine(&mut p, false), RxState::Current);
    assert_eq!(rx_machine(&mut p, false), RxState::Expired);
    p.rx_timer = 1;
    assert_eq!(rx_machine(&mut p, false), RxState::Defaulted);
}

#[test]
fn the_periodic_machine_stops_when_neither_side_is_active() {
    let mut p = PortSm { vars: AD_PORT_LACP_ENABLED, enabled: true,
                         periodic: PeriodicState::FastPeriodic, periodic_timer: 3,
                         actor_state: 0, partner_state: 0, ..PortSm::default() };
    assert_eq!(periodic_machine(&mut p), PeriodicState::NoPeriodic);
    assert_eq!(p.periodic_timer, 0);
}

#[test]
fn a_stopped_periodic_machine_restarts_fast() {
    let mut p = PortSm { vars: AD_PORT_LACP_ENABLED, enabled: true,
                         periodic: PeriodicState::NoPeriodic, periodic_timer: 0,
                         actor_state: LACP_STATE_LACP_ACTIVITY, ..PortSm::default() };
    assert_eq!(periodic_machine(&mut p), PeriodicState::FastPeriodic);
}

#[test]
fn an_expiring_period_owes_a_transmission() {
    let mut p = PortSm { vars: AD_PORT_LACP_ENABLED, enabled: true,
                         periodic: PeriodicState::FastPeriodic, periodic_timer: 1,
                         actor_state: LACP_STATE_LACP_ACTIVITY,
                         partner_state: LACP_STATE_LACP_TIMEOUT, ..PortSm::default() };
    assert_eq!(periodic_machine(&mut p), PeriodicState::PeriodicTx);
    assert!(p.ntt);
}

#[test]
fn the_partner_timeout_bit_picks_the_period_after_a_transmission() {
    let base = PortSm { vars: AD_PORT_LACP_ENABLED, enabled: true,
                        periodic: PeriodicState::PeriodicTx, periodic_timer: 0,
                        actor_state: LACP_STATE_LACP_ACTIVITY, ..PortSm::default() };
    let mut fast = PortSm { partner_state: LACP_STATE_LACP_TIMEOUT, ..base };
    assert_eq!(periodic_machine(&mut fast), PeriodicState::FastPeriodic);
    let mut slow = PortSm { partner_state: 0, ..base };
    // The partner is still active, just not asking for the fast period.
    slow.partner_state = LACP_STATE_LACP_ACTIVITY;
    assert_eq!(periodic_machine(&mut slow), PeriodicState::SlowPeriodic);
}

#[test]
fn a_partner_that_starts_asking_for_the_fast_period_forces_a_transmission() {
    let mut p = PortSm { vars: AD_PORT_LACP_ENABLED, enabled: true,
                         periodic: PeriodicState::SlowPeriodic, periodic_timer: 20,
                         actor_state: LACP_STATE_LACP_ACTIVITY,
                         partner_state: LACP_STATE_LACP_TIMEOUT, ..PortSm::default() };
    assert_eq!(periodic_machine(&mut p), PeriodicState::PeriodicTx);
    assert_eq!(p.periodic_timer, 0);
    assert!(p.ntt);
}

#[test]
fn the_multiplexer_detaches_a_reinitialised_port() {
    let mut p = PortSm { vars: AD_PORT_BEGIN, mux: MuxState::CollectingDistributing,
                         ..PortSm::default() };
    assert_eq!(mux_machine(&mut p, true, true, false), MuxState::Detached);
}

#[test]
fn a_selected_port_waits_then_attaches_once_its_group_is_ready() {
    let mut p = PortSm { vars: AD_PORT_SELECTED, mux: MuxState::Detached, mux_timer: 2,
                         ..PortSm::default() };
    assert_eq!(mux_machine(&mut p, false, true, false), MuxState::Waiting);
    assert_eq!(mux_machine(&mut p, false, true, false), MuxState::Waiting);
    // The wait-while timer expires and the group reports ready.
    p.set(AD_PORT_READY);
    assert_eq!(mux_machine(&mut p, false, true, false), MuxState::Attached);
}

#[test]
fn an_attached_port_on_the_active_group_starts_collecting_and_distributing() {
    let mut p = PortSm { vars: AD_PORT_SELECTED, mux: MuxState::Attached,
                         partner_state: LACP_STATE_SYNCHRONIZATION, ..PortSm::default() };
    assert_eq!(mux_machine(&mut p, true, true, false), MuxState::CollectingDistributing);
}

#[test]
fn without_coupled_control_the_port_collects_before_it_distributes() {
    let mut p = PortSm { vars: AD_PORT_SELECTED, mux: MuxState::Attached,
                         partner_state: LACP_STATE_SYNCHRONIZATION, ..PortSm::default() };
    assert_eq!(mux_machine(&mut p, true, false, false), MuxState::Collecting);
    assert_eq!(mux_machine(&mut p, true, false, false), MuxState::Distributing);
}

#[test]
fn an_attached_port_waits_while_the_group_selection_timer_runs() {
    let mut p = PortSm { vars: AD_PORT_SELECTED, mux: MuxState::Attached,
                         partner_state: LACP_STATE_SYNCHRONIZATION, ..PortSm::default() };
    assert_eq!(mux_machine(&mut p, true, true, true), MuxState::Attached);
    assert_eq!(p.actor_state & LACP_STATE_SYNCHRONIZATION, LACP_STATE_SYNCHRONIZATION);
}

#[test]
fn a_deselected_or_standby_port_detaches_from_the_attached_state() {
    for vars in [0u16, AD_PORT_SELECTED | AD_PORT_STANDBY] {
        let mut p = PortSm { vars, mux: MuxState::Attached, ..PortSm::default() };
        assert_eq!(mux_machine(&mut p, true, true, false), MuxState::Detached);
    }
}

#[test]
fn a_distributing_port_falls_back_when_the_partner_loses_synchronisation() {
    let mut p = PortSm { vars: AD_PORT_SELECTED, mux: MuxState::CollectingDistributing,
                         partner_state: 0, ..PortSm::default() };
    assert_eq!(mux_machine(&mut p, true, true, false), MuxState::Attached);
}

#[test]
fn a_transmission_happens_only_when_owed_and_within_budget() {
    let mut p = PortSm { ntt: true, ..PortSm::default() };
    assert_eq!(tx_machine(&mut p, 3), TxState::Transmit);
    assert!(!p.ntt);
    assert_eq!(tx_machine(&mut p, 3), TxState::Dummy);
    p.ntt = true;
    assert_eq!(tx_machine(&mut p, 0), TxState::Dummy);
    assert!(p.ntt);
}

#[test]
fn churn_is_reported_only_after_the_detection_window_with_no_synchronisation() {
    assert_eq!(churn_state(true, true), ChurnState::NoChurn);
    assert_eq!(churn_state(false, false), ChurnState::Monitor);
    assert_eq!(churn_state(false, true), ChurnState::Churn);
}
