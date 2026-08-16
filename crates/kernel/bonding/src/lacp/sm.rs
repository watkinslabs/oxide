// Per-port LACP state machines: receive, periodic, multiplexer, transmit, and
// the churn detector. Each transition is a pure function of the port's
// variables plus whether an LACPDU arrived on this tick.

use crate::flags::{
    AD_PORT_BEGIN, AD_PORT_CHURNED, AD_PORT_LACP_ENABLED, AD_PORT_READY, AD_PORT_READY_N,
    AD_PORT_SELECTED, AD_PORT_STANDBY, LACP_STATE_LACP_ACTIVITY, LACP_STATE_LACP_TIMEOUT,
    LACP_STATE_SYNCHRONIZATION,
};

/// Receive machine states.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RxState { Dummy = 0, Initialize, PortDisabled, LacpDisabled, Expired, Defaulted, Current }

/// Periodic transmission machine states.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PeriodicState { Dummy = 0, NoPeriodic, FastPeriodic, SlowPeriodic, PeriodicTx }

/// Multiplexer machine states.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MuxState {
    Dummy = 0, Detached, Waiting, Attached, Collecting, Distributing, CollectingDistributing,
}

/// Transmit machine states.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TxState { Dummy = 0, Transmit }

/// Churn detector states.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ChurnState { Monitor = 0, Churn, NoChurn }

/// Port variables the machines read and write.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PortSm {
    pub rx: RxState,
    pub periodic: PeriodicState,
    pub mux: MuxState,
    pub tx: TxState,
    /// `AD_PORT_*` flag set.
    pub vars: u16,
    /// Link is usable for aggregation.
    pub enabled: bool,
    /// Ticks remaining before the receive timer expires.
    pub rx_timer: u16,
    /// Ticks remaining before the periodic timer expires.
    pub periodic_timer: u16,
    /// Ticks remaining on the multiplexer wait-while timer.
    pub mux_timer: u16,
    /// Actor's own `LACP_STATE_*` octet.
    pub actor_state: u8,
    /// Partner's last-known `LACP_STATE_*` octet.
    pub partner_state: u8,
    /// A transmission is owed.
    pub ntt: bool,
}

impl Default for PortSm {
    fn default() -> Self {
        PortSm {
            rx: RxState::Initialize, periodic: PeriodicState::NoPeriodic,
            mux: MuxState::Detached, tx: TxState::Dummy,
            vars: AD_PORT_BEGIN | AD_PORT_LACP_ENABLED, enabled: false,
            rx_timer: 0, periodic_timer: 0, mux_timer: 0,
            actor_state: 0, partner_state: 0, ntt: false,
        }
    }
}

impl PortSm {
    /// # C: O(1)
    pub fn has(&self, flag: u16) -> bool { (self.vars & flag) != 0 }
    /// # C: O(1)
    pub fn set(&mut self, flag: u16) { self.vars |= flag; }
    /// # C: O(1)
    pub fn clear(&mut self, flag: u16) { self.vars &= !flag; }
}

/// One receive-machine tick. A reinitialised port restarts; a disabled port
/// parks; an arriving frame refreshes the current state; otherwise the
/// receive timer walks current → expired → defaulted.
/// # C: O(1)
pub fn rx_machine(port: &mut PortSm, lacpdu_arrived: bool) -> RxState {
    if port.has(AD_PORT_BEGIN) {
        port.rx = RxState::Initialize;
        port.set(AD_PORT_CHURNED);
        return port.rx;
    }
    if !port.enabled {
        port.rx = RxState::PortDisabled;
        return port.rx;
    }
    let refreshable = matches!(port.rx, RxState::Expired | RxState::Defaulted | RxState::Current);
    if lacpdu_arrived && refreshable {
        if port.rx != RxState::Current { port.set(AD_PORT_CHURNED); }
        port.rx_timer = 0;
        port.rx = RxState::Current;
        return port.rx;
    }
    if port.rx_timer > 0 {
        port.rx_timer -= 1;
        if port.rx_timer == 0 {
            port.rx = match port.rx {
                RxState::Expired => RxState::Defaulted,
                RxState::Current => RxState::Expired,
                other => other,
            };
        }
        return port.rx;
    }
    if port.rx == RxState::PortDisabled && port.enabled {
        port.rx = if port.has(AD_PORT_LACP_ENABLED) { RxState::Expired } else { RxState::LacpDisabled };
    }
    port.rx
}

/// One periodic-machine tick. The partner's timeout bit picks the fast or the
/// slow period; expiry of the period owes a transmission.
/// # C: O(1)
pub fn periodic_machine(port: &mut PortSm) -> PeriodicState {
    let last = port.periodic;
    let neither_active = (port.actor_state & LACP_STATE_LACP_ACTIVITY) == 0
        && (port.partner_state & LACP_STATE_LACP_ACTIVITY) == 0;
    if port.has(AD_PORT_BEGIN) || !port.has(AD_PORT_LACP_ENABLED) || !port.enabled
        || neither_active
    {
        port.periodic = PeriodicState::NoPeriodic;
    } else if port.periodic_timer > 0 {
        port.periodic_timer -= 1;
        if port.periodic_timer == 0 {
            port.periodic = PeriodicState::PeriodicTx;
        } else {
            let fast_partner = (port.partner_state & LACP_STATE_LACP_TIMEOUT) != 0;
            match port.periodic {
                PeriodicState::FastPeriodic if !fast_partner =>
                    port.periodic = PeriodicState::SlowPeriodic,
                PeriodicState::SlowPeriodic if fast_partner => {
                    port.periodic_timer = 0;
                    port.periodic = PeriodicState::PeriodicTx;
                }
                _ => {}
            }
        }
    } else {
        let fast_partner = (port.partner_state & LACP_STATE_LACP_TIMEOUT) != 0;
        match port.periodic {
            PeriodicState::NoPeriodic => port.periodic = PeriodicState::FastPeriodic,
            PeriodicState::PeriodicTx => {
                port.periodic = if fast_partner {
                    PeriodicState::FastPeriodic
                } else {
                    PeriodicState::SlowPeriodic
                };
            }
            _ => {}
        }
    }
    if port.periodic != last && port.periodic == PeriodicState::PeriodicTx { port.ntt = true; }
    if port.periodic != last && port.periodic == PeriodicState::NoPeriodic { port.periodic_timer = 0; }
    port.periodic
}

/// One multiplexer tick. `agg_active` reports whether the port's aggregator is
/// the selected one; `coupled_control` fuses collecting and distributing into
/// a single step.
/// # C: O(1)
pub fn mux_machine(port: &mut PortSm, agg_active: bool, coupled_control: bool,
                   agg_select_timer_running: bool) -> MuxState {
    if port.has(AD_PORT_BEGIN) {
        port.mux = MuxState::Detached;
        return port.mux;
    }
    match port.mux {
        MuxState::Detached => {
            if port.has(AD_PORT_SELECTED) || port.has(AD_PORT_STANDBY) {
                port.mux = MuxState::Waiting;
            }
        }
        MuxState::Waiting => {
            if !port.has(AD_PORT_SELECTED) {
                port.clear(AD_PORT_READY_N);
                port.mux = MuxState::Detached;
                return port.mux;
            }
            if port.mux_timer > 0 {
                port.mux_timer -= 1;
                if port.mux_timer == 0 { port.set(AD_PORT_READY_N); }
            }
            if port.has(AD_PORT_READY) && port.mux_timer == 0 { port.mux = MuxState::Attached; }
        }
        MuxState::Attached => {
            let partner_sync = (port.partner_state & LACP_STATE_SYNCHRONIZATION) != 0;
            if port.has(AD_PORT_SELECTED) && partner_sync && !agg_select_timer_running {
                if agg_active {
                    port.mux = if coupled_control {
                        MuxState::CollectingDistributing
                    } else {
                        MuxState::Collecting
                    };
                }
            } else if !port.has(AD_PORT_SELECTED) || port.has(AD_PORT_STANDBY) {
                port.clear(AD_PORT_READY_N);
                port.mux = MuxState::Detached;
            } else if agg_active {
                port.actor_state |= LACP_STATE_SYNCHRONIZATION;
            }
        }
        MuxState::Collecting => {
            if !port.has(AD_PORT_SELECTED) || port.has(AD_PORT_STANDBY) {
                port.mux = MuxState::Attached;
            } else if (port.partner_state & LACP_STATE_SYNCHRONIZATION) != 0 {
                port.mux = MuxState::Distributing;
            }
        }
        MuxState::Distributing | MuxState::CollectingDistributing => {
            if !port.has(AD_PORT_SELECTED) || port.has(AD_PORT_STANDBY)
                || (port.partner_state & LACP_STATE_SYNCHRONIZATION) == 0
            {
                port.mux = MuxState::Attached;
            }
        }
        MuxState::Dummy => {}
    }
    port.mux
}

/// One transmit tick: a port emits only when a transmission is owed and its
/// per-second budget has room.
/// # C: O(1)
pub fn tx_machine(port: &mut PortSm, tx_budget_left: u32) -> TxState {
    if port.ntt && tx_budget_left > 0 {
        port.ntt = false;
        port.tx = TxState::Transmit;
    } else {
        port.tx = TxState::Dummy;
    }
    port.tx
}

/// Churn verdict for one side: an unsynchronised port that stays that way for
/// the detection window is churning.
/// # C: O(1)
pub fn churn_state(synchronised: bool, timer_expired: bool) -> ChurnState {
    if synchronised { return ChurnState::NoChurn; }
    if timer_expired { return ChurnState::Churn; }
    ChurnState::Monitor
}
