//! Canonical Linux legacy bridge administrative timing configuration.

use super::{NetStack, NetResult};
use crate::{NetError, NetIfaceId};
use super::bridge::BridgeTable;

const MIN_HELLO_TIME_TICKS: u64 = 100;
const MAX_HELLO_TIME_TICKS: u64 = 1_000;
const MIN_MAX_AGE_TICKS: u64 = 600;
const MAX_MAX_AGE_TICKS: u64 = 4_000;

/// Legacy `BRCTL_*` bridge timing field selected by the socket-ioctl shim.
pub enum BridgeTiming { ForwardDelay, HelloTime, MaxAge }

impl BridgeTable {
    /// Change one administrative bridge timer in Linux's userspace clock units. # C: O(1)
    pub(crate) fn set_timing(&self, bridge: NetIfaceId, net_ns: u64, field: BridgeTiming,
                             ticks: u64) -> NetResult<()>
    {
        match field {
            BridgeTiming::HelloTime if !(MIN_HELLO_TIME_TICKS..=MAX_HELLO_TIME_TICKS).contains(&ticks) => return Err(NetError::Erange),
            BridgeTiming::MaxAge if !(MIN_MAX_AGE_TICKS..=MAX_MAX_AGE_TICKS).contains(&ticks) => return Err(NetError::Erange),
            BridgeTiming::ForwardDelay | BridgeTiming::HelloTime | BridgeTiming::MaxAge => {}
        }
        let mut state = self.state.lock();
        let row = state.get_mut(&bridge).ok_or(NetError::Enodev)?;
        if row.net_ns != net_ns || row.deleting { return Err(NetError::Enodev); }
        match field {
            BridgeTiming::ForwardDelay => row.forward_delay = ticks,
            BridgeTiming::HelloTime => row.hello_time = ticks,
            BridgeTiming::MaxAge => row.max_age = ticks,
        }
        Ok(())
    }

    /// Change canonical bridge STP state only when its state machine owns the transition. # C: O(1)
    pub(crate) fn disable_stp(&self, bridge: NetIfaceId, net_ns: u64) -> NetResult<()> {
        self.stp_disable(bridge, net_ns)
    }

    /// Enable IEEE 802.1D through its canonical root/port/timer owner. # C: O(N ports)
    pub(crate) fn enable_stp(&self, bridge: NetIfaceId, net_ns: u64) -> NetResult<()> {
        self.stp_enable(bridge, net_ns)
    }
}

impl NetStack {
    /// Change one legacy bridge timing configuration field. # C: O(1)
    pub fn bridge_set_timing(&self, net_ns: u64, bridge: NetIfaceId, field: BridgeTiming,
                             ticks: u64) -> NetResult<()>
    {
        self.bridges.set_timing(bridge, net_ns, field, ticks)
    }

    /// Disable bridge STP through its canonical state owner. # C: O(1)
    pub fn bridge_disable_stp(&self, net_ns: u64, bridge: NetIfaceId) -> NetResult<()> {
        self.bridges.disable_stp(bridge, net_ns)
    }

    /// Enable bridge STP and transmit the initial Configuration BPDUs. # C: O(N ports + frame)
    pub fn bridge_enable_stp(&self, net_ns: u64, bridge: NetIfaceId) -> NetResult<()> {
        self.bridges.enable_stp(bridge, net_ns)?;
        self.bridge_stp_tick(super::monotonic_ns_safe());
        Ok(())
    }
}
