// Per-mode transmit slave selection. Pure over a slave slice: the caller owns
// the round-robin counter and the random source, so every decision here is
// reproducible from its inputs.

extern crate alloc;
use alloc::vec::Vec;

use crate::hash::{bond_xmit_hash, FlowKeys};
use crate::limits::PACKETS_PER_SLAVE_DEFAULT;
use crate::slave::{LinkState, SlaveState};
use crate::uapi::{
    BOND_MODE_8023AD, BOND_MODE_ACTIVEBACKUP, BOND_MODE_ALB, BOND_MODE_BROADCAST,
    BOND_MODE_ROUNDROBIN, BOND_MODE_TLB, BOND_MODE_XOR,
};

/// Which slaves one frame goes to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TxTarget {
    /// Nothing eligible; the frame is dropped.
    None,
    /// Exactly one slave index.
    One(usize),
    /// A copy per index, in slice order.
    All(Vec<usize>),
}

/// Round-robin slave-id source. `packets_per_slave` of zero draws from the
/// caller's random word; one advances every packet; larger values divide the
/// counter so each slave keeps that many consecutive packets.
/// # C: O(1)
pub fn rr_gen_slave_id(packets_per_slave: u32, counter: u32, random: u32) -> u32 {
    match packets_per_slave {
        0 => random,
        1 => counter,
        n => counter / n,
    }
}

/// Walk from `slave_id` to the end, then wrap over the earlier entries, and
/// return the first slave able to transmit.
/// # C: O(slaves)
pub fn slave_by_id(slaves: &[SlaveState], slave_id: usize) -> Option<usize> {
    let n = slaves.len();
    if n == 0 { return None; }
    for (i, s) in slaves.iter().enumerate().skip(slave_id.min(n)) {
        if s.can_tx() { return Some(i); }
    }
    for (i, s) in slaves.iter().enumerate().take(slave_id.min(n)) {
        if s.can_tx() { return Some(i); }
    }
    None
}

/// Round-robin selection. IGMP traffic is pinned so membership reports keep
/// leaving by one interface across a failover.
/// # C: O(slaves)
pub fn roundrobin_slave(slaves: &[SlaveState], counter: u32, packets_per_slave: u32,
                        is_igmp: bool, curr_active: Option<usize>, random: u32) -> Option<usize> {
    if is_igmp {
        if let Some(a) = curr_active { return Some(a); }
        return slave_by_id(slaves, 0);
    }
    if slaves.is_empty() { return None; }
    let id = rr_gen_slave_id(packets_per_slave, counter, random) as usize % slaves.len();
    slave_by_id(slaves, id)
}

/// Active-backup selection: the one currently active slave, never a hash.
/// # C: O(1)
pub fn activebackup_slave(curr_active: Option<usize>) -> Option<usize> { curr_active }

/// Hash-reduced selection over an already-filtered candidate array.
/// # C: O(1)
pub fn hash_slave(candidates: &[usize], policy: u8, flow: &FlowKeys) -> Option<usize> {
    if candidates.is_empty() { return None; }
    let hash = bond_xmit_hash(policy, flow);
    Some(candidates[(hash as usize) % candidates.len()])
}

/// Slaves eligible to carry hashed traffic.
/// # C: O(slaves)
pub fn usable_slaves(slaves: &[SlaveState]) -> Vec<usize> {
    slaves.iter().enumerate().filter(|(_, s)| s.can_tx()).map(|(i, _)| i).collect()
}

/// Slaves belonging to the aggregator the 802.3ad selection settled on.
/// # C: O(slaves)
pub fn aggregator_slaves(slaves: &[SlaveState], active_agg: u16) -> Vec<usize> {
    slaves.iter().enumerate()
        .filter(|(_, s)| s.agg_id == active_agg && s.can_tx())
        .map(|(i, _)| i)
        .collect()
}

/// Every slave a broadcast frame is replicated to: running with the link
/// settled up, skipping anything still failing or delayed.
/// # C: O(slaves)
pub fn broadcast_slaves(slaves: &[SlaveState]) -> Vec<usize> {
    slaves.iter().enumerate()
        .filter(|(_, s)| s.is_up() && s.link == LinkState::Up)
        .map(|(i, _)| i)
        .collect()
}

/// Inputs one transmit decision needs beyond the slave slice.
#[derive(Copy, Clone, Debug)]
pub struct TxContext {
    pub mode: u8,
    pub xmit_policy: u8,
    pub packets_per_slave: u32,
    pub rr_counter: u32,
    pub rr_random: u32,
    pub is_igmp: bool,
    pub curr_active: Option<usize>,
    /// Aggregator the 802.3ad selection made active.
    pub active_agg: u16,
}

impl Default for TxContext {
    fn default() -> Self {
        TxContext {
            mode: crate::uapi::BOND_MODE_ROUNDROBIN,
            xmit_policy: crate::uapi::BOND_XMIT_POLICY_LAYER2,
            packets_per_slave: PACKETS_PER_SLAVE_DEFAULT,
            rr_counter: 0, rr_random: 0, is_igmp: false,
            curr_active: None, active_agg: 0,
        }
    }
}

/// Mode-dispatched transmit target for one frame.
/// # C: O(slaves)
pub fn select_tx(slaves: &[SlaveState], ctx: &TxContext, flow: &FlowKeys) -> TxTarget {
    match ctx.mode {
        BOND_MODE_ROUNDROBIN => {
            match roundrobin_slave(slaves, ctx.rr_counter, ctx.packets_per_slave,
                                   ctx.is_igmp, ctx.curr_active, ctx.rr_random) {
                Some(i) => TxTarget::One(i),
                None => TxTarget::None,
            }
        }
        BOND_MODE_ACTIVEBACKUP => match activebackup_slave(ctx.curr_active) {
            Some(i) => TxTarget::One(i),
            None => TxTarget::None,
        },
        BOND_MODE_XOR => match hash_slave(&usable_slaves(slaves), ctx.xmit_policy, flow) {
            Some(i) => TxTarget::One(i),
            None => TxTarget::None,
        },
        BOND_MODE_8023AD => {
            let cand = aggregator_slaves(slaves, ctx.active_agg);
            match hash_slave(&cand, ctx.xmit_policy, flow) {
                Some(i) => TxTarget::One(i),
                None => TxTarget::None,
            }
        }
        BOND_MODE_BROADCAST => {
            let all = broadcast_slaves(slaves);
            if all.is_empty() { TxTarget::None } else { TxTarget::All(all) }
        }
        BOND_MODE_TLB | BOND_MODE_ALB => {
            // Load-balanced transmit is decided by the TLB table, which needs
            // the per-flow history the caller owns; without an assignment the
            // frame falls back to the active slave.
            match ctx.curr_active {
                Some(i) => TxTarget::One(i),
                None => TxTarget::None,
            }
        }
        _ => TxTarget::None,
    }
}
