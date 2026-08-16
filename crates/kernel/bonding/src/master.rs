// The bond master device. It is an ordinary interface as far as the registry
// is concerned: it owns a slave list, the runtime parameters, and the
// transmit path that fans a frame out to the slaves the mode picks.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use net::addr::MacAddr;
use net::netdev::{NamespaceDropAction, NetDev, NetError, NetResult};
use net::pkt::Pkt;
use sync::{LockClass, RwLock};

/// Lock class for the master's slave list and parameter block. Ranked
/// directly above the interface-configuration lock: a configuration change
/// takes that lock first and then reaches into the master.
pub struct BondLockClass;
impl LockClass for BondLockClass {
    fn rank() -> u16 { BOND_LOCK_RANK }
    fn name() -> &'static str { "Bond" }
}
const BOND_LOCK_RANK: u16 = 126;

type BondLock<T> = RwLock<T, BondLockClass>;

use crate::hash::{dissect, is_igmp};
use crate::limits::{BOND_MAX_SLAVES, PACKETS_PER_SLAVE_DEFAULT};
use crate::mode::{select_tx, TxContext, TxTarget};
use crate::slave::{LinkState, SlaveRole, SlaveState};
use crate::uapi::{
    BOND_FOM_ACTIVE, BOND_FOM_FOLLOW, BOND_FOM_NONE, BOND_MODE_8023AD, BOND_MODE_ALB,
    BOND_MODE_ROUNDROBIN, BOND_MODE_TLB, BOND_PRI_RESELECT_ALWAYS,
    BOND_XMIT_POLICY_LAYER2, DUPLEX_FULL,
};

/// Default master MTU before any slave joins.
const BOND_DEFAULT_MTU: u32 = 1500;

/// Runtime parameters a master carries.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BondParams {
    pub mode: u8,
    pub xmit_policy: u8,
    pub packets_per_slave: u32,
    pub miimon: u32,
    pub updelay: u32,
    pub downdelay: u32,
    pub arp_interval: u32,
    pub arp_validate: u32,
    pub arp_all_targets: u32,
    pub missed_max: u32,
    pub primary_reselect: u32,
    pub fail_over_mac: u32,
    pub ad_select: u32,
    pub lacp_rate: u32,
    pub lacp_active: bool,
    pub lacp_strict: bool,
    pub min_links: u32,
    pub num_peer_notif: u32,
    pub peer_notif_delay: u32,
    pub all_slaves_active: bool,
    pub resend_igmp: u32,
    pub lp_interval: u32,
    pub tlb_dynamic_lb: bool,
    pub use_carrier: bool,
    pub coupled_control: bool,
    pub broadcast_neighbor: bool,
    pub ad_actor_sys_prio: u32,
    pub ad_user_port_key: u32,
    pub ad_actor_system: MacAddr,
}

impl Default for BondParams {
    fn default() -> Self {
        use crate::limits::{
            AD_ACTOR_SYS_PRIO_DEFAULT, BOND_MISSED_MAX_DEFAULT, BOND_NUM_PEER_NOTIF_DEFAULT,
            BOND_RESEND_IGMP_DEFAULT,
        };
        BondParams {
            mode: BOND_MODE_ROUNDROBIN,
            xmit_policy: BOND_XMIT_POLICY_LAYER2,
            packets_per_slave: PACKETS_PER_SLAVE_DEFAULT,
            miimon: 0, updelay: 0, downdelay: 0, arp_interval: 0,
            arp_validate: 0, arp_all_targets: 0,
            missed_max: BOND_MISSED_MAX_DEFAULT,
            primary_reselect: BOND_PRI_RESELECT_ALWAYS,
            fail_over_mac: BOND_FOM_NONE,
            ad_select: 0, lacp_rate: 0, lacp_active: true, lacp_strict: true,
            min_links: 0,
            num_peer_notif: BOND_NUM_PEER_NOTIF_DEFAULT,
            peer_notif_delay: 0,
            all_slaves_active: false,
            resend_igmp: BOND_RESEND_IGMP_DEFAULT,
            lp_interval: 1, tlb_dynamic_lb: true, use_carrier: true,
            coupled_control: true, broadcast_neighbor: false,
            ad_actor_sys_prio: AD_ACTOR_SYS_PRIO_DEFAULT,
            ad_user_port_key: 0,
            ad_actor_system: MacAddr::ZERO,
        }
    }
}

/// One enslaved port: the device plus the state the decision layer reads and
/// the identity the master must restore on release.
pub struct BondSlave {
    pub dev: Arc<dyn NetDev>,
    pub state: SlaveState,
    /// The port's own address, recorded before the master overwrote it.
    pub perm_mac: MacAddr,
    /// The port's own MTU, recorded before the master imposed its own.
    pub perm_mtu: u32,
}

struct MasterInner {
    slaves: Vec<BondSlave>,
    params: BondParams,
    mac: MacAddr,
    mtu: u32,
    curr_active: Option<usize>,
    primary: Option<String>,
    active_agg: u16,
    /// The master itself is administratively up.
    if_up: bool,
}

/// A bonding master interface.
pub struct BondMaster {
    name: String,
    inner: BondLock<MasterInner>,
    rr_counter: AtomicU32,
}

impl BondMaster {
    /// # C: O(1)
    pub fn new(name: &str) -> BondMaster {
        BondMaster {
            name: name.to_string(),
            inner: BondLock::new(MasterInner {
                slaves: Vec::new(), params: BondParams::default(),
                mac: MacAddr::ZERO, mtu: BOND_DEFAULT_MTU,
                curr_active: None, primary: None, active_agg: 0, if_up: false,
            }),
            rr_counter: AtomicU32::new(0),
        }
    }

    /// # C: O(1)
    pub fn params(&self) -> BondParams { self.inner.read().params }

    /// Replace the parameter block wholesale after the option layer validated
    /// the write.
    /// # C: O(1)
    pub fn set_params(&self, params: BondParams) { self.inner.write().params = params; }

    /// # C: O(1)
    pub fn slave_count(&self) -> usize { self.inner.read().slaves.len() }

    /// # C: O(1)
    pub fn is_up(&self) -> bool { self.inner.read().if_up }

    /// # C: O(1)
    pub fn set_up(&self, up: bool) { self.inner.write().if_up = up; }

    /// State view every dependency check needs.
    /// # C: O(1)
    pub fn state_view(&self) -> crate::options::BondStateView {
        let g = self.inner.read();
        crate::options::BondStateView {
            mode: g.params.mode, has_slaves: !g.slaves.is_empty(), if_up: g.if_up,
        }
    }

    /// Snapshot of the slave states for the pure decision modules.
    /// Names of every slave, for the teardown that must hand each its own
    /// identity back before the master goes. # C: O(slaves)
    pub fn slave_names(&self) -> Vec<alloc::string::String> {
        self.inner.read().slaves.iter()
            .map(|s| alloc::string::String::from(s.dev.name())).collect()
    }

    /// # C: O(slaves)
    pub fn slave_states(&self) -> Vec<SlaveState> {
        self.inner.read().slaves.iter().map(|s| s.state).collect()
    }

    /// # C: O(1)
    pub fn curr_active(&self) -> Option<usize> { self.inner.read().curr_active }

    /// Install the active slave and, when the address policy follows the
    /// active port, move the master's address with it.
    /// # C: O(1)
    pub fn set_curr_active(&self, idx: Option<usize>) {
        let mut g = self.inner.write();
        g.curr_active = idx;
        if g.params.fail_over_mac == BOND_FOM_ACTIVE {
            g.mac = match idx { Some(i) => g.slaves[i].perm_mac, None => MacAddr::ZERO };
        }
    }

    /// # C: O(1)
    pub fn set_active_aggregator(&self, agg: u16) { self.inner.write().active_agg = agg; }

    /// Update one port's monitored state.
    /// # C: O(1)
    pub fn update_slave(&self, idx: usize, state: SlaveState) -> NetResult<()> {
        let mut g = self.inner.write();
        let s = g.slaves.get_mut(idx).ok_or(NetError::Enodev)?;
        s.state = state;
        Ok(())
    }

    /// Attach a port. The first port sets the master's address when the
    /// master has none; ports otherwise take the master's address unless the
    /// address policy leaves them alone, and every port takes the master's
    /// MTU.
    /// # C: O(slaves)
    pub fn enslave(&self, dev: Arc<dyn NetDev>) -> NetResult<usize> {
        let mut g = self.inner.write();
        if g.slaves.len() >= BOND_MAX_SLAVES { return Err(NetError::Enospc); }
        // Enslaving a bond to itself is refused outright, not merely rejected
        // as a malformed request.
        if dev.name() == self.name { return Err(NetError::Eperm); }
        if g.slaves.iter().any(|s| s.dev.name() == dev.name()) { return Err(NetError::Ebusy); }

        let perm_mac = dev.mac();
        let perm_mtu = dev.mtu();
        let first = g.slaves.is_empty();

        if first && g.mac == MacAddr::ZERO { g.mac = perm_mac; }
        if first { g.mtu = perm_mtu; } else if perm_mtu != g.mtu { dev.set_mtu(g.mtu)?; }

        // Only the "none" policy rewrites every port's address to the
        // master's; "active" keeps the master on the active port's address
        // and "follow" only moves an address at failover time.
        if g.params.fail_over_mac == BOND_FOM_NONE && perm_mac != g.mac {
            dev.set_mac(g.mac)?;
        }

        let role = if g.params.mode == crate::uapi::BOND_MODE_ACTIVEBACKUP && !first {
            SlaveRole::Backup
        } else {
            SlaveRole::Active
        };
        let state = SlaveState {
            ifindex: 0, link: LinkState::Down, carrier: false, delay: 0, role,
            speed_mbps: dev.link_speed_mbps().unwrap_or(0), duplex: DUPLEX_FULL,
            prio: 0, queue_id: 0, agg_id: 0, tlb_load: 0, link_failure_count: 0,
        };
        g.slaves.push(BondSlave { dev, state, perm_mac, perm_mtu });
        let idx = g.slaves.len() - 1;
        if g.curr_active.is_none() { g.curr_active = Some(idx); }
        Ok(idx)
    }

    /// Detach a port, restoring the address and MTU it joined with.
    /// # C: O(slaves)
    pub fn release(&self, name: &str) -> NetResult<()> {
        let mut g = self.inner.write();
        let idx = g.slaves.iter().position(|s| s.dev.name() == name)
            .ok_or(NetError::Enodev)?;
        let s = g.slaves.remove(idx);
        let _ = s.dev.set_mac(s.perm_mac);
        let _ = s.dev.set_mtu(s.perm_mtu);
        g.curr_active = match g.curr_active {
            Some(c) if c == idx => if g.slaves.is_empty() { None } else { Some(0) },
            Some(c) if c > idx => Some(c - 1),
            other => other,
        };
        if g.slaves.is_empty() && g.params.fail_over_mac != BOND_FOM_FOLLOW {
            // The master keeps its address across an empty period so a
            // re-enslave does not renumber the interface.
        }
        Ok(())
    }

    /// Transmit context for one frame.
    /// # C: O(1)
    fn tx_context(&self, g: &MasterInner, frame: &[u8]) -> TxContext {
        TxContext {
            mode: g.params.mode,
            xmit_policy: g.params.xmit_policy,
            packets_per_slave: g.params.packets_per_slave,
            rr_counter: self.rr_counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1),
            rr_random: 0,
            is_igmp: is_igmp(frame),
            curr_active: g.curr_active,
            active_agg: g.active_agg,
        }
    }

    /// Slaves one frame goes to, without transmitting it.
    /// # C: O(slaves)
    pub fn tx_target(&self, frame: &[u8]) -> TxTarget {
        let g = self.inner.read();
        let states: Vec<SlaveState> = g.slaves.iter().map(|s| s.state).collect();
        let ctx = self.tx_context(&g, frame);
        select_tx(&states, &ctx, &dissect(frame))
    }

    /// Whether the mode balances transmit load through the TLB table rather
    /// than a hash or the active port alone.
    /// # C: O(1)
    pub fn uses_tlb(&self) -> bool {
        let m = self.inner.read().params.mode;
        m == BOND_MODE_TLB || m == BOND_MODE_ALB
    }

    /// Whether the mode negotiates aggregation with the link partner.
    /// # C: O(1)
    pub fn uses_lacp(&self) -> bool { self.inner.read().params.mode == BOND_MODE_8023AD }

    /// Name of the configured primary port, when one is set.
    /// # C: O(1)
    pub fn primary(&self) -> Option<String> { self.inner.read().primary.clone() }

    /// # C: O(1)
    pub fn set_primary(&self, name: Option<&str>) {
        self.inner.write().primary = name.map(|n| n.to_string());
    }
}

impl NetDev for BondMaster {
    fn name(&self) -> &str { &self.name }
    fn mac(&self) -> MacAddr { self.inner.read().mac }
    fn mtu(&self) -> u32 { self.inner.read().mtu }

    /// The master's MTU propagates to every port, so a change that a port
    /// refuses fails the whole change rather than leaving the bond mixed.
    /// # C: O(slaves)
    fn set_mtu(&self, mtu: u32) -> NetResult<()> {
        let mut g = self.inner.write();
        for s in g.slaves.iter() { s.dev.set_mtu(mtu)?; }
        g.mtu = mtu;
        Ok(())
    }

    /// # C: O(slaves)
    fn set_mac(&self, mac: MacAddr) -> NetResult<()> {
        let mut g = self.inner.write();
        if g.params.fail_over_mac == BOND_FOM_NONE {
            for s in g.slaves.iter() { s.dev.set_mac(mac)?; }
        }
        g.mac = mac;
        Ok(())
    }

    fn link_speed_mbps(&self) -> Option<u32> {
        let g = self.inner.read();
        let sum: u32 = g.slaves.iter().filter(|s| s.state.can_tx())
            .map(|s| s.state.speed_mbps).sum();
        if sum == 0 { None } else { Some(sum) }
    }

    fn xmit(&self, pkt: Pkt) -> NetResult<()> {
        let g = self.inner.read();
        let states: Vec<SlaveState> = g.slaves.iter().map(|s| s.state).collect();
        let ctx = self.tx_context(&g, pkt.data());
        let flow = dissect(pkt.data());
        match select_tx(&states, &ctx, &flow) {
            TxTarget::None => Err(NetError::Enetdown),
            TxTarget::One(i) => g.slaves[i].dev.xmit(pkt),
            TxTarget::All(list) => {
                let (last, rest) = list.split_last().ok_or(NetError::Enetdown)?;
                for i in rest { g.slaves[*i].dev.xmit_raw(pkt.data())?; }
                g.slaves[*last].dev.xmit(pkt)
            }
        }
    }

    fn retire_namespace(&self) {
        for s in self.inner.read().slaves.iter() { s.dev.retire_namespace(); }
    }

    fn namespace_drop_action(&self) -> NamespaceDropAction { NamespaceDropAction::Destroy }
}
