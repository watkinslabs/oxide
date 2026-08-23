//! Canonical bonding snapshots consumed by procfs and sysfs projections.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use net::addr::MacAddr;
use crate::master::BondMaster;

/// One slave's published bonding state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondSlaveView {
    pub name: String,
    pub state: crate::slave::SlaveState,
    pub permanent_mac: MacAddr,
    pub actor_port_state: u8,
    pub partner_port_state: u8,
    pub lacp: bool,
}

/// Snapshot of the master and every slave, from one owner lock acquisition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondView {
    pub name: String,
    pub params: crate::master::BondParams,
    pub active: Option<String>,
    pub active_aggregator: u16,
    pub up: bool,
    pub slaves: Vec<BondSlaveView>,
}

impl BondMaster {
    /// Snapshot the state exposed by bonding's procfs and slave sysfs owners.
    /// # C: O(slaves)
    pub fn view(&self) -> BondView {
        let g = self.inner.read();
        let active = g.curr_active.and_then(|i| g.slaves.get(i))
            .map(|s| String::from(s.dev.name()));
        let slaves = g.slaves.iter().map(|s| BondSlaveView {
            name: String::from(s.dev.name()), state: s.state,
            permanent_mac: s.perm_mac, actor_port_state: s.actor.state,
            partner_port_state: s.partner.state,
            lacp: g.params.mode == crate::uapi::BOND_MODE_8023AD,
        }).collect();
        BondView { name: self.name.clone(), params: g.params, active,
                   active_aggregator: g.active_agg, up: g.if_up, slaves }
    }

    /// Render the Linux bonding procfs report from the canonical snapshot.
    /// # C: O(slaves)
    pub fn proc_body(&self) -> Vec<u8> {
        let v = self.view();
        let mut s = String::new();
        let _ = writeln!(s, "Ethernet Channel Bonding Driver: v3.7.1");
        let _ = writeln!(s, "Bonding Mode: {}", crate::uapi::bond_mode_name(v.params.mode).unwrap_or("unknown"));
        let _ = writeln!(s, "Transmit Hash Policy: {}", crate::uapi::xmit_policy_name(v.params.xmit_policy).unwrap_or("unknown"));
        let _ = writeln!(s, "MII Status: {}", if v.up { "up" } else { "down" });
        let _ = writeln!(s, "MII Polling Interval (ms): {}", v.params.miimon);
        let _ = writeln!(s, "Up Delay (ms): {}", v.params.updelay);
        let _ = writeln!(s, "Down Delay (ms): {}", v.params.downdelay);
        if let Some(active) = v.active.as_deref() { let _ = writeln!(s, "Currently Active Slave: {active}"); }
        for slave in v.slaves {
            let _ = writeln!(s, "\nSlave Interface: {}", slave.name);
            let _ = writeln!(s, "MII Status: {}", match slave.state.link {
                crate::slave::LinkState::Up => "up", crate::slave::LinkState::Fail => "failed",
                crate::slave::LinkState::Back => "backup", crate::slave::LinkState::Down => "down",
            });
            let _ = writeln!(s, "Speed: {} Mbps", slave.state.speed_mbps);
            let _ = writeln!(s, "Duplex: {}", if slave.state.duplex == crate::uapi::DUPLEX_FULL { "full" } else { "half" });
            let _ = writeln!(s, "Link Failure Count: {}", slave.state.link_failure_count);
            let _ = writeln!(s, "Permanent HW addr: {}", mac_text(slave.permanent_mac));
            let _ = writeln!(s, "Slave queue ID: {}", slave.state.queue_id);
            if slave.lacp { let _ = writeln!(s, "Aggregator ID: {}", slave.state.agg_id); }
        }
        s.into_bytes()
    }
}

fn mac_text(mac: MacAddr) -> String {
    alloc::format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                   mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_master_report_is_linux_shaped_and_live() {
        let bond = BondMaster::new("bond0");
        let view = bond.view();
        assert_eq!(view.name, "bond0");
        assert!(view.slaves.is_empty());
        let body = String::from_utf8(bond.proc_body()).unwrap();
        assert!(body.contains("Ethernet Channel Bonding Driver:"));
        assert!(body.contains("Bonding Mode: balance-rr"));
        assert!(body.contains("MII Polling Interval (ms): 0"));
    }
}
