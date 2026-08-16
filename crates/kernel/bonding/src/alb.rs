// Receive load balancing. Each client IP is pinned to a slave in the client
// table, and the address-resolution replies the bond emits carry that slave's
// address so inbound traffic spreads across the ports.

use crate::limits::{RLB_HASH_TABLE_SIZE, TLB_NULL_INDEX};
use crate::slave::SlaveState;
use crate::tlb::simple_hash;

/// One receive-balancing client entry.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RlbClient {
    /// Client address, in network byte order.
    pub ip_src: [u8; 4],
    /// Local address the client talks to, in network byte order.
    pub ip_dst: [u8; 4],
    pub mac_src: [u8; 6],
    pub mac_dst: [u8; 6],
    /// Slave the client's inbound traffic is steered to.
    pub slave: Option<usize>,
    pub assigned: bool,
    /// A refresh is owed to this client.
    pub ntt: bool,
    pub vlan_id: u16,
    /// Next entry sharing the same source-address fold.
    pub src_next: u32,
}

impl Default for RlbClient {
    fn default() -> Self {
        RlbClient {
            ip_src: [0; 4], ip_dst: [0; 4], mac_src: [0; 6], mac_dst: [0; 6],
            slave: None, assigned: false, ntt: false, vlan_id: 0,
            src_next: TLB_NULL_INDEX,
        }
    }
}

/// Client table plus the round-robin cursor the next assignment starts from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RlbTable {
    entries: [RlbClient; RLB_HASH_TABLE_SIZE],
    next_rx_cursor: usize,
}

impl Default for RlbTable {
    fn default() -> Self {
        RlbTable { entries: [RlbClient::default(); RLB_HASH_TABLE_SIZE], next_rx_cursor: 0 }
    }
}

/// The address-resolution fields the receive balancer reads out of a frame.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ArpView {
    pub ip_src: [u8; 4],
    pub ip_dst: [u8; 4],
    pub mac_src: [u8; 6],
    pub mac_dst: [u8; 6],
    pub vlan_id: u16,
}

/// What the balancer decided for one outbound resolution frame.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RlbDecision {
    /// Slave the client is now pinned to.
    pub slave: Option<usize>,
    /// Table index the client occupies.
    pub index: u8,
    /// Whether the source address of the emitted frame must be rewritten to
    /// the pinned slave's address rather than the master's.
    pub rewrite_src: bool,
}

/// Next slave in the round-robin over ports able to receive.
/// # C: O(slaves)
pub fn next_rx_slave(slaves: &[SlaveState], cursor: usize) -> Option<usize> {
    let n = slaves.len();
    if n == 0 { return None; }
    for k in 0..n {
        let i = (cursor + k) % n;
        if slaves[i].can_tx() { return Some(i); }
    }
    None
}

impl RlbTable {
    /// # C: O(1)
    pub fn client(&self, index: u8) -> &RlbClient { &self.entries[index as usize] }

    /// # C: O(1)
    pub fn cursor(&self) -> usize { self.next_rx_cursor }

    /// Pick, or confirm, the slave one client's inbound traffic uses. A client
    /// already holding its entry keeps its slave; a colliding client displaces
    /// the incumbent onto the currently active slave first.
    /// # C: O(slaves)
    pub fn choose_channel(&mut self, arp: &ArpView, slaves: &[SlaveState],
                          curr_active: Option<usize>) -> RlbDecision {
        let index = simple_hash(&arp.ip_dst);
        let i = index as usize;

        if self.entries[i].assigned {
            let same_client = self.entries[i].ip_src == arp.ip_src
                && self.entries[i].ip_dst == arp.ip_dst;
            if same_client {
                if !is_broadcast(&arp.mac_dst) { self.entries[i].mac_dst = arp.mac_dst; }
                self.entries[i].mac_src = arp.mac_src;
                if let Some(s) = self.entries[i].slave {
                    return RlbDecision { slave: Some(s), index, rewrite_src: true };
                }
            } else if let Some(a) = curr_active {
                if self.entries[i].slave != Some(a) {
                    self.entries[i].slave = Some(a);
                    self.entries[i].ntt = true;
                }
            }
        }

        let assigned = next_rx_slave(slaves, self.next_rx_cursor);
        if let Some(s) = assigned {
            self.next_rx_cursor = (s + 1) % slaves.len().max(1);
            let e = &mut self.entries[i];
            e.ip_src = arp.ip_src;
            e.ip_dst = arp.ip_dst;
            e.mac_dst = arp.mac_dst;
            e.mac_src = arp.mac_src;
            e.vlan_id = arp.vlan_id;
            e.slave = Some(s);
            e.assigned = true;
            e.ntt = is_valid_unicast(&arp.mac_dst);
        }
        RlbDecision { slave: assigned, index, rewrite_src: assigned.is_some() }
    }

    /// Move every client pinned to a departing slave onto a replacement.
    /// # C: O(table)
    pub fn purge_slave(&mut self, slave: usize, replacement: Option<usize>) {
        for e in self.entries.iter_mut() {
            if e.slave == Some(slave) {
                e.slave = replacement;
                e.ntt = replacement.is_some();
            }
        }
    }

    /// Clients owed a refresh, as table indexes.
    /// # C: O(table)
    pub fn pending_updates(&self) -> impl Iterator<Item = usize> + '_ {
        self.entries.iter().enumerate().filter(|(_, e)| e.assigned && e.ntt).map(|(i, _)| i)
    }

    /// Clear the refresh debt after the learning packets went out.
    /// # C: O(table)
    pub fn clear_updates(&mut self) {
        for e in self.entries.iter_mut() { e.ntt = false; }
    }
}

/// # C: O(1)
fn is_broadcast(mac: &[u8; 6]) -> bool { mac.iter().all(|b| *b == 0xff) }

/// # C: O(1)
fn is_valid_unicast(mac: &[u8; 6]) -> bool {
    (mac[0] & 0x01) == 0 && mac.iter().any(|b| *b != 0)
}
