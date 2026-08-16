// Per-slave state the pure decision modules read: link phase, carrier,
// monitor countdown, negotiated speed/duplex, reselection priority, and the
// 802.3ad aggregator the port currently belongs to.

/// Link phase of one enslaved port.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LinkState { Up = 0, Fail = 1, Down = 2, Back = 3 }

impl LinkState {
    /// # C: O(1)
    pub const fn as_u8(self) -> u8 { self as u8 }
    /// # C: O(1)
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(LinkState::Up),
            1 => Some(LinkState::Fail),
            2 => Some(LinkState::Down),
            3 => Some(LinkState::Back),
            _ => None,
        }
    }
}

/// Whether the port is forwarding user traffic or held as a backup.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SlaveRole { Active = 0, Backup = 1 }

/// One enslaved port as the decision layer sees it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SlaveState {
    /// Registry identity of the port, so callers can map an index back.
    pub ifindex: u32,
    pub link: LinkState,
    /// Administratively running with carrier present.
    pub carrier: bool,
    /// Monitor countdown remaining, in monitor ticks.
    pub delay: i32,
    pub role: SlaveRole,
    pub speed_mbps: u32,
    /// Duplex encoding shared with the reselection tiebreak.
    pub duplex: u8,
    /// Reselection priority; higher wins.
    pub prio: i32,
    /// Transmit queue the port answers to, zero when unset.
    pub queue_id: u16,
    /// Aggregator this port currently belongs to under 802.3ad.
    pub agg_id: u16,
    /// Accumulated transmit bytes used by the TLB gap computation.
    pub tlb_load: u64,
    /// Consecutive link failures observed on this port.
    pub link_failure_count: u32,
}

impl Default for SlaveState {
    fn default() -> Self {
        SlaveState {
            ifindex: 0, link: LinkState::Down, carrier: false, delay: 0,
            role: SlaveRole::Backup, speed_mbps: 0, duplex: crate::uapi::DUPLEX_HALF,
            prio: 0, queue_id: 0, agg_id: 0, tlb_load: 0, link_failure_count: 0,
        }
    }
}

impl SlaveState {
    /// Running with carrier — the condition every transmit path gates on.
    /// # C: O(1)
    pub const fn is_up(&self) -> bool { self.carrier }
    /// # C: O(1)
    pub const fn is_active(&self) -> bool { matches!(self.role, SlaveRole::Active) }
    /// Eligible to carry a transmitted frame: running, link settled up, and
    /// not held in the backup role.
    /// # C: O(1)
    pub const fn can_tx(&self) -> bool {
        self.carrier && matches!(self.link, LinkState::Up) && self.is_active()
    }
}
