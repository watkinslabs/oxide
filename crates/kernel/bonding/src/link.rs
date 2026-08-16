// Link monitoring decisions: the MII monitor's per-tick phase machine and the
// ARP monitor's validation rules. Both are pure — they propose a new phase and
// a new countdown, and the caller commits.

extern crate alloc;
use alloc::vec::Vec;

use crate::slave::{LinkState, SlaveState};
use crate::uapi::{
    BOND_ARP_FILTER, BOND_ARP_TARGETS_ALL, BOND_ARP_VALIDATE_ACTIVE,
    BOND_ARP_VALIDATE_BACKUP, BOND_ARP_VALIDATE_NONE, BOND_MODE_ACTIVEBACKUP,
};

/// Monitor parameters shared by every slave in one pass.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct MiiParams {
    /// Ticks a slave stays in `Fail` before it counts as down.
    pub downdelay: i32,
    /// Ticks a slave stays in `Back` before it counts as up.
    pub updelay: i32,
}

/// What one tick decided for one slave.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MiiProposal {
    /// New phase, or `None` when the tick changed nothing.
    pub link: Option<LinkState>,
    /// Countdown the slave carries into the next tick.
    pub delay: i32,
    /// Whether this slave contributed a commit.
    pub commit: bool,
}

/// Whether the bond has no working path at all, in which case a recovering
/// slave skips its up-delay rather than leaving the bond dark.
/// # C: O(slaves)
pub fn ignore_updelay(mode: u8, slaves: &[SlaveState], curr_active: Option<usize>) -> bool {
    if mode == BOND_MODE_ACTIVEBACKUP { return curr_active.is_none(); }
    !slaves.iter().any(|s| s.can_tx())
}

/// One monitor tick for one slave.
/// # C: O(1)
pub fn mii_tick(slave: &SlaveState, params: &MiiParams, ignore_up: bool) -> MiiProposal {
    let carrier = slave.carrier;
    let mut delay = slave.delay;

    // `Up` losing carrier enters the fail phase with a fresh down-delay and
    // then re-evaluates that phase in the same tick.
    let mut phase = slave.link;
    let mut entered_fail = false;
    if phase == LinkState::Up {
        if carrier { return MiiProposal { link: None, delay, commit: false }; }
        phase = LinkState::Fail;
        delay = params.downdelay;
        entered_fail = true;
    }
    if phase == LinkState::Fail {
        if carrier {
            return MiiProposal { link: Some(LinkState::Up), delay, commit: true };
        }
        if delay <= 0 {
            return MiiProposal { link: Some(LinkState::Down), delay, commit: true };
        }
        delay -= 1;
        return MiiProposal {
            link: if entered_fail { Some(LinkState::Fail) } else { None },
            delay,
            commit: entered_fail,
        };
    }

    // `Down` regaining carrier enters the back phase with a fresh up-delay and
    // re-evaluates that phase in the same tick.
    let mut entered_back = false;
    if phase == LinkState::Down {
        if !carrier { return MiiProposal { link: None, delay, commit: false }; }
        delay = params.updelay;
        entered_back = true;
    }
    if !carrier {
        return MiiProposal { link: Some(LinkState::Down), delay, commit: true };
    }
    if ignore_up { delay = 0; }
    if delay <= 0 {
        return MiiProposal { link: Some(LinkState::Up), delay, commit: true };
    }
    delay -= 1;
    MiiProposal {
        link: if entered_back { Some(LinkState::Back) } else { None },
        delay,
        commit: entered_back,
    }
}

/// A whole monitor pass. Once a slave is brought up the remaining slaves no
/// longer skip their up-delay, because the bond again has a working path.
/// # C: O(slaves)
pub fn mii_inspect(slaves: &[SlaveState], params: &MiiParams, mode: u8,
                   curr_active: Option<usize>) -> Vec<MiiProposal> {
    let mut ignore_up = ignore_updelay(mode, slaves, curr_active);
    let mut out = Vec::with_capacity(slaves.len());
    for s in slaves {
        let p = mii_tick(s, params, ignore_up);
        if p.link == Some(LinkState::Up) && s.link != LinkState::Up { ignore_up = false; }
        out.push(p);
    }
    out
}

// -------------------------------------------------------------- ARP monitoring

/// Whether the arp_validate setting asks this slave's role to be validated.
/// # C: O(1)
pub fn arp_validate_for_role(arp_validate: u32, active: bool) -> bool {
    let bit = if active { BOND_ARP_VALIDATE_ACTIVE } else { BOND_ARP_VALIDATE_BACKUP };
    (arp_validate & bit) != 0
}

/// Whether inbound traffic on a slave is filtered to validated ARP only.
/// # C: O(1)
pub fn arp_filtered(arp_validate: u32) -> bool { (arp_validate & BOND_ARP_FILTER) != 0 }

/// Whether validation is switched off entirely.
/// # C: O(1)
pub fn arp_validate_disabled(arp_validate: u32) -> bool {
    arp_validate == BOND_ARP_VALIDATE_NONE
}

/// Why a received ARP was accepted as proof the path works.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ArpAccept {
    /// Rejected: nothing about this frame proves a working path.
    No,
    /// The receiving slave is the active one; sender/target as received.
    OnActive,
    /// A backup slave saw the broadcast request the active slave's peer
    /// answered, so sender and target are validated swapped.
    OnBackupSwapped,
    /// A probing slave sent a request last interval and this is its reply.
    ProbeReply,
}

/// Inputs the ARP receive decision reads.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ArpRxContext {
    /// Receiving slave carries the active role.
    pub slave_is_active: bool,
    /// A currently active slave exists.
    pub have_active: bool,
    /// The active slave has received traffic since it became active.
    pub active_rx_since_up: bool,
    /// A slave is probing with ARP requests.
    pub have_arp_slave: bool,
    /// That probe was sent within the last interval.
    pub arp_slave_tx_in_interval: bool,
    /// The frame is an ARP reply rather than a request.
    pub is_reply: bool,
    /// Hardware address length matches the bond's.
    pub hlen_ok: bool,
    /// Protocol address length is four octets.
    pub plen_ok: bool,
    /// Hardware type and protocol type are Ethernet/IPv4.
    pub types_ok: bool,
    /// The frame was addressed to this host rather than overheard.
    pub addressed_here: bool,
}

/// Whether a received ARP validates the receiving slave's path.
/// # C: O(1)
pub fn arp_rcv(ctx: &ArpRxContext) -> ArpAccept {
    if !ctx.hlen_ok || !ctx.plen_ok || !ctx.types_ok || !ctx.addressed_here {
        return ArpAccept::No;
    }
    if ctx.slave_is_active { return ArpAccept::OnActive; }
    if ctx.have_active && ctx.active_rx_since_up { return ArpAccept::OnBackupSwapped; }
    if ctx.have_arp_slave && ctx.is_reply && ctx.arp_slave_tx_in_interval {
        return ArpAccept::ProbeReply;
    }
    ArpAccept::No
}

/// Whether the configured targets have answered often enough to call the link
/// up: `any` needs one reply, `all` needs every target inside the window.
/// # C: O(targets)
pub fn arp_targets_satisfied(arp_all_targets: u32, replied: &[bool]) -> bool {
    if replied.is_empty() { return false; }
    if arp_all_targets == BOND_ARP_TARGETS_ALL {
        replied.iter().all(|r| *r)
    } else {
        replied.iter().any(|r| *r)
    }
}

/// Whether a slave has missed enough consecutive intervals to count as down.
/// # C: O(1)
pub fn arp_missed_exceeded(missed: u32, missed_max: u32) -> bool { missed > missed_max }
