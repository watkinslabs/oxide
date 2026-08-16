// Active-slave selection: primary handling, the reselection policies, and the
// gate on gratuitous peer notification.

use crate::slave::{LinkState, SlaveState};
use crate::uapi::{
    BOND_MODE_8023AD, BOND_PRI_RESELECT_ALWAYS, BOND_PRI_RESELECT_BETTER,
    BOND_PRI_RESELECT_FAILURE,
};

/// Selection inputs beyond the slave slice.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SelectContext {
    /// Configured primary slave index, when one is set.
    pub primary: Option<usize>,
    /// Slave carrying the active role right now.
    pub curr_active: Option<usize>,
    /// One-shot: the primary wins this selection regardless of the policy.
    pub force_primary: bool,
    /// One of the `BOND_PRI_RESELECT_*` policies.
    pub primary_reselect: u32,
    /// Up-delay, which bounds how long a recovering candidate may still owe.
    pub updelay: i32,
}

/// Highest-priority slave whose link is settled up.
/// # C: O(slaves)
pub fn highest_prio_up(slaves: &[SlaveState]) -> Option<usize> {
    let mut best: Option<usize> = None;
    for (i, s) in slaves.iter().enumerate() {
        if s.link != LinkState::Up { continue; }
        match best {
            None => best = Some(i),
            Some(b) => if s.prio > slaves[b].prio { best = Some(i); },
        }
    }
    best
}

/// Primary-or-current decision. A primary that is down yields to the
/// highest-priority up slave; two up candidates are resolved by the
/// reselection policy, whose `better` arm compares speed then duplex.
/// # C: O(slaves)
pub fn choose_primary_or_current(slaves: &[SlaveState], ctx: &SelectContext) -> Option<usize> {
    let curr = ctx.curr_active;
    let curr_up = curr.map(|c| slaves[c].link == LinkState::Up).unwrap_or(false);
    let mut prim = ctx.primary;
    let prim_up = prim.map(|p| slaves[p].link == LinkState::Up).unwrap_or(false);

    if !prim_up {
        let hprio = highest_prio_up(slaves);
        match hprio {
            Some(h) if Some(h) != curr => prim = Some(h),
            _ => return if curr_up { curr } else { None },
        }
    } else if ctx.force_primary {
        return prim;
    }

    let p = prim?;
    if !curr_up { return Some(p); }
    let c = curr?;
    match ctx.primary_reselect {
        BOND_PRI_RESELECT_ALWAYS => Some(p),
        BOND_PRI_RESELECT_BETTER => {
            if slaves[p].speed_mbps < slaves[c].speed_mbps { return Some(c); }
            if slaves[p].speed_mbps == slaves[c].speed_mbps
                && slaves[p].duplex <= slaves[c].duplex { return Some(c); }
            Some(p)
        }
        BOND_PRI_RESELECT_FAILURE => Some(c),
        _ => Some(c),
    }
}

/// Best slave overall: the primary-or-current answer, else the first settled
/// up slave, else the recovering slave closest to finishing its up-delay.
/// # C: O(slaves)
pub fn find_best_slave(slaves: &[SlaveState], ctx: &SelectContext) -> Option<usize> {
    if let Some(s) = choose_primary_or_current(slaves, ctx) { return Some(s); }
    let mut mintime = ctx.updelay;
    let mut best: Option<usize> = None;
    for (i, s) in slaves.iter().enumerate() {
        if s.link == LinkState::Up { return Some(i); }
        if s.link == LinkState::Back && s.is_up() && s.delay < mintime {
            mintime = s.delay;
            best = Some(i);
        }
    }
    best
}

/// Whether a gratuitous notification is due on this pass: notifications
/// remain owed, the delay divides the remaining count, the bond's own carrier
/// is up, and the mode has somewhere to send from.
/// # C: O(1)
pub fn should_notify_peers(send_peer_notif: u32, peer_notif_delay: u32, carrier_ok: bool,
                           mode: u8, usable_count: usize, curr_active: Option<usize>,
                           linkwatch_pending: bool) -> bool {
    if send_peer_notif == 0 { return false; }
    let divisor = core::cmp::max(1, peer_notif_delay);
    if send_peer_notif % divisor != 0 { return false; }
    if !carrier_ok { return false; }
    if mode == BOND_MODE_8023AD { return usable_count != 0; }
    curr_active.is_some() && !linkwatch_pending
}
