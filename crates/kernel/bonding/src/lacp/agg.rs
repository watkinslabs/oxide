// Aggregator comparison and selection. The precedence is fixed: a negotiated
// aggregator always beats an individual one, an answering partner beats a
// silent one, and only then does the configured ad_select policy decide.

use crate::uapi::{BOND_AD_BANDWIDTH, BOND_AD_COUNT, BOND_AD_PRIO, BOND_AD_STABLE};

/// One aggregation group as the selection reads it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Aggregator {
    pub id: u16,
    /// No partner negotiated the group, so it aggregates one port alone.
    pub is_individual: bool,
    /// Partner system address, all-zero when no partner answered.
    pub partner_system: [u8; 6],
    /// Ports currently able to carry traffic.
    pub active_ports: u32,
    /// Summed port priority across the group.
    pub ports_priority: u32,
    /// Summed link bandwidth across the group, in megabits per second.
    pub bandwidth: u64,
    /// Ports attached to the group at all.
    pub num_ports: u32,
    /// Aggregation key the actor operates with.
    pub actor_key: u16,
    /// At least one port has a running device with carrier.
    pub device_up: bool,
    /// The group carrying traffic right now.
    pub is_active: bool,
}

impl Aggregator {
    /// Whether a partner answered for this group.
    /// # C: O(1)
    pub fn has_partner(&self) -> bool { self.partner_system != [0u8; 6] }
}

/// Pairwise comparison. Returns the winner between the incumbent `best` and
/// the challenger `curr` under `policy`; a policy that ties falls through to
/// the next criterion in the documented order.
/// # C: O(1)
pub fn agg_selection_test<'a>(best: Option<&'a Aggregator>, curr: &'a Aggregator, policy: u32)
    -> &'a Aggregator
{
    let best = match best { None => return curr, Some(b) => b };

    if !curr.is_individual && best.is_individual { return curr; }
    if curr.is_individual && !best.is_individual { return best; }

    if curr.has_partner() && !best.has_partner() { return curr; }
    if !curr.has_partner() && best.has_partner() { return best; }

    let mut stage = policy;
    if stage == BOND_AD_PRIO {
        if curr.ports_priority > best.ports_priority { return curr; }
        if curr.ports_priority < best.ports_priority { return best; }
        stage = BOND_AD_COUNT;
    }
    if stage == BOND_AD_COUNT {
        if curr.active_ports > best.active_ports { return curr; }
        if curr.active_ports < best.active_ports { return best; }
        stage = BOND_AD_BANDWIDTH;
    }
    if stage == BOND_AD_STABLE || stage == BOND_AD_BANDWIDTH {
        if curr.bandwidth > best.bandwidth { return curr; }
    }
    best
}

/// Whole-bond selection. Only groups with active ports on a live device are
/// candidates; under the stable policy an incumbent that still has ports and
/// an answering partner keeps the role rather than being replaced.
/// # C: O(aggregators)
pub fn select_aggregator(aggs: &[Aggregator], policy: u32) -> Option<usize> {
    let active = aggs.iter().position(|a| a.is_active);
    let mut best: Option<usize> = match active {
        Some(i) if aggs[i].device_up => Some(i),
        _ => None,
    };

    for (i, a) in aggs.iter().enumerate() {
        if a.active_ports == 0 || !a.device_up { continue; }
        match best {
            None => best = Some(i),
            Some(b) => {
                let winner = agg_selection_test(Some(&aggs[b]), a, policy);
                if core::ptr::eq(winner, a) { best = Some(i); }
            }
        }
    }

    let chosen = best?;
    if policy == BOND_AD_STABLE {
        if let Some(act) = active {
            let a = &aggs[act];
            let b = &aggs[chosen];
            let sticky = a.num_ports > 0 && a.active_ports > 0
                && (a.has_partner() || (!a.has_partner() && !b.has_partner()));
            let key_upgrade = a.actor_key == 0 && b.actor_key != 0;
            if sticky && !key_upgrade { return Some(act); }
        }
    }
    Some(chosen)
}
