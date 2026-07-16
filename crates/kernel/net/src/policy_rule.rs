extern crate alloc;

use alloc::vec::Vec;

use sync::{Spinlock, Socket as RuleLockClass};

pub const RT_TABLE_DEFAULT: u32 = 253;
pub const RT_TABLE_MAIN:    u32 = 254;
pub const RT_TABLE_LOCAL:   u32 = 255;
/// rtnetlink's `rtmsg.rtm_table` wire-width forms of the canonical IDs.
pub const RT_TABLE_DEFAULT_WIRE: u8 = RT_TABLE_DEFAULT as u8;
pub const RT_TABLE_MAIN_WIRE:    u8 = RT_TABLE_MAIN as u8;
pub const RT_TABLE_LOCAL_WIRE:   u8 = RT_TABLE_LOCAL as u8;

pub use crate::socket_args::{AF_INET6_RULE as AF_INET6, AF_INET_RULE as AF_INET};

pub const FR_ACT_TO_TBL: u8 = 1;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    pub ns:       u64,
    pub family:   u8,
    pub dst_len:  u8,
    pub src_len:  u8,
    pub tos:      u8,
    pub table:    u32,
    pub action:   u8,
    pub flags:    u32,
    pub priority: u32,
}

struct PolicyRuleState {
    rows: Vec<PolicyRule>,
    initialized: Vec<(u64, u8)>,
}

/// Canonical policy-rule owner for one network stack.
pub struct PolicyRuleTable {
    state: Spinlock<PolicyRuleState, RuleLockClass>,
}

impl PolicyRuleTable {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { state: Spinlock::new(PolicyRuleState {
            rows: Vec::new(), initialized: Vec::new(),
        }) }
    }

    fn assert_owner(&self, rtnl: &crate::RtnlGuard<'_>) {
        assert!(core::ptr::eq(rtnl.stack().policy_rules(), self),
            "policy-rule mutation requires owning stack RTNL");
    }

    fn initialize(state: &mut PolicyRuleState, ns: u64, family: u8) {
        if state.initialized.iter().any(|key| *key == (ns, family)) { return; }
        state.rows.extend_from_slice(&builtin_rules(ns, family));
        state.initialized.push((ns, family));
    }

    /// Snapshot stored policy rules in network namespace `ns`. # C: O(N)
    pub fn snapshot_custom_ns(&self, ns: u64) -> Vec<PolicyRule> {
        self.state.lock().rows.iter().filter(|r| {
            r.ns == ns && !builtin_rules(r.ns, r.family).contains(r)
        }).copied().collect()
    }

    /// Materialize once, then snapshot stored policy rules sorted by priority. # C: O(N log N)
    pub fn snapshot_effective(&self, ns: u64, family: u8) -> Vec<PolicyRule> {
        let mut state = self.state.lock();
        Self::initialize(&mut state, ns, family);
        let mut rows: Vec<PolicyRule> = state.rows.iter()
            .filter(|r| r.ns == ns && r.family == family).copied().collect();
        rows.sort_by_key(|r| r.priority);
        rows
    }

    /// Check custom-rule identity under owning stack RTNL. # Lk: stack RTNL held. # C: O(N)
    pub fn exists_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, row: PolicyRule) -> bool {
        self.assert_owner(rtnl);
        let mut state = self.state.lock();
        Self::initialize(&mut state, row.ns, row.family);
        state.rows.iter().any(|r| *r == row)
    }

    /// Insert and return the exact published row. Linux permits equal-priority rules.
    /// # Lk: stack RTNL held. # C: O(1)
    pub fn insert_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, row: PolicyRule) -> PolicyRule {
        self.assert_owner(rtnl);
        let mut state = self.state.lock();
        Self::initialize(&mut state, row.ns, row.family);
        state.rows.push(row);
        row
    }

    /// Remove and return the first Linux selector match. # Lk: stack RTNL held. # C: O(N)
    pub fn remove_one_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64, family: u8,
                           priority: Option<u32>, table: Option<u32>) -> Option<PolicyRule> {
        self.assert_owner(rtnl);
        let mut state = self.state.lock();
        Self::initialize(&mut state, ns, family);
        let pos = state.rows.iter().position(|r| {
            r.ns == ns && r.family == family
                && priority.is_none_or(|p| r.priority == p)
                && table.is_none_or(|t| r.table == t)
        })?;
        Some(state.rows.remove(pos))
    }

    /// Remove and return exact matching rows. # Lk: stack RTNL held. # C: O(N)
    pub fn remove_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64, family: u8,
        priority: Option<u32>, table: Option<u32>) -> Vec<PolicyRule> {
        self.assert_owner(rtnl);
        let mut state = self.state.lock();
        Self::initialize(&mut state, ns, family);
        let mut removed = Vec::new();
        state.rows.retain(|r| {
            let matched = r.ns == ns && r.family == family
                && priority.is_none_or(|p| r.priority == p)
                && table.is_none_or(|t| r.table == t);
            if matched { removed.push(*r); }
            !matched
        });
        removed
    }

    /// Remove namespace rules under owning stack RTNL. # Lk: stack RTNL held. # C: O(N)
    pub fn remove_namespace_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64) -> usize {
        self.assert_owner(rtnl);
        if ns == 0 { return 0; }
        let mut state = self.state.lock();
        let before = state.rows.len();
        state.rows.retain(|r| r.ns != ns);
        state.initialized.retain(|key| key.0 != ns);
        before - state.rows.len()
    }

    /// Pick a free priority under owning stack RTNL. # Lk: stack RTNL held. # C: O(N * 32765)
    pub fn next_priority_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, ns: u64, family: u8) -> u32 {
        self.assert_owner(rtnl);
        let mut state = self.state.lock();
        Self::initialize(&mut state, ns, family);
        (1..32766).rev().find(|p| !state.rows.iter().any(|r| {
            r.ns == ns && r.family == family && r.priority == *p
        })).unwrap_or(1)
    }
}

impl Default for PolicyRuleTable { fn default() -> Self { Self::new() } }

/// Built-in local/main/default policy rules. # C: O(1)
pub fn builtin_rules(ns: u64, family: u8) -> [PolicyRule; 3] {
    [
        PolicyRule { ns, family, priority: 0, table: RT_TABLE_LOCAL,
            action: FR_ACT_TO_TBL, dst_len: 0, src_len: 0, tos: 0, flags: 0 },
        PolicyRule { ns, family, priority: 32766, table: RT_TABLE_MAIN,
            action: FR_ACT_TO_TBL, dst_len: 0, src_len: 0, tos: 0, flags: 0 },
        PolicyRule { ns, family, priority: 32767, table: RT_TABLE_DEFAULT,
            action: FR_ACT_TO_TBL, dst_len: 0, src_len: 0, tos: 0, flags: 0 },
    ]
}

/// Snapshot custom rules in the global stack. # C: O(N)
pub fn snapshot_custom_ns(ns: u64) -> Vec<PolicyRule> {
    crate::global_stack().policy_rules().snapshot_custom_ns(ns)
}

/// Insert into the global stack under its RTNL lock. # C: O(N)
pub fn insert(row: PolicyRule) {
    let stack = crate::global_stack();
    let rtnl = stack.rtnl_lock();
    stack.policy_rules().insert_rtnl(&rtnl, row);
}

/// Remove from the global stack under its RTNL lock. # C: O(N)
pub fn remove(ns: u64, family: u8, priority: Option<u32>, table: Option<u32>) -> usize {
    let stack = crate::global_stack();
    let rtnl = stack.rtnl_lock();
    stack.policy_rules().remove_rtnl(&rtnl, ns, family, priority, table).len()
}

/// Remove matching rules from the guard's owning stack. # Lk: stack RTNL held. # C: O(N)
pub fn remove_rtnl(rtnl: &crate::RtnlGuard<'_>, ns: u64, family: u8,
    priority: Option<u32>, table: Option<u32>) -> Vec<PolicyRule> {
    rtnl.stack().policy_rules().remove_rtnl(rtnl, ns, family, priority, table)
}

/// Remove namespace rules from the guard's owning stack. # Lk: stack RTNL held. # C: O(N)
pub fn remove_namespace_rtnl(rtnl: &crate::RtnlGuard<'_>, ns: u64) -> usize {
    rtnl.stack().policy_rules().remove_namespace_rtnl(rtnl, ns)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(table: u32) -> PolicyRule {
        PolicyRule { ns: 7, family: AF_INET, dst_len: 0, src_len: 0, tos: 0,
            table, action: FR_ACT_TO_TBL, flags: 0, priority: 100 }
    }

    #[test]
    fn stacks_own_independent_policy_rule_tables() {
        let a = crate::NetStack::new();
        let b = crate::NetStack::new();
        {
            let rtnl = a.rtnl_lock();
            a.policy_rules().insert_rtnl(&rtnl, row(1001));
        }
        {
            let rtnl = b.rtnl_lock();
            b.policy_rules().insert_rtnl(&rtnl, row(2002));
        }
        assert_eq!(a.policy_rules().snapshot_custom_ns(7), alloc::vec![row(1001)]);
        assert_eq!(b.policy_rules().snapshot_custom_ns(7), alloc::vec![row(2002)]);
    }

    #[test]
    fn priority_selection_and_insert_share_stack_rtnl_identity() {
        let a = crate::NetStack::new();
        let b = crate::NetStack::new();
        let a_priority;
        {
            let rtnl = a.rtnl_lock();
            a_priority = a.policy_rules().next_priority_rtnl(&rtnl, 7, AF_INET);
            let mut selected = row(1001);
            selected.priority = a_priority;
            a.policy_rules().insert_rtnl(&rtnl, selected);
        }
        let rtnl = b.rtnl_lock();
        assert_eq!(b.policy_rules().next_priority_rtnl(&rtnl, 7, AF_INET), a_priority);
    }

    #[test]
    fn equal_priority_distinct_rules_are_independent() {
        let stack = crate::NetStack::new();
        let mut a = row(1001);
        let mut b = row(2002);
        a.priority = 777;
        b.priority = 777;
        let rtnl = stack.rtnl_lock();
        stack.policy_rules().insert_rtnl(&rtnl, a);
        stack.policy_rules().insert_rtnl(&rtnl, b);
        assert!(stack.policy_rules().exists_rtnl(&rtnl, a));
        assert!(stack.policy_rules().exists_rtnl(&rtnl, b));
        assert_eq!(stack.policy_rules().snapshot_custom_ns(7), alloc::vec![a, b]);
    }

    #[test]
    fn remove_one_uses_first_selector_match() {
        let stack = crate::NetStack::new();
        let a = row(1001);
        let b = row(2002);
        let rtnl = stack.rtnl_lock();
        stack.policy_rules().insert_rtnl(&rtnl, a);
        stack.policy_rules().insert_rtnl(&rtnl, b);
        assert_eq!(stack.policy_rules().remove_one_rtnl(
            &rtnl, 7, AF_INET, Some(100), None), Some(a));
        assert_eq!(stack.policy_rules().snapshot_custom_ns(7), alloc::vec![b]);
        assert_eq!(stack.policy_rules().remove_one_rtnl(
            &rtnl, 7, AF_INET, Some(100), Some(1001)), None);
    }

    #[test]
    #[should_panic(expected = "policy-rule mutation requires owning stack RTNL")]
    fn foreign_stack_rtnl_cannot_mutate_table() {
        let a = crate::NetStack::new();
        let b = crate::NetStack::new();
        let rtnl = b.rtnl_lock();
        a.policy_rules().insert_rtnl(&rtnl, row(1001));
    }
}
