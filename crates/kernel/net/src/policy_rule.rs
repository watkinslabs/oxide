extern crate alloc;

use alloc::vec::Vec;

use sync::{Spinlock, Socket as RuleLockClass};

pub const RT_TABLE_DEFAULT: u32 = 253;
pub const RT_TABLE_MAIN:    u32 = 254;
pub const RT_TABLE_LOCAL:   u32 = 255;

pub const AF_INET:  u8 = 2;
pub const AF_INET6: u8 = 10;

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

static RULE_TABLE: Spinlock<Vec<PolicyRule>, RuleLockClass> = Spinlock::new(Vec::new());

/// Built-in local/main/default policy rules. # C: O(1)
pub fn builtin_rules(ns: u64, family: u8) -> [PolicyRule; 3] {
    [
        PolicyRule {
            ns, family, priority: 0, table: RT_TABLE_LOCAL,
            action: FR_ACT_TO_TBL, dst_len: 0, src_len: 0, tos: 0, flags: 0,
        },
        PolicyRule {
            ns, family, priority: 32766, table: RT_TABLE_MAIN,
            action: FR_ACT_TO_TBL, dst_len: 0, src_len: 0, tos: 0, flags: 0,
        },
        PolicyRule {
            ns, family, priority: 32767, table: RT_TABLE_DEFAULT,
            action: FR_ACT_TO_TBL, dst_len: 0, src_len: 0, tos: 0, flags: 0,
        },
    ]
}

/// Snapshot custom policy rules in network namespace `ns`. # C: O(N)
pub fn snapshot_custom_ns(ns: u64) -> Vec<PolicyRule> {
    RULE_TABLE.lock().iter().filter(|r| r.ns == ns).copied().collect()
}

/// Snapshot built-in and custom policy rules sorted by priority. # C: O(N log N)
pub fn snapshot_effective(ns: u64, family: u8) -> Vec<PolicyRule> {
    let mut rows: Vec<PolicyRule> = builtin_rules(ns, family).into_iter().collect();
    rows.extend(snapshot_custom_ns(ns).into_iter().filter(|r| r.family == family));
    rows.sort_by_key(|r| r.priority);
    rows
}

/// True if an equivalent custom rule exists. # C: O(N)
pub fn exists(row: PolicyRule) -> bool {
    RULE_TABLE.lock().iter().any(|r| {
        r.ns == row.ns && r.family == row.family && r.priority == row.priority
    })
}

/// Insert or replace by `(ns, family, priority)`. # C: O(N)
pub fn insert(row: PolicyRule) {
    let mut g = RULE_TABLE.lock();
    if let Some(i) = g.iter().position(|r| {
        r.ns == row.ns && r.family == row.family && r.priority == row.priority
    }) {
        g[i] = row;
    } else {
        g.push(row);
    }
}

/// Remove custom rules matching optional key fields. # C: O(N)
pub fn remove(ns: u64, family: u8, priority: Option<u32>, table: Option<u32>) -> usize {
    let mut g = RULE_TABLE.lock();
    let before = g.len();
    g.retain(|r| {
        r.ns != ns
            || r.family != family
            || priority.is_some_and(|p| r.priority != p)
            || table.is_some_and(|t| r.table != t)
    });
    before - g.len()
}

/// Pick a free priority before the built-in main/default rules. # C: O(N * 32765)
pub fn next_priority(ns: u64, family: u8) -> u32 {
    let used = snapshot_custom_ns(ns);
    (1..32766)
        .rev()
        .find(|p| !used.iter().any(|r| r.family == family && r.priority == *p))
        .unwrap_or(1)
}
