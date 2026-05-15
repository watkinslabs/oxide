// Landlock per `27` + Linux Documentation/userspace-api/landlock.rst.
// Per-task ruleset chain consulted on every path-based syscall;
// any ruleset that rejects the access denies the syscall with
// EACCES. Layered semantics: each landlock_restrict_self() appends
// a ruleset; an access is allowed only if EVERY ruleset in the
// chain allows it.

#![cfg(target_os = "oxide-kernel")]

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};

/// Linux LANDLOCK_ACCESS_FS_* bit-set.
pub mod access {
    pub const EXECUTE:           u64 = 1 << 0;
    pub const WRITE_FILE:        u64 = 1 << 1;
    pub const READ_FILE:         u64 = 1 << 2;
    pub const READ_DIR:          u64 = 1 << 3;
    pub const REMOVE_DIR:        u64 = 1 << 4;
    pub const REMOVE_FILE:       u64 = 1 << 5;
    pub const MAKE_CHAR:         u64 = 1 << 6;
    pub const MAKE_DIR:          u64 = 1 << 7;
    pub const MAKE_REG:          u64 = 1 << 8;
    pub const MAKE_SOCK:         u64 = 1 << 9;
    pub const MAKE_FIFO:         u64 = 1 << 10;
    pub const MAKE_BLOCK:        u64 = 1 << 11;
    pub const MAKE_SYM:          u64 = 1 << 12;
    pub const REFER:             u64 = 1 << 13;
    pub const TRUNCATE:          u64 = 1 << 14;
}

/// One path-prefix rule within a ruleset.
#[derive(Clone, Debug)]
pub struct Rule {
    /// Absolute path the rule applies to (matches if the target
    /// path starts with this prefix). Trailing slash optional.
    pub path_prefix: String,
    /// Allowed access bits at and below `path_prefix`.
    pub allowed: u64,
}

/// Layered ruleset created via `landlock_create_ruleset`. Each
/// ruleset declares which access kinds it `handled` (mask of
/// LANDLOCK_ACCESS_FS_*); unhandled kinds always pass through.
/// Tightening: once attached to a task chain via `restrict_self`,
/// the ruleset can't be removed.
pub struct Ruleset {
    pub id:      u64,
    pub handled: u64,
    pub rules:   Spinlock<Vec<Rule>, TaskListClass>,
}

impl Ruleset {
    /// # C: O(1)
    pub fn new(id: u64, handled: u64) -> Arc<Self> {
        Arc::new(Self { id, handled, rules: Spinlock::new(Vec::new()) })
    }

    /// Append a path-prefix rule.
    /// # C: O(1)
    pub fn add(&self, rule: Rule) {
        self.rules.lock().push(rule);
    }

    /// True if this ruleset allows `op` on `path`. Unhandled-by-
    /// ruleset access kinds pass (Linux semantic: only the
    /// declared `handled` set is filtered).
    /// # C: O(N_rules) per call
    pub fn allows(&self, path: &str, op: u64) -> bool {
        if (op & self.handled) == 0 { return true; }
        let must_match = op & self.handled;
        let mut accumulated: u64 = 0;
        for r in self.rules.lock().iter() {
            if path_matches(path, &r.path_prefix) {
                accumulated |= r.allowed & must_match;
            }
        }
        (accumulated & must_match) == must_match
    }
}

/// Path-prefix match. `prefix` matches `path` iff `prefix == path`
/// or `path` starts with `prefix` followed by `/`.
fn path_matches(path: &str, prefix: &str) -> bool {
    if prefix == path { return true; }
    if prefix == "/" { return true; }
    let p = prefix.trim_end_matches('/');
    if path.len() <= p.len() { return false; }
    path.starts_with(p) && path.as_bytes()[p.len()] == b'/'
}

/// Global ruleset registry. landlock_create_ruleset allocates an
/// id + stashes the ruleset here; landlock_add_rule and
/// landlock_restrict_self look it up by id.
static REGISTRY: Spinlock<Vec<Arc<Ruleset>>, TaskListClass> = Spinlock::new(Vec::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a fresh ruleset, register it, return its id.
/// # C: O(1)
pub fn create_ruleset(handled: u64) -> u64 {
    let id = NEXT_ID.fetch_add(1, Ordering::AcqRel);
    let rs = Ruleset::new(id, handled);
    REGISTRY.lock().push(rs);
    id
}

/// Look up a registered ruleset by id.
/// # C: O(N_rulesets)
pub fn lookup(id: u64) -> Option<Arc<Ruleset>> {
    REGISTRY.lock().iter().find(|r| r.id == id).cloned()
}

/// Per-task landlock chain: ordered list of rulesets that ALL
/// must permit an access for it to succeed. Caller obtains via
/// `Task.landlock_chain.lock()`.
pub type Chain = Vec<Arc<Ruleset>>;

/// Check `(path, op)` against a chain. Returns Ok(()) when every
/// ruleset permits; Err(()) on first denial.
/// # C: O(N_chain × N_rules)
pub fn chain_permits(chain: &Chain, path: &str, op: u64) -> bool {
    chain.iter().all(|rs| rs.allows(path, op))
}
