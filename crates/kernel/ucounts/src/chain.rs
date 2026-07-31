// Per-user-namespace link and ceiling: Linux `user_namespace::ucounts` (the
// creating task's ucounts, one level up) and `user_namespace::rlimit_max`.
//
// A namespace with no registered link is the initial namespace's shape: no
// parent account to charge, no ceiling. That is also the safe reading for a
// namespace created before anyone registered it — it charges only itself and
// enforces only the caller's own `RLIMIT_NPROC`, never a ceiling it never
// agreed to.

use alloc::collections::BTreeMap;

use crate::counter::{Counter, COUNTS};
use crate::key::UcountKey;

/// Linux `RLIM_INFINITY` as this crate stores a ceiling. Counts are `i64`,
/// so an unbounded ceiling is the largest representable count. # C: O(1)
pub const RLIM_INFINITY: i64 = i64::MAX;

#[derive(Clone, Copy)]
struct NsLink {
    /// The account that created this namespace, in its PARENT namespace.
    creator: UcountKey,
    /// Per-counter ceiling this namespace imposes on the level ABOVE it.
    ceiling: [i64; COUNTS],
}

static LINKS: sync::Spinlock<BTreeMap<u64, NsLink>, sync::TaskList> =
    sync::Spinlock::new(BTreeMap::new());

/// Record the creator account and ceilings of a newly created user
/// namespace (Linux `create_user_ns`: `ns->ucounts = ucounts` plus
/// `set_userns_rlimit_max(ns, UCOUNT_RLIMIT_NPROC, enforced_nproc_rlimit())`).
///
/// `nproc_ceiling` is the creating task's own effective `RLIMIT_NPROC`, or
/// [`RLIM_INFINITY`] when the creator is the initial namespace's root — which
/// is Linux's `enforced_nproc_rlimit()` in full.
/// # C: O(log N); # Lk: TaskList
pub fn register_namespace(ns: u64, creator: UcountKey, nproc_ceiling: i64) {
    let mut ceiling = [RLIM_INFINITY; COUNTS];
    ceiling[Counter::Nproc.index()] = nproc_ceiling.max(0);
    LINKS.lock().insert(ns, NsLink { creator, ceiling });
}

/// Drop a namespace's link once the namespace itself is gone. # C: O(log N)
pub fn forget_namespace(ns: u64) { LINKS.lock().remove(&ns); }

/// The account one level up from `ns`, or `None` at the top of the chain.
/// # C: O(log N); # Lk: TaskList
pub(crate) fn creator_of(ns: u64) -> Option<UcountKey> {
    LINKS.lock().get(&ns).map(|link| link.creator)
}

/// The ceiling `ns` imposes on the level above it in the chain.
/// # C: O(log N); # Lk: TaskList
pub(crate) fn ceiling_of(ns: u64, counter: Counter) -> i64 {
    LINKS.lock().get(&ns).map_or(RLIM_INFINITY, |link| link.ceiling[counter.index()])
}

#[cfg(test)]
pub(crate) fn clear_for_tests() { LINKS.lock().clear(); }
