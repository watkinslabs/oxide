// The global `(namespace, uid) -> counters` table (Linux's `ucounts_hashtable`).
//
// An entry exists only while some counter is non-zero, which is Linux's
// refcount rule stated positively: `put_ucounts` frees the struct once the
// last charge is gone, so an idle account costs nothing and a long-lived
// system does not accumulate one entry per uid ever seen.

use alloc::collections::BTreeMap;

use crate::counter::COUNTS;
use crate::key::UcountKey;

static TABLE: sync::Spinlock<BTreeMap<UcountKey, [i64; COUNTS]>, sync::TaskList> =
    sync::Spinlock::new(BTreeMap::new());

/// Add `delta` to one counter of one key and return the resulting value.
/// The entry is created on first charge and removed once every counter is
/// back to zero. # C: O(log N); # Lk: TaskList
pub(crate) fn adjust(key: UcountKey, index: usize, delta: i64) -> i64 {
    let mut table = TABLE.lock();
    let counters = table.entry(key).or_insert([0; COUNTS]);
    // Saturating so a runaway charge cannot wrap into a negative count and
    // read back as "far below the limit".
    counters[index] = counters[index].saturating_add(delta).max(0);
    let now = counters[index];
    if counters.iter().all(|c| *c == 0) { table.remove(&key); }
    now
}

/// Current value of one counter. # C: O(log N); # Lk: TaskList
pub(crate) fn read(key: UcountKey, index: usize) -> i64 {
    TABLE.lock().get(&key).map_or(0, |counters| counters[index])
}

#[cfg(test)]
pub(crate) fn clear_for_tests() { TABLE.lock().clear(); }
