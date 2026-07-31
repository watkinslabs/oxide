// The hierarchical charge walks: Linux `inc_rlimit_ucounts`,
// `dec_rlimit_ucounts` and `is_rlimit_overlimit` (`kernel/ucount.c`).
//
// Every walk starts at the task's own account and follows each namespace's
// creator link upward. `inc`/`dec` are UNCONDITIONAL — Linux charges first
// and asks afterwards, because `fork` wants the count to include the task it
// is deciding about, and `commit_creds` must not be able to fail. The
// admission decision is [`is_overlimit`], run separately by the caller.

use crate::chain::{ceiling_of, creator_of, RLIM_INFINITY};
use crate::counter::Counter;
use crate::key::UcountKey;
use crate::table;

/// Longest namespace chain a walk will follow. Linux bounds nesting with
/// `MAX_USER_NS_LEVEL`; the same bound keeps a corrupted or cyclic link from
/// spinning a walk forever. # C: O(1)
const MAX_CHAIN: usize = 32;

/// Charge `delta` to `key` and to every account above it, returning the
/// resulting value at `key` itself (Linux `inc_rlimit_ucounts`).
/// # C: O(chain * log N); # Lk: TaskList
pub fn inc_rlimit(key: UcountKey, counter: Counter, delta: i64) -> i64 {
    walk(key, |k| { table::adjust(k, counter.index(), delta) })
}

/// Release `delta` from `key` and every account above it (Linux
/// `dec_rlimit_ucounts`). Returns the resulting value at `key`.
/// # C: O(chain * log N); # Lk: TaskList
pub fn dec_rlimit(key: UcountKey, counter: Counter, delta: i64) -> i64 {
    walk(key, |k| { table::adjust(k, counter.index(), -delta) })
}

/// Current value at `key` alone, ancestors excluded. # C: O(log N)
pub fn value(key: UcountKey, counter: Counter) -> i64 {
    table::read(key, counter.index())
}

/// Linux `is_rlimit_overlimit`: is the account — or any account above it —
/// at or past the limit that applies at its level? `rlimit` bounds the task's
/// OWN account; each level above is bounded by the ceiling recorded on the
/// namespace below it, so a nested user namespace cannot hand out more than
/// its creator was allowed.
/// # C: O(chain * log N); # Lk: TaskList
pub fn is_overlimit(key: UcountKey, counter: Counter, rlimit: u64) -> bool {
    let mut max = if rlimit > RLIM_INFINITY as u64 { RLIM_INFINITY } else { rlimit as i64 };
    let mut at = Some(key);
    for _ in 0..MAX_CHAIN {
        let Some(current) = at else { return false; };
        if table::read(current, counter.index()) > max { return true; }
        max = ceiling_of(current.ns, counter);
        at = creator_of(current.ns);
    }
    false
}

/// Apply `f` at `key` and at every account above it, returning `f`'s result
/// at `key` itself. # C: O(chain * log N)
fn walk(key: UcountKey, mut f: impl FnMut(UcountKey) -> i64) -> i64 {
    let mut result = 0;
    let mut at = Some(key);
    for step in 0..MAX_CHAIN {
        let Some(current) = at else { break; };
        let value = f(current);
        if step == 0 { result = value; }
        at = creator_of(current.ns);
    }
    result
}
