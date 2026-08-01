// Pure decision half of inode writeback + the lazytime deferral. No `Inode`, no
// `SuperBlock`, no clock — every rule here is a function of `i_state`, the
// requested dirty bits, and two nanosecond stamps, so the whole ladder is
// hosted-testable without a filesystem.

use crate::inode::{I_DIRTY, I_DIRTY_ALL, I_DIRTY_INODE, I_DIRTY_SYNC, I_DIRTY_TIME};

/// Linux `dirtytime_expire_interval` default (`fs/fs-writeback.c`, the
/// `vm.dirtytime_expire_seconds` sysctl): how long a lazily-deferred timestamp
/// may sit in memory before a background writeback pass forces it to disk.
pub const DIRTYTIME_EXPIRE_SECS: u64 = 12 * 60 * 60;

/// Nanoseconds per second, for the expiry arithmetic.
pub const NSEC_PER_SEC: u64 = 1_000_000_000;

/// Linux `inode_time_dirty_flag`: which dirty bit a PURE timestamp change earns.
/// Under `SB_LAZYTIME` it is `I_DIRTY_TIME` (deferred, no I/O); otherwise
/// `I_DIRTY_SYNC` (ordinary metadata dirt, written back with everything else).
/// This one function is the entire behavioural difference the mount option buys.
/// # C: O(1)
pub fn time_dirty_flag(lazytime: bool) -> u32 {
    if lazytime { I_DIRTY_TIME } else { I_DIRTY_SYNC }
}

/// The state transition `__mark_inode_dirty` performs, computed without
/// touching an inode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DirtyTransition {
    /// Bits to pass to `s_op->dirty_inode` so the backend can journal the
    /// change. `0` when no notification is owed (page-only or time-only dirt).
    pub notify:   u32,
    /// Bits to OR into `i_state`.
    pub set:      u32,
    /// Bits to clear from `i_state` (only ever `I_DIRTY_TIME`, superseded).
    pub clear:    u32,
    /// This is the transition that STARTS a lazy deferral on a previously clean
    /// inode — the caller stamps `dirtied_time_when`.
    pub stamp:    bool,
    /// `i_state` actually gains a bit (Linux's early return when it does not).
    pub changed:  bool,
}

/// `__mark_inode_dirty(inode, flags)` reduced to arithmetic on the prior
/// `i_state`.
///
/// Three rules carry the contract:
///
/// 1. A real inode change (`I_DIRTY_INODE`) SUPERSEDES a pending lazy stamp: the
///    `I_DIRTY_TIME` bit is cleared, but it is folded into the `dirty_inode`
///    notification so the backend knows to write the timestamps out along with
///    whatever else changed. Dropping it silently instead is how a lazytime
///    implementation loses an atime.
/// 2. `I_DIRTY_TIME` never combines with the page bit; it is its own request.
/// 3. The expiry clock is stamped only when the deferral begins on an inode
///    that carried no `I_DIRTY` bit — a re-dirty must not push the deadline out
///    (Linux keys `dirtied_time_when` off `!was_dirty` for exactly that reason).
///
/// Lifecycle bits (`I_NEW`/`I_FREEING`/…) are masked out: dirtying is not a
/// channel for smuggling them in.
/// # C: O(1)
pub fn mark_dirty_transition(state: u32, flags: u32) -> DirtyTransition {
    let mut flags = flags & I_DIRTY_ALL;
    let mut t = DirtyTransition::default();
    if flags & I_DIRTY_INODE != 0 {
        let was_dirty_time = state & I_DIRTY_TIME != 0;
        if was_dirty_time { t.clear = I_DIRTY_TIME; }
        t.notify = (flags | if was_dirty_time { I_DIRTY_TIME } else { 0 })
            & (I_DIRTY_INODE | I_DIRTY_TIME);
        flags &= !I_DIRTY_TIME; // I_DIRTY_INODE supersedes I_DIRTY_TIME
    }
    let dirtytime = flags & I_DIRTY_TIME;
    t.changed = flags != 0 && (state & flags) != flags;
    if t.changed {
        t.set = flags;
        t.stamp = dirtytime != 0 && state & I_DIRTY == 0;
    }
    t
}

/// True once a deferred timestamp has sat in memory longer than the expire
/// interval. `when_ns == 0` (no deferral pending) and a clock that has not yet
/// passed the deadline both answer false. Saturating so a bogus future stamp
/// cannot wrap into an immediate expiry. # C: O(1)
pub fn dirtytime_expired(when_ns: u64, now_ns: u64, interval_secs: u64) -> bool {
    if when_ns == 0 { return false; }
    now_ns >= when_ns.saturating_add(interval_secs.saturating_mul(NSEC_PER_SEC))
}

/// `__writeback_single_inode`'s lazytime gate: a data-integrity pass
/// (`WB_SYNC_ALL` — `sync`, `syncfs`, `fsync`, unmount) ALWAYS converts a
/// pending lazy stamp; a background pass converts only an expired one.
/// # C: O(1)
pub fn forces_lazytime(sync_all: bool, when_ns: u64, now_ns: u64, interval_secs: u64) -> bool {
    sync_all || dirtytime_expired(when_ns, now_ns, interval_secs)
}

/// `__writeback_single_inode`: `s_op->write_inode` is owed only when the INODE
/// itself is dirty. Dirty pages alone are the address-space's business and are
/// flushed by the data pass, not by an inode write. # C: O(1)
pub fn needs_write_inode(dirty: u32) -> bool { dirty & I_DIRTY_INODE != 0 }

/// `I_DIRTY_TIME` alone, on an inode that is neither being created nor destroyed
/// (Linux `inode_is_dirtytime_only`) — the state in which a filesystem may
/// opportunistically write the timestamps out with a neighbouring inode.
/// # C: O(1)
pub fn is_dirtytime_only(state: u32) -> bool {
    use crate::inode::{I_FREEING, I_NEW, I_WILL_FREE};
    state & (I_DIRTY_TIME | I_NEW | I_FREEING | I_WILL_FREE) == I_DIRTY_TIME
}

/// The dirty bits a writeback pass harvests and clears from `i_state`
/// (`dirty = inode->i_state & I_DIRTY`). `I_DIRTY_TIME` is NOT in it: it is
/// resolved before this point by the lazytime conversion, never dropped.
/// # C: O(1)
pub fn harvest_dirty(state: u32) -> u32 { state & I_DIRTY }

/// True iff `I_DIRTY_SYNC` is the bit a timestamp change earns here, i.e. the
/// superblock is NOT lazytime — the eager path, unchanged from before the
/// deferral existed. # C: O(1)
pub fn is_eager_timestamp(lazytime: bool) -> bool { time_dirty_flag(lazytime) == I_DIRTY_SYNC }
