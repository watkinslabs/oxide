//! Pure writeback/lazytime decision ladder (Linux fs/fs-writeback.c
//! `__mark_inode_dirty` state machine, fs/inode.c `inode_time_dirty_flag`,
//! `dirtytime_expire_interval`). No inode, no superblock — the arithmetic only.
//!
//! The `lazytime_writeback.rs` sibling proves the ladder is WIRED and that a
//! deferred stamp survives to the backing store; this file pins the rules it is
//! wired to.

use vfs::inode::{I_DIRTY_DATASYNC, I_DIRTY_PAGES, I_DIRTY_SYNC, I_DIRTY_TIME, I_FREEING, I_NEW};
use vfs::writeback::policy::{
    dirtytime_expired, forces_lazytime, harvest_dirty, is_dirtytime_only, mark_dirty_transition,
    needs_write_inode, time_dirty_flag, DIRTYTIME_EXPIRE_SECS, NSEC_PER_SEC,
};

/// The one bit the mount option buys: a pure timestamp change is deferred under
/// lazytime and ordinary metadata dirt otherwise.
#[test]
fn time_dirty_flag_is_the_whole_mount_option() {
    assert_eq!(time_dirty_flag(true), I_DIRTY_TIME);
    assert_eq!(time_dirty_flag(false), I_DIRTY_SYNC);
}

/// A timestamp-only dirtying on a clean inode starts the deferral AND the
/// expiry clock, and owes the backend no `dirty_inode` notification — nothing
/// has changed that a journal needs to hear about yet.
#[test]
fn lazy_stamp_on_a_clean_inode_starts_the_deferral() {
    let t = mark_dirty_transition(0, I_DIRTY_TIME);
    assert_eq!(t.set, I_DIRTY_TIME);
    assert_eq!(t.clear, 0);
    assert_eq!(t.notify, 0, "no dirty_inode call for a pure timestamp");
    assert!(t.changed);
    assert!(t.stamp, "expiry clock starts here");
}

/// Re-dirtying a still-deferred timestamp must NOT push the deadline out —
/// otherwise a file read once a second would defer its atime forever.
#[test]
fn re_dirtying_a_deferral_does_not_restart_the_expiry_clock() {
    let t = mark_dirty_transition(I_DIRTY_TIME, I_DIRTY_TIME);
    assert!(!t.changed, "the bit is already set");
    assert!(!t.stamp, "and the clock is left alone");
}

/// `I_DIRTY_INODE` SUPERSEDES `I_DIRTY_TIME`: the bit is cleared, but it is
/// folded into the `dirty_inode` notification so the backend writes the
/// timestamps out with whatever else changed. Dropping it silently instead is
/// precisely how a lazytime implementation loses an atime.
#[test]
fn a_real_change_supersedes_the_deferral_and_carries_it_in_the_notification() {
    let t = mark_dirty_transition(I_DIRTY_TIME, I_DIRTY_SYNC);
    assert_eq!(t.clear, I_DIRTY_TIME, "deferral resolved");
    assert_eq!(t.set, I_DIRTY_SYNC, "and not re-latched as a time bit");
    assert_eq!(t.notify, I_DIRTY_SYNC | I_DIRTY_TIME,
        "backend told the timestamps need writing too");
}

/// With no deferral pending the same call carries no timestamp bit.
#[test]
fn a_real_change_without_a_deferral_notifies_only_its_own_bits() {
    let t = mark_dirty_transition(0, I_DIRTY_DATASYNC);
    assert_eq!(t.clear, 0);
    assert_eq!(t.notify, I_DIRTY_DATASYNC);
    assert_eq!(t.set, I_DIRTY_DATASYNC);
}

/// A deferral may begin over an `I_DIRTY_SYNC` that is already in flight
/// (writeback may have harvested the old stamp already), but the expiry clock
/// is not started for it — the inode is already on the dirty list.
#[test]
fn a_deferral_over_an_in_flight_sync_bit_does_not_start_the_clock() {
    let t = mark_dirty_transition(I_DIRTY_SYNC, I_DIRTY_TIME);
    assert_eq!(t.set, I_DIRTY_TIME, "the newer stamp is still recorded");
    assert!(!t.stamp, "but the inode was already dirty");
}

/// Page dirt alone neither notifies the backend nor touches the deferral.
#[test]
fn page_dirt_leaves_a_deferral_untouched() {
    let t = mark_dirty_transition(I_DIRTY_TIME, I_DIRTY_PAGES);
    assert_eq!(t.clear, 0);
    assert_eq!(t.notify, 0);
    assert_eq!(t.set, I_DIRTY_PAGES);
}

/// Lifecycle bits are not a dirtying channel.
#[test]
fn lifecycle_bits_cannot_be_smuggled_through_the_dirty_path() {
    let t = mark_dirty_transition(0, I_NEW | I_FREEING | I_DIRTY_SYNC);
    assert_eq!(t.set, I_DIRTY_SYNC);
}

/// `s_op->write_inode` is owed for inode dirt, not for page dirt.
#[test]
fn write_inode_is_owed_only_for_inode_dirt() {
    assert!(needs_write_inode(I_DIRTY_SYNC));
    assert!(needs_write_inode(I_DIRTY_DATASYNC));
    assert!(!needs_write_inode(I_DIRTY_PAGES));
    assert!(!needs_write_inode(0));
}

/// The harvest never includes the deferral bit: it is resolved by the lazytime
/// conversion ahead of the harvest, never cleared as if it had been written.
#[test]
fn the_dirty_harvest_never_swallows_the_deferral_bit() {
    let dirty = harvest_dirty(I_DIRTY_SYNC | I_DIRTY_PAGES | I_DIRTY_TIME);
    assert_eq!(dirty, I_DIRTY_SYNC | I_DIRTY_PAGES);
}

/// Expiry: `0` means no deferral pending, and the deadline is exactly the
/// interval past the moment the deferral began.
#[test]
fn expiry_is_the_interval_past_the_start_of_the_deferral() {
    let when = 1_000 * NSEC_PER_SEC;
    let deadline = when + DIRTYTIME_EXPIRE_SECS * NSEC_PER_SEC;
    assert!(!dirtytime_expired(0, deadline, DIRTYTIME_EXPIRE_SECS), "nothing pending");
    assert!(!dirtytime_expired(when, deadline - 1, DIRTYTIME_EXPIRE_SECS), "one ns short");
    assert!(dirtytime_expired(when, deadline, DIRTYTIME_EXPIRE_SECS), "exactly due");
    assert!(dirtytime_expired(when, deadline + 1, DIRTYTIME_EXPIRE_SECS));
}

/// A clock reading before the deferral started (a stamp from the future) must
/// not wrap into an immediate expiry.
#[test]
fn a_future_deferral_stamp_does_not_wrap_into_an_expiry() {
    assert!(!dirtytime_expired(u64::MAX, 1, DIRTYTIME_EXPIRE_SECS));
    assert!(!dirtytime_expired(10 * NSEC_PER_SEC, 1, DIRTYTIME_EXPIRE_SECS));
}

/// A data-integrity pass forces regardless of age; a background pass only
/// forces what has expired. That asymmetry is what makes lazytime both safe and
/// worth having.
#[test]
fn only_a_data_integrity_pass_forces_a_fresh_deferral() {
    let when = 1_000 * NSEC_PER_SEC;
    assert!(forces_lazytime(true, when, when, DIRTYTIME_EXPIRE_SECS), "sync forces at once");
    assert!(!forces_lazytime(false, when, when, DIRTYTIME_EXPIRE_SECS), "background waits");
    let late = when + (DIRTYTIME_EXPIRE_SECS + 1) * NSEC_PER_SEC;
    assert!(forces_lazytime(false, when, late, DIRTYTIME_EXPIRE_SECS), "…until it expires");
}

/// `inode_is_dirtytime_only`: the state in which a filesystem may write the
/// timestamps out opportunistically alongside a neighbouring inode. The mask
/// covers the deferral bit and the LIFECYCLE bits only — a concurrently set
/// `I_DIRTY_SYNC` does NOT disqualify it (the timestamps are still worth
/// piggybacking), while an inode being created or destroyed does.
#[test]
fn dirtytime_only_excludes_the_lifecycle_states() {
    assert!(is_dirtytime_only(I_DIRTY_TIME));
    assert!(is_dirtytime_only(I_DIRTY_TIME | I_DIRTY_SYNC));
    assert!(!is_dirtytime_only(0), "no deferral, nothing to piggyback");
    assert!(!is_dirtytime_only(I_DIRTY_TIME | I_NEW));
    assert!(!is_dirtytime_only(I_DIRTY_TIME | I_FREEING));
}
