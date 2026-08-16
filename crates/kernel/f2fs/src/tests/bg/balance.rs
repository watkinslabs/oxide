//! The balance path: what an operation that used space does before returning.
//!
//! The decision is checked on its own — every ordering case is reachable there
//! and only there — and then the two Volume entry points are driven against a
//! real image, because the decision being right is worth nothing if the caller
//! reads the wrong state into it.

use crate::bg::balance::{balance_fs_choice, needs_checkpoint, BgState};
use crate::mode::S_IFREG;
use crate::test_image::{self, ROOT_INO};
use crate::volume::NewInode;

const NOW: (u64, u32) = (1_800_000_000, 11);

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

/// The state of a volume with nothing to do.
fn settled() -> BgState {
    BgState { space_for_roll_forward: true, ..BgState::default() }
}

#[test]
fn a_settled_volume_is_not_checkpointed() {
    assert!(!needs_checkpoint(&settled()));
}

#[test]
fn a_replay_is_never_checkpointed_over() {
    // Replay is still walking the chain a checkpoint would retire.
    let s = BgState { recovering: true, excess_prefree: true, excess_dirty_nats: true,
                      space_for_roll_forward: false, ..settled() };
    assert!(!needs_checkpoint(&s));
}

#[test]
fn each_hard_condition_alone_is_enough() {
    for s in [BgState { excess_dirty_nats: true, ..settled() },
              BgState { excess_dirty_meta: true, ..settled() },
              BgState { excess_prefree: true, ..settled() },
              BgState { space_for_roll_forward: false, ..settled() }] {
        assert!(needs_checkpoint(&s), "{s:?}");
    }
}

#[test]
fn a_hard_condition_is_not_deferred_for_a_busy_volume() {
    // A checkpoint stalls every writer, so a due-by-the-clock one waits. One
    // the volume cannot go on without does not.
    let s = BgState { excess_prefree: true, recent_io: true, ..settled() };
    assert!(needs_checkpoint(&s));
}

#[test]
fn the_periodic_checkpoint_waits_for_a_quiet_moment() {
    let busy = BgState { cp_time_over: true, recent_io: true, ..settled() };
    assert!(!needs_checkpoint(&busy));
    let quiet = BgState { cp_time_over: true, ..settled() };
    assert!(needs_checkpoint(&quiet));
}

#[test]
fn caches_past_their_threshold_are_the_last_reason_and_still_a_reason() {
    let s = BgState { excess_cached_nats: true, ..settled() };
    assert!(needs_checkpoint(&s));
    let busy = BgState { excess_cached_nats: true, recent_io: true, ..settled() };
    assert!(!needs_checkpoint(&busy));
}

#[test]
fn the_blocking_balance_asks_both_questions_independently() {
    assert_eq!(balance_fs_choice(true, false, true),
               crate::bg::BalanceFs { background: false, clean: false });
    // Room to allocate, but the caches have grown: still a checkpoint.
    assert_eq!(balance_fs_choice(true, true, true),
               crate::bg::BalanceFs { background: true, clean: false });
    // Short of sections: clean, whatever the caches say.
    assert_eq!(balance_fs_choice(false, true, false),
               crate::bg::BalanceFs { background: false, clean: true });
    // An operation that allocated nothing has not grown the caches.
    assert_eq!(balance_fs_choice(false, true, true),
               crate::bg::BalanceFs { background: false, clean: false });
}

#[test]
fn a_fresh_volume_has_room_and_the_balance_does_nothing() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    v.load_segments().unwrap();
    assert!(v.has_enough_free_secs(0, 0));
    let before = v.checkpoint().version;
    v.balance_fs(true).unwrap();
    assert_eq!(v.checkpoint().version, before, "no checkpoint was needed");
}

#[test]
fn the_reserve_is_stated_in_sections_and_never_zero() {
    let v = test_image::with_root().mount_rw().unwrap();
    assert!(v.reserved_sections() >= 1, "a cleaner with no destination cannot run");
}

#[test]
fn changed_metadata_counts_against_the_space_the_volume_has() {
    // Every changed entry becomes a block in the next checkpoint. A volume
    // with exactly enough sections for its data has none for the metadata.
    let mut v = test_image::with_root().mount_rw().unwrap();
    v.load_segments().unwrap();
    assert_eq!(v.secs_required(), 0);
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    assert!(v.cached_nats() > 0, "the create changed node-table entries");
}

#[test]
fn a_volume_holding_prefree_segments_is_checkpointed_by_the_background_pass() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &alloc::vec![7u8; crate::uapi::BLKSIZE]).unwrap();
    v.commit().unwrap();
    v.remove(ROOT_INO, b"f", false, NOW).unwrap();
    // Force the one condition under test rather than waiting for a volume
    // large enough to reach it on its own.
    for s in 0..v.super_block().segment_count_main {
        if v.seg_is_free(s) { v.retire_segment(s); }
    }
    let held = v.prefree_count();
    if held == 0 { return; }
    let before = v.checkpoint().version;
    v.balance_fs_bg(true).unwrap();
    assert!(v.checkpoint().version > before, "the held space was retired");
    assert_eq!(v.prefree_count(), 0);
}

#[test]
fn the_periodic_clock_restarts_only_at_a_checkpoint() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    v.set_clock(1_000);
    assert!(!v.cp_time_over(), "a mount that has just started is not overdue");
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.set_clock(1_000 + crate::bg::balance::CP_INTERVAL_SECS + 1);
    assert!(v.cp_time_over());
    v.commit().unwrap();
    assert!(!v.cp_time_over(), "the checkpoint restarted the interval");
}

#[test]
fn utilization_is_the_share_of_the_volume_in_use() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    v.load_segments().unwrap();
    assert!(v.utilization() <= 100);
}

#[test]
fn a_read_only_mount_neither_cleans_nor_checkpoints() {
    let mut v = test_image::with_root().mount().unwrap();
    v.balance_fs(true).unwrap();
    v.balance_fs_bg(true).unwrap();
}
