use super::*;

const GRACE: u64 = 604_800;
const NOW: u64 = 1_000_000;

fn info() -> MemDqinfo {
    MemDqinfo { dqi_bgrace: GRACE, dqi_igrace: GRACE, ..MemDqinfo::default() }
}

fn ctx() -> ChargeCtx {
    ChargeCtx { info: info(), now_sec: NOW, enforced: true, ignore_hardlimit: false }
}

fn blk(hard: u64, soft: u64, cur: u64, rsv: u64) -> MemDqblk {
    MemDqblk { dqb_bhardlimit: hard, dqb_bsoftlimit: soft, dqb_curspace: cur, dqb_rsvspace: rsv, ..MemDqblk::new() }
}

fn ino(hard: u64, soft: u64, cur: u64) -> MemDqblk {
    MemDqblk { dqb_ihardlimit: hard, dqb_isoftlimit: soft, dqb_curinodes: cur, ..MemDqblk::new() }
}

// ---- hard limit ---------------------------------------------------------

#[test]
fn space_hard_limit_admits_exactly_up_to_the_limit() {
    let out = add_space(blk(1000, 0, 900, 0), 100, 0, DQUOT_SPACE_WARN, ctx());
    assert_eq!(out.result, Ok(()));
    assert_eq!(out.dqblk.dqb_curspace, 1000);
    assert_eq!(out.warn, QuotaWarnType::NoWarn);
}

#[test]
fn space_past_hard_limit_is_edquot_and_leaves_counters_untouched() {
    let out = add_space(blk(1000, 0, 900, 0), 101, 0, DQUOT_SPACE_WARN, ctx());
    assert_eq!(out.result, Err(VfsError::Edquot));
    assert_eq!(out.dqblk.dqb_curspace, 900);
    assert_eq!(out.warn, QuotaWarnType::BHardWarn);
}

// The hard limit governs used PLUS reserved space, not each independently.
// A reservation that fits on its own must still fail once the combined total
// crosses the limit, and vice versa.
#[test]
fn reserved_space_counts_toward_the_block_hard_limit() {
    let out = add_space(blk(1000, 0, 0, 900), 0, 101, DQUOT_SPACE_WARN, ctx());
    assert_eq!(out.result, Err(VfsError::Edquot));
    assert_eq!(out.dqblk.dqb_rsvspace, 900);
}

#[test]
fn existing_reservation_blocks_a_later_real_allocation() {
    let out = add_space(blk(1000, 0, 500, 400), 200, 0, DQUOT_SPACE_WARN, ctx());
    assert_eq!(out.result, Err(VfsError::Edquot));
    assert_eq!(out.dqblk.dqb_curspace, 500);
}

#[test]
fn existing_usage_blocks_a_later_reservation() {
    let out = add_space(blk(1000, 0, 900, 0), 0, 200, DQUOT_SPACE_WARN, ctx());
    assert_eq!(out.result, Err(VfsError::Edquot));
    assert_eq!(out.dqblk.dqb_rsvspace, 0);
}

#[test]
fn zero_hard_limit_means_unlimited() {
    let out = add_space(blk(0, 0, u64::MAX / 2, 0), 1 << 40, 0, DQUOT_SPACE_WARN, ctx());
    assert_eq!(out.result, Ok(()));
}

// ---- privileged limit override -----------------------------------------

// CAP_SYS_RESOURCE lets a privileged task push past both the hard limit and
// an expired soft-limit grace period; it does NOT suppress the first
// soft-limit crossing, which still starts the grace timer and warns.
#[test]
fn ignore_hardlimit_allows_exceeding_the_block_hard_limit() {
    let mut c = ctx();
    c.ignore_hardlimit = true;
    let out = add_space(blk(1000, 0, 900, 0), 500, 0, DQUOT_SPACE_WARN, c);
    assert_eq!(out.result, Ok(()));
    assert_eq!(out.dqblk.dqb_curspace, 1400);
    assert_eq!(out.warn, QuotaWarnType::NoWarn);
}

#[test]
fn ignore_hardlimit_allows_exceeding_an_expired_block_grace() {
    let mut c = ctx();
    c.ignore_hardlimit = true;
    let dq = MemDqblk { dqb_btime: (NOW - 1) as i64, ..blk(0, 1000, 1100, 0) };
    let out = add_space(dq, 100, 0, DQUOT_SPACE_WARN, c);
    assert_eq!(out.result, Ok(()));
    assert_eq!(out.dqblk.dqb_curspace, 1200);
}

#[test]
fn ignore_hardlimit_still_starts_the_soft_grace_timer() {
    let mut c = ctx();
    c.ignore_hardlimit = true;
    let out = add_space(blk(0, 1000, 900, 0), 200, 0, DQUOT_SPACE_WARN, c);
    assert_eq!(out.result, Ok(()));
    assert_eq!(out.warn, QuotaWarnType::BSoftWarn);
    assert_eq!(out.dqblk.dqb_btime, (NOW + GRACE) as i64);
}

#[test]
fn ignore_hardlimit_allows_exceeding_the_inode_hard_limit() {
    let mut c = ctx();
    c.ignore_hardlimit = true;
    let out = add_inodes(ino(10, 0, 10), 5, c);
    assert_eq!(out.result, Ok(()));
    assert_eq!(out.dqblk.dqb_curinodes, 15);
}

// ---- soft limit + grace -------------------------------------------------

#[test]
fn crossing_the_soft_limit_starts_the_grace_timer_and_allows_the_write() {
    let out = add_space(blk(0, 1000, 900, 0), 200, 0, DQUOT_SPACE_WARN, ctx());
    assert_eq!(out.result, Ok(()));
    assert_eq!(out.warn, QuotaWarnType::BSoftWarn);
    assert_eq!(out.dqblk.dqb_btime, (NOW + GRACE) as i64);
    assert_eq!(out.dqblk.dqb_curspace, 1100);
}

#[test]
fn over_soft_limit_within_grace_still_allows_the_write() {
    let dq = MemDqblk { dqb_btime: (NOW + 100) as i64, ..blk(0, 1000, 1100, 0) };
    let out = add_space(dq, 50, 0, DQUOT_SPACE_WARN, ctx());
    assert_eq!(out.result, Ok(()));
    assert_eq!(out.warn, QuotaWarnType::NoWarn);
    assert_eq!(out.dqblk.dqb_btime, (NOW + 100) as i64);
}

#[test]
fn over_soft_limit_after_grace_expiry_is_edquot() {
    let dq = MemDqblk { dqb_btime: NOW as i64, ..blk(0, 1000, 1100, 0) };
    let out = add_space(dq, 50, 0, DQUOT_SPACE_WARN, ctx());
    assert_eq!(out.result, Err(VfsError::Edquot));
    assert_eq!(out.warn, QuotaWarnType::BSoftLongWarn);
    assert_eq!(out.dqblk.dqb_curspace, 1100);
}

#[test]
fn hard_limit_is_checked_before_the_soft_grace_ladder() {
    let dq = MemDqblk { dqb_btime: NOW as i64, ..blk(1200, 1000, 1100, 0) };
    let out = add_space(dq, 500, 0, DQUOT_SPACE_WARN, ctx());
    assert_eq!(out.result, Err(VfsError::Edquot));
    assert_eq!(out.warn, QuotaWarnType::BHardWarn);
}

// ---- preallocation arm --------------------------------------------------

// Without DQUOT_SPACE_WARN the caller is preallocating: crossing the soft
// limit is refused outright instead of starting a grace period.
#[test]
fn prealloc_may_not_cross_the_soft_limit() {
    let out = add_space(blk(0, 1000, 900, 0), 0, 200, DQUOT_SPACE_RESERVE, ctx());
    assert_eq!(out.result, Err(VfsError::Edquot));
    assert_eq!(out.dqblk.dqb_btime, 0);
    assert_eq!(out.dqblk.dqb_rsvspace, 0);
}

#[test]
fn prealloc_under_the_soft_limit_succeeds() {
    let out = add_space(blk(0, 1000, 500, 0), 0, 400, DQUOT_SPACE_RESERVE, ctx());
    assert_eq!(out.result, Ok(()));
    assert_eq!(out.dqblk.dqb_rsvspace, 400);
}

#[test]
fn prealloc_hard_limit_failure_raises_no_warning() {
    let out = add_space(blk(1000, 0, 900, 0), 0, 500, DQUOT_SPACE_RESERVE, ctx());
    assert_eq!(out.result, Err(VfsError::Edquot));
    assert_eq!(out.warn, QuotaWarnType::NoWarn);
}

// ---- nofail -------------------------------------------------------------

// NOFAIL suppresses the failure but still runs warning + grace generation,
// so the timer is armed and the counters move.
#[test]
fn nofail_charges_past_the_hard_limit() {
    let out = add_space(blk(1000, 0, 900, 0), 500, 0, DQUOT_SPACE_WARN | DQUOT_SPACE_NOFAIL, ctx());
    assert_eq!(out.result, Ok(()));
    assert_eq!(out.dqblk.dqb_curspace, 1400);
    assert_eq!(out.warn, QuotaWarnType::BHardWarn);
}

#[test]
fn nofail_still_arms_the_soft_grace_timer() {
    let out = add_space(blk(0, 1000, 900, 0), 200, 0, DQUOT_SPACE_WARN | DQUOT_SPACE_NOFAIL, ctx());
    assert_eq!(out.dqblk.dqb_btime, (NOW + GRACE) as i64);
}

// ---- accounting-only ----------------------------------------------------

#[test]
fn accounting_only_class_never_refuses_a_charge() {
    let mut c = ctx();
    c.enforced = false;
    let out = add_space(blk(1000, 500, 900, 0), 5000, 0, DQUOT_SPACE_WARN, c);
    assert_eq!(out.result, Ok(()));
    assert_eq!(out.dqblk.dqb_curspace, 5900);
    assert_eq!(out.dqblk.dqb_btime, 0);
    assert_eq!(out.warn, QuotaWarnType::NoWarn);
}

#[test]
fn a_record_with_no_limits_skips_the_ladder_entirely() {
    let out = add_space(blk(0, 0, 0, 0), u64::MAX / 4, 0, DQUOT_SPACE_WARN, ctx());
    assert_eq!(out.result, Ok(()));
}

// ---- inodes -------------------------------------------------------------

#[test]
fn inode_hard_limit_admits_up_to_the_limit_then_refuses() {
    assert_eq!(add_inodes(ino(10, 0, 9), 1, ctx()).result, Ok(()));
    let out = add_inodes(ino(10, 0, 10), 1, ctx());
    assert_eq!(out.result, Err(VfsError::Edquot));
    assert_eq!(out.warn, QuotaWarnType::IHardWarn);
    assert_eq!(out.dqblk.dqb_curinodes, 10);
}

#[test]
fn inode_soft_crossing_starts_grace_and_expiry_refuses() {
    let out = add_inodes(ino(0, 5, 5), 1, ctx());
    assert_eq!(out.result, Ok(()));
    assert_eq!(out.warn, QuotaWarnType::ISoftWarn);
    assert_eq!(out.dqblk.dqb_itime, (NOW + GRACE) as i64);

    let expired = MemDqblk { dqb_itime: NOW as i64, ..ino(0, 5, 6) };
    let out = add_inodes(expired, 1, ctx());
    assert_eq!(out.result, Err(VfsError::Edquot));
    assert_eq!(out.warn, QuotaWarnType::ISoftLongWarn);
}

// Preallocation flags have no inode analogue: inode charges always take the
// warn-and-grace arm.
#[test]
fn inode_soft_crossing_warns_regardless_of_space_flags() {
    let out = add_inodes(ino(0, 5, 5), 1, ctx());
    assert_eq!(out.warn, QuotaWarnType::ISoftWarn);
}

// ---- release ladder + below warnings ------------------------------------

#[test]
fn dropping_below_the_soft_limit_clears_the_block_grace_timer() {
    let dq = MemDqblk { dqb_btime: (NOW + GRACE) as i64, ..blk(0, 1000, 1100, 0) };
    let next = decr_space(dq, 200);
    assert_eq!(next.dqb_curspace, 900);
    assert_eq!(next.dqb_btime, 0);
}

// Reserved space keeps the grace timer armed: the combined total is what the
// soft limit measures.
#[test]
fn reserved_space_keeps_the_block_grace_timer_armed() {
    let dq = MemDqblk { dqb_btime: (NOW + GRACE) as i64, ..blk(0, 1000, 1100, 500) };
    let next = decr_space(dq, 200);
    assert_eq!(next.dqb_btime, (NOW + GRACE) as i64);
}

#[test]
fn freeing_reservation_below_the_soft_limit_clears_the_timer() {
    let dq = MemDqblk { dqb_btime: (NOW + GRACE) as i64, ..blk(0, 1000, 900, 500) };
    let next = free_reserved_space(dq, 500);
    assert_eq!(next.dqb_rsvspace, 0);
    assert_eq!(next.dqb_btime, 0);
}

#[test]
fn dropping_below_the_inode_soft_limit_clears_the_inode_timer() {
    let dq = MemDqblk { dqb_itime: (NOW + GRACE) as i64, ..ino(0, 5, 6) };
    let next = decr_inodes(dq, 2);
    assert_eq!(next.dqb_curinodes, 4);
    assert_eq!(next.dqb_itime, 0);
}

#[test]
fn below_soft_and_below_hard_warning_classes() {
    assert_eq!(bdq_free_warn(blk(0, 1000, 1100, 0), 200, true), QuotaWarnType::BSoftBelow);
    assert_eq!(bdq_free_warn(blk(1000, 0, 1000, 0), 200, true), QuotaWarnType::BHardBelow);
    assert_eq!(bdq_free_warn(blk(0, 1000, 900, 0), 200, true), QuotaWarnType::NoWarn);
    assert_eq!(bdq_free_warn(blk(0, 1000, 1100, 0), 200, false), QuotaWarnType::NoWarn);

    assert_eq!(idq_free_warn(ino(0, 5, 7), 3, true), QuotaWarnType::ISoftBelow);
    assert_eq!(idq_free_warn(ino(10, 0, 10), 3, true), QuotaWarnType::IHardBelow);
    assert_eq!(idq_free_warn(ino(0, 5, 4), 1, true), QuotaWarnType::NoWarn);
}

// The below-warning is computed against the pre-drop record, so reserved
// space participates in the block total the same way it does on charge.
#[test]
fn below_warning_uses_the_combined_space_total() {
    assert_eq!(bdq_free_warn(blk(0, 1000, 600, 600), 300, true), QuotaWarnType::BSoftBelow);
}

// ---- reservation conversion --------------------------------------------

#[test]
fn claim_moves_reserved_space_into_used_space() {
    let next = claim_space(blk(0, 0, 100, 400), 300);
    assert_eq!(next.dqb_curspace, 400);
    assert_eq!(next.dqb_rsvspace, 100);
}

#[test]
fn claim_is_clamped_to_the_reservation() {
    let next = claim_space(blk(0, 0, 100, 200), 500);
    assert_eq!(next.dqb_curspace, 300);
    assert_eq!(next.dqb_rsvspace, 0);
}

#[test]
fn reclaim_moves_used_space_back_into_reservation() {
    let next = reclaim_space(blk(0, 0, 400, 100), 300);
    assert_eq!(next.dqb_curspace, 100);
    assert_eq!(next.dqb_rsvspace, 400);
}

#[test]
fn reclaim_is_clamped_to_used_space() {
    let next = reclaim_space(blk(0, 0, 200, 0), 500);
    assert_eq!(next.dqb_curspace, 0);
    assert_eq!(next.dqb_rsvspace, 200);
}

// Claiming a reservation never changes the combined total, so it can never
// newly cross a limit that the reservation had not already accounted for.
#[test]
fn claim_preserves_the_combined_space_total() {
    let before = blk(1000, 0, 100, 400);
    let after = claim_space(before, 400);
    assert_eq!(before.dqb_curspace + before.dqb_rsvspace, after.dqb_curspace + after.dqb_rsvspace);
}

// ---- negative-time grace ------------------------------------------------

// A negative on-disk grace deadline is always treated as expired rather than
// wrapping into a huge future time.
#[test]
fn negative_grace_deadline_counts_as_expired() {
    let dq = MemDqblk { dqb_btime: -1, ..blk(0, 1000, 1100, 0) };
    let out = add_space(dq, 50, 0, DQUOT_SPACE_WARN, ctx());
    assert_eq!(out.result, Err(VfsError::Edquot));
}

#[test]
fn grace_deadline_saturates_instead_of_wrapping() {
    let c = ChargeCtx { info: MemDqinfo { dqi_bgrace: u64::MAX, ..MemDqinfo::default() }, now_sec: NOW, enforced: true, ignore_hardlimit: false };
    let out = add_space(blk(0, 1000, 900, 0), 200, 0, DQUOT_SPACE_WARN, c);
    assert_eq!(out.dqblk.dqb_btime, i64::MAX);
}
