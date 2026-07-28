//! atime-update policy (Linux fs/inode.c `atime_needs_update` /
//! `relatime_need_update`). Validates the three mount modes — relatime (update
//! only if atime<=ctime/mtime or >24h stale), noatime (never), strictatime
//! (always, subject to the noatime gates + equality) — plus the per-inode
//! S_NOATIME, RO-superblock, and nodiratime short-circuits. Pure value math;
//! no global state, no SERIAL guard needed.

use vfs::inode_times::{atime_needs_update, relatime_need_update, AtimeCtx, RELATIME_MAX_AGE_SECS};
use vfs::mount::{MNT_NOATIME, MNT_NODIRATIME, MNT_RELATIME, MNT_STRICTATIME};
use vfs::superblock::{SB_NOATIME, SB_NODIRATIME, SB_RDONLY};
use vfs::Timespec64;

/// Whole-second instant. The relatime window is compared in SECONDS (Linux
/// `(long)(now.tv_sec - atime.tv_sec) >= 24*60*60`), so these tests work at
/// second scale with an explicit sub-second field where one matters.
fn ts(sec: i64) -> Timespec64 { Timespec64::from_secs(sec) }

/// Base ctx: relatime mount, clean sb, regular file. atime far in the past so
/// the per-mode logic is the only thing under test.
fn base() -> AtimeCtx {
    AtimeCtx {
        mnt_flags: MNT_RELATIME,
        sb_flags: 0,
        inode_noatime: false,
        is_dir: false,
        atime: ts(100),
        mtime: ts(50),
        ctime: ts(50),
    }
}

// ---- relatime ----

#[test]
fn relatime_skips_when_atime_newer_than_mtime_ctime_and_fresh() {
    let c = base(); // atime=100 > mtime=ctime=50, now within the day
    let now = Timespec64::new(100, 1); // distinct from atime, < 24h after
    assert!(!atime_needs_update(&c, now),
        "relatime skips: atime already past mtime/ctime and < 24h stale");
}

#[test]
fn relatime_updates_when_mtime_ge_atime() {
    let mut c = base();
    c.mtime = c.atime; // mtime >= atime → file modified since last read
    let now = ts(200);
    assert!(atime_needs_update(&c, now), "relatime updates when mtime>=atime");
}

#[test]
fn relatime_updates_when_ctime_ge_atime() {
    let mut c = base();
    c.ctime = ts(c.atime.sec + 1); // metadata changed since last read
    let now = ts(200);
    assert!(atime_needs_update(&c, now), "relatime updates when ctime>=atime");
}

#[test]
fn relatime_updates_when_atime_older_than_a_day() {
    let c = base(); // atime=100s, mtime/ctime older
    let now = ts(100 + RELATIME_MAX_AGE_SECS); // exactly 24h later
    assert!(atime_needs_update(&c, now), "relatime updates once atime is >=24h stale");
    let now_just_under = Timespec64::new(100 + RELATIME_MAX_AGE_SECS - 1, 999_999_999);
    assert!(!atime_needs_update(&c, now_just_under),
        "just under 24h with fresh mtime/ctime still skips");
}

#[test]
fn relatime_need_update_helper_matches_branches() {
    // mtime>=atime
    assert!(relatime_need_update(MNT_RELATIME, ts(100), ts(100), ts(0), ts(100)));
    // ctime>=atime
    assert!(relatime_need_update(MNT_RELATIME, ts(100), ts(0), ts(100), ts(100)));
    // none stale, under a day → skip
    assert!(!relatime_need_update(MNT_RELATIME, ts(100), ts(50), ts(50), Timespec64::new(100, 1)));
    // backwards clock (now < atime) never forces a stale-update. Linux computes
    // a SIGNED delta here; the old unsigned model could only approximate it
    // with a `saturating_sub` floored at 0.
    assert!(!relatime_need_update(MNT_RELATIME, ts(100), ts(50), ts(50), ts(10)));
}

// ---- noatime ----

#[test]
fn noatime_mount_never_updates() {
    let mut c = base();
    c.mnt_flags = MNT_NOATIME;
    c.mtime = c.atime; // would otherwise force an update under relatime
    assert!(!atime_needs_update(&c, ts(1_000)), "MNT_NOATIME suppresses all atime updates");
}

#[test]
fn inode_noatime_flag_never_updates() {
    let mut c = base();
    c.mnt_flags = MNT_STRICTATIME;
    c.inode_noatime = true;
    assert!(!atime_needs_update(&c, ts(1_000)), "per-inode S_NOATIME wins over strictatime");
}

#[test]
fn readonly_or_noatime_superblock_never_updates() {
    let mut c = base();
    c.mnt_flags = MNT_STRICTATIME;
    c.sb_flags = SB_RDONLY;
    assert!(!atime_needs_update(&c, ts(1_000)), "RO superblock never advances atime");
    c.sb_flags = SB_NOATIME;
    assert!(!atime_needs_update(&c, ts(1_000)), "SB_NOATIME never advances atime");
}

// ---- strictatime ----

#[test]
fn strictatime_always_updates_regardless_of_relation() {
    let mut c = base(); // atime newer than mtime/ctime, fresh
    c.mnt_flags = MNT_STRICTATIME;
    let now = Timespec64::new(100, 1); // distinct from atime
    assert!(atime_needs_update(&c, now),
        "strictatime updates even when relatime would skip");
}

#[test]
fn strictatime_skips_only_on_equal_timestamp() {
    let mut c = base();
    c.mnt_flags = MNT_STRICTATIME;
    assert!(!atime_needs_update(&c, c.atime),
        "no write when the candidate equals the stored atime");
}

// ---- nodiratime ----

#[test]
fn nodiratime_suppresses_dirs_only() {
    let mut c = base();
    c.mnt_flags = MNT_STRICTATIME | MNT_NODIRATIME;
    let now = Timespec64::new(100, 1);
    c.is_dir = true;
    assert!(!atime_needs_update(&c, now), "MNT_NODIRATIME suppresses directory atime");
    c.is_dir = false;
    assert!(atime_needs_update(&c, now), "MNT_NODIRATIME leaves regular files updating");
}

#[test]
fn sb_nodiratime_suppresses_dirs_only() {
    let mut c = base();
    c.mnt_flags = MNT_STRICTATIME;
    c.sb_flags = SB_NODIRATIME;
    let now = Timespec64::new(100, 1);
    c.is_dir = true;
    assert!(!atime_needs_update(&c, now), "SB_NODIRATIME suppresses directory atime");
    c.is_dir = false;
    assert!(atime_needs_update(&c, now), "SB_NODIRATIME leaves regular files updating");
}

// ---- F767: signedness of the relatime comparisons ----

/// THE inversion an unsigned model hides. A pre-1970 atime with a post-1970
/// mtime means "the file was modified after it was last read", so relatime MUST
/// update the atime (Linux `timespec64_compare(&mtime, &atime) >= 0`).
/// As `u64` nanoseconds the negative atime reads as ~1.8e19 — GREATER than any
/// real mtime — so the comparison inverted and relatime silently skipped the
/// update forever on any file carrying a restored pre-1970 atime.
#[test]
fn relatime_compares_pre_epoch_atime_as_older_not_newer() {
    let mut c = base();
    c.atime = ts(-1_000_000);        // 1969-12-20
    c.mtime = ts(1_700_000_000);     // 2023
    c.ctime = ts(-2_000_000);
    assert!(relatime_need_update(MNT_RELATIME, c.atime, c.mtime, c.ctime, ts(1_700_000_001)),
        "mtime (2023) is newer than a pre-1970 atime → update");
    assert!(atime_needs_update(&c, ts(1_700_000_001)));
}

/// The symmetric case: both stamps pre-1970, atime the newer of the two, and
/// `now` within the day. Ordering among negatives must still work.
#[test]
fn relatime_orders_two_pre_epoch_stamps_correctly() {
    let atime = ts(-1_000_000);      // newer (closer to the epoch)
    let mtime = ts(-2_000_000);      // older
    let ctime = ts(-2_000_000);
    assert!(!relatime_need_update(MNT_RELATIME, atime, mtime, ctime, Timespec64::new(-1_000_000, 1)),
        "atime already newer than mtime/ctime and < 24h stale → skip");
    // ...and once a day has passed, the seconds delta forces the update even
    // though both operands are negative.
    assert!(relatime_need_update(MNT_RELATIME, atime, mtime, ctime,
        ts(-1_000_000 + RELATIME_MAX_AGE_SECS)),
        "24h stale in the pre-epoch range still updates");
}

/// The staleness delta is a SIGNED seconds subtraction, so a pre-epoch atime
/// against a modern `now` yields an enormous positive age — not a wrap.
#[test]
fn stale_delta_across_the_epoch_is_positive() {
    let c = AtimeCtx { atime: ts(-2_000_000_000), mtime: ts(-2_000_000_001),
                       ctime: ts(-2_000_000_001), ..base() };
    assert!(atime_needs_update(&c, ts(1_700_000_000)),
        "a 1906 atime is far more than 24h stale in 2023");
}
