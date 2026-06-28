//! atime-update policy (Linux fs/inode.c `atime_needs_update` /
//! `relatime_need_update`). Validates the three mount modes — relatime (update
//! only if atime<=ctime/mtime or >24h stale), noatime (never), strictatime
//! (always, subject to the noatime gates + equality) — plus the per-inode
//! S_NOATIME, RO-superblock, and nodiratime short-circuits. Pure value math;
//! no global state, no SERIAL guard needed.

use vfs::inode_times::{atime_needs_update, relatime_need_update, AtimeCtx, RELATIME_MAX_AGE_NS};
use vfs::mount::{MNT_NOATIME, MNT_NODIRATIME, MNT_RELATIME, MNT_STRICTATIME};
use vfs::superblock::{NSEC_PER_SEC, SB_NOATIME, SB_NODIRATIME, SB_RDONLY};

const SEC: u64 = NSEC_PER_SEC;

/// Base ctx: relatime mount, clean sb, regular file. atime far in the past so
/// the per-mode logic is the only thing under test.
fn base() -> AtimeCtx {
    AtimeCtx {
        mnt_flags: MNT_RELATIME,
        sb_flags: 0,
        inode_noatime: false,
        is_dir: false,
        atime_ns: 100 * SEC,
        mtime_ns: 50 * SEC,
        ctime_ns: 50 * SEC,
    }
}

// ---- relatime ----

#[test]
fn relatime_skips_when_atime_newer_than_mtime_ctime_and_fresh() {
    let c = base(); // atime=100 > mtime=ctime=50, now within the day
    let now = 100 * SEC + 1; // distinct from atime, < 24h after
    assert!(!atime_needs_update(&c, now),
        "relatime skips: atime already past mtime/ctime and < 24h stale");
}

#[test]
fn relatime_updates_when_mtime_ge_atime() {
    let mut c = base();
    c.mtime_ns = c.atime_ns; // mtime >= atime → file modified since last read
    let now = 200 * SEC;
    assert!(atime_needs_update(&c, now), "relatime updates when mtime>=atime");
}

#[test]
fn relatime_updates_when_ctime_ge_atime() {
    let mut c = base();
    c.ctime_ns = c.atime_ns + SEC; // metadata changed since last read
    let now = 200 * SEC;
    assert!(atime_needs_update(&c, now), "relatime updates when ctime>=atime");
}

#[test]
fn relatime_updates_when_atime_older_than_a_day() {
    let c = base(); // atime=100s, mtime/ctime older
    let now = 100 * SEC + RELATIME_MAX_AGE_NS; // exactly 24h later
    assert!(atime_needs_update(&c, now), "relatime updates once atime is >=24h stale");
    let now_just_under = 100 * SEC + RELATIME_MAX_AGE_NS - 1;
    assert!(!atime_needs_update(&c, now_just_under),
        "just under 24h with fresh mtime/ctime still skips");
}

#[test]
fn relatime_need_update_helper_matches_branches() {
    // mtime>=atime
    assert!(relatime_need_update(MNT_RELATIME, 100, 100, 0, 100));
    // ctime>=atime
    assert!(relatime_need_update(MNT_RELATIME, 100, 0, 100, 100));
    // none stale, under a day → skip
    assert!(!relatime_need_update(MNT_RELATIME, 100 * SEC, 50 * SEC, 50 * SEC, 100 * SEC + 1));
    // backwards clock (now < atime) never forces a stale-update
    assert!(!relatime_need_update(MNT_RELATIME, 100 * SEC, 50 * SEC, 50 * SEC, 10 * SEC));
}

// ---- noatime ----

#[test]
fn noatime_mount_never_updates() {
    let mut c = base();
    c.mnt_flags = MNT_NOATIME;
    c.mtime_ns = c.atime_ns; // would otherwise force an update under relatime
    assert!(!atime_needs_update(&c, 1_000 * SEC), "MNT_NOATIME suppresses all atime updates");
}

#[test]
fn inode_noatime_flag_never_updates() {
    let mut c = base();
    c.mnt_flags = MNT_STRICTATIME;
    c.inode_noatime = true;
    assert!(!atime_needs_update(&c, 1_000 * SEC), "per-inode S_NOATIME wins over strictatime");
}

#[test]
fn readonly_or_noatime_superblock_never_updates() {
    let mut c = base();
    c.mnt_flags = MNT_STRICTATIME;
    c.sb_flags = SB_RDONLY;
    assert!(!atime_needs_update(&c, 1_000 * SEC), "RO superblock never advances atime");
    c.sb_flags = SB_NOATIME;
    assert!(!atime_needs_update(&c, 1_000 * SEC), "SB_NOATIME never advances atime");
}

// ---- strictatime ----

#[test]
fn strictatime_always_updates_regardless_of_relation() {
    let mut c = base(); // atime newer than mtime/ctime, fresh
    c.mnt_flags = MNT_STRICTATIME;
    let now = 100 * SEC + 1; // distinct from atime
    assert!(atime_needs_update(&c, now),
        "strictatime updates even when relatime would skip");
}

#[test]
fn strictatime_skips_only_on_equal_timestamp() {
    let mut c = base();
    c.mnt_flags = MNT_STRICTATIME;
    assert!(!atime_needs_update(&c, c.atime_ns),
        "no write when the candidate equals the stored atime");
}

// ---- nodiratime ----

#[test]
fn nodiratime_suppresses_dirs_only() {
    let mut c = base();
    c.mnt_flags = MNT_STRICTATIME | MNT_NODIRATIME;
    let now = 100 * SEC + 1;
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
    let now = 100 * SEC + 1;
    c.is_dir = true;
    assert!(!atime_needs_update(&c, now), "SB_NODIRATIME suppresses directory atime");
    c.is_dir = false;
    assert!(atime_needs_update(&c, now), "SB_NODIRATIME leaves regular files updating");
}
