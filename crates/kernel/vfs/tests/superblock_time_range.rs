//! superblock: `s_time_min`/`s_time_max` epoch-window clamp (the
//! `timestamp_truncate` contract). A backend whose on-disk timestamp field
//! is narrower than `time64_t` (ext4 32-bit = 1901..2446) publishes its window
//! via `set_time_range`; `timestamp_truncate` then pins an out-of-window setattr
//! time to the nearest boundary second (sub-second field zeroed), so an
//! over-the-cap mtime is never wrapped onto disk. With the default
//! `TIME64_MIN`/`TIME64_MAX` window the clamp is a no-op — the granularity-only
//! behaviour the pre-existing `superblock_time_gran` tests assert is preserved.
//!
//! The range rule is a CLAMP, never an error: Linux caps at the filesystem
//! boundary and lets the syscall succeed, which is why `utimensat` carries no
//! seconds-range check at all (only `tv_nsec` is validated).

use std::sync::Arc;

mod common;

use vfs::fs::FileSystem;
use vfs::superblock::{TIME64_MAX, TIME64_MIN};
use vfs::timespec::NSEC_PER_SEC;
use vfs::{SuperBlock, Timespec64};

struct TFs;
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
}

fn sb() -> Arc<SuperBlock> {
    common::realize_sb(Arc::new(TFs), None, 0x55, String::from("tfs"))
}

#[test]
fn default_range_is_full_time64() {
    let sb = sb();
    assert_eq!(sb.s_time_min(), TIME64_MIN, "fresh SB defaults to the widest floor");
    assert_eq!(sb.s_time_max(), TIME64_MAX, "fresh SB defaults to the widest ceiling");
    // A far-future timestamp passes through unclamped under the default window.
    let t = Timespec64::new(9_000_000_000, 5);
    assert_eq!(sb.timestamp_truncate(t), t, "default window never clamps");
}

/// F767: the default window is `TIME64_MIN..TIME64_MAX`, so it must pass a
/// timestamp BEYOND what a 64-bit nanosecond scalar can express — the reason
/// the VFS model is a `(sec, nsec)` pair and not an `i64` of ns.
#[test]
fn default_range_passes_times_outside_the_nanosecond_window() {
    let sb = sb();
    // Year ~2446 — ext4's own `s_time_max`; 1.5e19 ns, past `i64::MAX` ns.
    let ext4_max = Timespec64::from_secs(((1i64 << 34) - 1) + i32::MIN as i64);
    assert_eq!(ext4_max.checked_to_ns(), None, "outside the ns-scalar window");
    assert_eq!(sb.timestamp_truncate(ext4_max), ext4_max, "still representable and unclamped");
    // And the symmetric deep-past case.
    let deep_past = Timespec64::from_secs(-30_000_000_000);
    assert_eq!(deep_past.checked_to_ns(), None);
    assert_eq!(sb.timestamp_truncate(deep_past), deep_past);
}

#[test]
fn over_max_clamps_down_to_boundary_second() {
    let sb = sb();
    // ext4 32-bit upper bound ~ year 2446.
    let smax: i64 = 0x37fff_ffff;
    sb.set_time_range(-0x8000_0000, smax);
    assert_eq!(sb.s_time_max(), smax, "set_time_range publishes the ceiling");
    let over = Timespec64::new(smax + 100, 123_456_789);
    // Pinned to smax seconds with a ZEROED sub-second field (Linux tv_nsec=0).
    assert_eq!(sb.timestamp_truncate(over), Timespec64::from_secs(smax),
        "a time past s_time_max is clamped to the boundary second, nsec zeroed");
}

#[test]
fn in_window_time_is_untouched() {
    let sb = sb();
    sb.set_time_range(-0x8000_0000, 0x37fff_ffff);
    let t = Timespec64::new(1_700_000_000, 42); // ~year 2023, well inside
    assert_eq!(sb.timestamp_truncate(t), t, "an in-window timestamp is preserved exactly");
}

/// F767: the ext4 window's FLOOR is `S32_MIN` (1901-12-13), so a pre-1970
/// timestamp is squarely IN range for a real filesystem and must survive
/// untouched. This is the case `utime`/`utimes`/`futimesat`/`utimensat` used to
/// reject outright with `EINVAL` because the VFS model was unsigned.
#[test]
fn pre_epoch_time_is_in_range_for_an_ext4_shaped_window() {
    let sb = sb();
    let smin: i64 = i32::MIN as i64; // EXT4_TIMESTAMP_MIN (ext4's 32-bit signed timestamp floor)
    sb.set_time_range(smin, 0x37fff_ffff);
    // 1906-08-16 — the shape `tar`/`rsync`/`cp -p` restore from old archives.
    let t = Timespec64::new(-2_000_000_000, 123_456_789);
    assert_eq!(sb.timestamp_truncate(t), t, "1906 is inside ext4's window, no clamp");
    // Exactly on the floor is in-window, not clamped away.
    assert_eq!(sb.timestamp_truncate(Timespec64::from_secs(smin)), Timespec64::from_secs(smin));
}

/// F767: below the floor clamps UP to `s_time_min` — and `s_time_min` is itself
/// negative, a clamp target the unsigned model could not even express.
#[test]
fn below_a_negative_floor_clamps_up_to_that_negative_floor() {
    let sb = sb();
    let smin: i64 = i32::MIN as i64;
    sb.set_time_range(smin, 0x37fff_ffff);
    let under = Timespec64::new(smin - 1_000, 7); // just past the 1901 floor
    assert_eq!(sb.timestamp_truncate(under), Timespec64::from_secs(smin),
        "clamped up to the NEGATIVE floor second, nsec zeroed");
}

#[test]
fn post_epoch_floor_clamps_up() {
    let sb = sb();
    // A (contrived) backend that cannot represent times before year ~2001.
    let smin: i64 = 1_000_000_000;
    sb.set_time_range(smin, TIME64_MAX);
    let under = Timespec64::new(5, 7); // 5s after epoch — below smin
    assert_eq!(sb.timestamp_truncate(under), Timespec64::from_secs(smin),
        "a time before s_time_min is clamped up to the floor second");
}

#[test]
fn inverted_range_is_normalized() {
    let sb = sb();
    // Pass min/max swapped — set_time_range must order them so the window is sane.
    sb.set_time_range(0x37fff_ffff, -0x8000_0000);
    assert_eq!(sb.s_time_min(), -0x8000_0000, "min is the smaller of the two");
    assert_eq!(sb.s_time_max(), 0x37fff_ffff, "max is the larger of the two");
}

#[test]
fn clamp_composes_with_granularity_truncation() {
    let sb = sb();
    // Coarse 1s granularity AND a year-2446 ceiling.
    sb.set_time_gran(NSEC_PER_SEC);
    sb.set_time_range(-0x8000_0000, 0x37fff_ffff);
    // In-window: granularity floors the sub-second remainder, range untouched.
    let t = Timespec64::new(1_700_000_000, 999_999_999);
    assert_eq!(sb.timestamp_truncate(t), Timespec64::from_secs(1_700_000_000),
        "1s gran floors sub-second; in-window seconds preserved");
    // Pre-epoch, in-window: same rule, and the second does not move.
    let p = Timespec64::new(-2_000_000_000, 999_999_999);
    assert_eq!(sb.timestamp_truncate(p), Timespec64::from_secs(-2_000_000_000),
        "1s gran on a pre-epoch time zeroes nsec without shifting the second");
}
