//! superblock: `s_time_min`/`s_time_max` epoch-window clamp (Linux
//! `timestamp_truncate`, fs/inode.c). A backend whose on-disk timestamp field
//! is narrower than `time64_t` (ext4 32-bit = 1901..2446) publishes its window
//! via `set_time_range`; `timestamp_truncate` then pins an out-of-window setattr
//! time to the nearest boundary second (sub-second field zeroed), so an
//! over-the-cap mtime is never wrapped onto disk. With the default
//! `TIME64_MIN`/`TIME64_MAX` window the clamp is a no-op — the granularity-only
//! behaviour the pre-existing `superblock_time_gran` tests assert is preserved.

use std::sync::Arc;

use vfs::fs::FileSystem;
use vfs::superblock::{NSEC_PER_SEC, TIME64_MAX, TIME64_MIN};
use vfs::SuperBlock;

struct TFs;
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::for_backend(Arc::new(TFs), None, 0x55, String::from("tfs"))
}

#[test]
fn default_range_is_full_time64() {
    let sb = sb();
    assert_eq!(sb.s_time_min(), TIME64_MIN, "fresh SB defaults to the widest floor");
    assert_eq!(sb.s_time_max(), TIME64_MAX, "fresh SB defaults to the widest ceiling");
    // A far-future timestamp passes through unclamped under the default window.
    let t = 9_000_000_000u64 * NSEC_PER_SEC + 5;
    assert_eq!(sb.timestamp_truncate(t), t, "default window never clamps");
}

#[test]
fn over_max_clamps_down_to_boundary_second() {
    let sb = sb();
    // ext4 32-bit upper bound ~ year 2446.
    let smax: i64 = 0x37fff_ffff;
    sb.set_time_range(-0x8000_0000, smax);
    assert_eq!(sb.s_time_max(), smax, "set_time_range publishes the ceiling");
    let over = (smax as u64 + 100) * NSEC_PER_SEC + 123_456_789;
    // Pinned to smax seconds with a ZEROED sub-second field (Linux tv_nsec=0).
    assert_eq!(sb.timestamp_truncate(over), smax as u64 * NSEC_PER_SEC,
        "a time past s_time_max is clamped to the boundary second, nsec zeroed");
}

#[test]
fn in_window_time_is_untouched() {
    let sb = sb();
    sb.set_time_range(-0x8000_0000, 0x37fff_ffff);
    let t = 1_700_000_000u64 * NSEC_PER_SEC + 42; // ~year 2023, well inside
    assert_eq!(sb.timestamp_truncate(t), t, "an in-window timestamp is preserved exactly");
}

#[test]
fn post_epoch_floor_clamps_up() {
    let sb = sb();
    // A (contrived) backend that cannot represent times before year ~2001.
    let smin: i64 = 1_000_000_000;
    sb.set_time_range(smin, TIME64_MAX);
    let under = 5u64 * NSEC_PER_SEC + 7; // 5s after epoch — below smin
    assert_eq!(sb.timestamp_truncate(under), smin as u64 * NSEC_PER_SEC,
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
    sb.set_time_gran(NSEC_PER_SEC as u32);
    sb.set_time_range(-0x8000_0000, 0x37fff_ffff);
    // In-window: granularity floors the sub-second remainder, range untouched.
    let t = 1_700_000_000u64 * NSEC_PER_SEC + 999_999_999;
    assert_eq!(sb.timestamp_truncate(t), 1_700_000_000u64 * NSEC_PER_SEC,
        "1s gran floors sub-second; in-window seconds preserved");
}
