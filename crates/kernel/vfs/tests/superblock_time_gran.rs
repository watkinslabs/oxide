//! superblock-D: `s_time_gran` timestamp rounding (Linux `timestamp_truncate`,
//! fs/inode.c). The SB stores a per-fs granularity (set at `fill_super` via
//! `set_time_gran`); `timestamp_truncate` floors a wall-clock timestamp DOWN
//! to that granularity so a setattr never records sub-granularity precision the
//! backend cannot persist (ext4 1ns vs a coarse-time backend). The rounding is
//! confined to the sub-second field, so a coarse `gran` never perturbs seconds —
//! including for a PRE-EPOCH timestamp, whose seconds field is already the
//! floor and must not be pushed a second further back.

use std::sync::Arc;

mod common;

use vfs::fs::FileSystem;
use vfs::timespec::NSEC_PER_SEC;
use vfs::{SuperBlock, Timespec64};

/// Minimal backend — no root inode needed; the test exercises pure SB math.
struct TFs;
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
}

fn sb() -> Arc<SuperBlock> {
    common::realize_sb(Arc::new(TFs), None, 0x55, String::from("tfs"))
}

#[test]
fn default_gran_is_ns_identity() {
    let sb = sb();
    assert_eq!(sb.s_time_gran(), 1, "fresh SB defaults to ns granularity");
    let t = Timespec64::new(7, 123_456_789);
    assert_eq!(sb.timestamp_truncate(t), t, "gran==1 is the identity (full ns)");
}

#[test]
fn microsecond_gran_floors_sub_us() {
    let sb = sb();
    sb.set_time_gran(1_000); // 1 µs
    assert_eq!(sb.s_time_gran(), 1_000, "set_time_gran is observable");
    let t = Timespec64::new(7, 123_456_789);
    // 123_456_789 ns floored to a 1_000 ns multiple = 123_456_000 ns.
    assert_eq!(sb.timestamp_truncate(t), Timespec64::new(7, 123_456_000),
        "sub-microsecond remainder truncated, seconds preserved");
}

#[test]
fn millisecond_gran_floors_sub_ms() {
    let sb = sb();
    sb.set_time_gran(1_000_000); // 1 ms
    let t = Timespec64::new(42, 999_999_999);
    assert_eq!(sb.timestamp_truncate(t), Timespec64::new(42, 999_000_000),
        "floored to a whole millisecond");
}

#[test]
fn second_gran_floors_to_whole_second() {
    let sb = sb();
    sb.set_time_gran(NSEC_PER_SEC); // 1 s
    let t = Timespec64::new(5, 999_999_999);
    assert_eq!(sb.timestamp_truncate(t), Timespec64::from_secs(5),
        "gran==NSEC_PER_SEC zeroes the sub-second field, second kept");
    // An already-aligned timestamp is unchanged.
    assert_eq!(sb.timestamp_truncate(Timespec64::from_secs(5)), Timespec64::from_secs(5),
        "whole-second input is a fixed point");
}

#[test]
fn zero_gran_normalized_to_ns() {
    let sb = sb();
    sb.set_time_gran(0); // invalid → normalize to 1 (no divide-by-zero)
    assert_eq!(sb.s_time_gran(), 1, "gran 0 normalized to ns");
    let t = Timespec64::new(3, 1);
    assert_eq!(sb.timestamp_truncate(t), t, "normalized gran is the identity");
}

#[test]
fn epoch_zero_is_fixed_point() {
    let sb = sb();
    sb.set_time_gran(NSEC_PER_SEC);
    assert_eq!(sb.timestamp_truncate(Timespec64::ZERO), Timespec64::ZERO,
        "epoch 0 truncates to 0 at any gran");
}

/// F767: granularity flooring on a PRE-EPOCH instant touches only `tv_nsec`.
/// Linux `timestamp_truncate` subtracts `tv_nsec % gran` and never the seconds
/// field, so 1969-12-31T23:59:59.999999999 floors to ...:59.999 at ms gran and
/// to ...:59 at second gran — it does NOT roll back to 1969-12-31T23:59:58.
/// A model storing ns as one scalar and flooring the whole value would move the
/// second, because integer division of a negative truncates toward zero.
#[test]
fn pre_epoch_gran_floor_moves_only_the_subsecond_field() {
    let sb = sb();
    let t = Timespec64::new(-1, 999_999_999); // 1969-12-31T23:59:59.999999999Z
    sb.set_time_gran(1_000_000); // 1 ms
    assert_eq!(sb.timestamp_truncate(t), Timespec64::new(-1, 999_000_000),
        "pre-epoch ms floor keeps the second");
    sb.set_time_gran(NSEC_PER_SEC);
    assert_eq!(sb.timestamp_truncate(t), Timespec64::from_secs(-1),
        "pre-epoch second floor zeroes nsec and keeps sec == -1");
}

/// F767: a deep pre-1970 timestamp (1906) survives the default window intact.
#[test]
fn deep_pre_epoch_survives_default_window() {
    let sb = sb();
    let t = Timespec64::new(-2_000_000_000, 500_000_000); // 1906-08-16
    assert_eq!(sb.timestamp_truncate(t), t, "no clamp under the default TIME64 window");
}
