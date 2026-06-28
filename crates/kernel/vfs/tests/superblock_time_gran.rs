//! superblock-D: `s_time_gran` timestamp rounding (Linux `timestamp_truncate`,
//! fs/inode.c). The SB stores a per-fs granularity (set at `fill_super` via
//! `set_time_gran`); `timestamp_truncate` floors a wall-clock ns timestamp DOWN
//! to that granularity so a setattr never records sub-granularity precision the
//! backend cannot persist (ext4 1ns vs a coarse-time backend). The rounding is
//! confined to the sub-second field, so a coarse `gran` never perturbs seconds.

use std::sync::Arc;

use vfs::fs::FileSystem;
use vfs::superblock::NSEC_PER_SEC;
use vfs::SuperBlock;

/// Minimal backend — no root inode needed; the test exercises pure SB math.
struct TFs;
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::for_backend(Arc::new(TFs), None, 0x55, String::from("tfs"))
}

#[test]
fn default_gran_is_ns_identity() {
    let sb = sb();
    assert_eq!(sb.s_time_gran(), 1, "fresh SB defaults to ns granularity");
    let t = 7 * NSEC_PER_SEC + 123_456_789;
    assert_eq!(sb.timestamp_truncate(t), t, "gran==1 is the identity (full ns)");
}

#[test]
fn microsecond_gran_floors_sub_us() {
    let sb = sb();
    sb.set_time_gran(1_000); // 1 µs
    assert_eq!(sb.s_time_gran(), 1_000, "set_time_gran is observable");
    let t = 7 * NSEC_PER_SEC + 123_456_789;
    // 123_456_789 ns floored to a 1_000 ns multiple = 123_456_000 ns.
    assert_eq!(sb.timestamp_truncate(t), 7 * NSEC_PER_SEC + 123_456_000,
        "sub-microsecond remainder truncated, seconds preserved");
}

#[test]
fn millisecond_gran_floors_sub_ms() {
    let sb = sb();
    sb.set_time_gran(1_000_000); // 1 ms
    let t = 42 * NSEC_PER_SEC + 999_999_999;
    assert_eq!(sb.timestamp_truncate(t), 42 * NSEC_PER_SEC + 999_000_000,
        "floored to a whole millisecond");
}

#[test]
fn second_gran_floors_to_whole_second() {
    let sb = sb();
    sb.set_time_gran(NSEC_PER_SEC as u32); // 1 s
    let t = 5 * NSEC_PER_SEC + 999_999_999;
    assert_eq!(sb.timestamp_truncate(t), 5 * NSEC_PER_SEC,
        "gran==NSEC_PER_SEC zeroes the sub-second field, second kept");
    // An already-aligned timestamp is unchanged.
    assert_eq!(sb.timestamp_truncate(5 * NSEC_PER_SEC), 5 * NSEC_PER_SEC,
        "whole-second input is a fixed point");
}

#[test]
fn zero_gran_normalized_to_ns() {
    let sb = sb();
    sb.set_time_gran(0); // invalid → normalize to 1 (no divide-by-zero)
    assert_eq!(sb.s_time_gran(), 1, "gran 0 normalized to ns");
    let t = 3 * NSEC_PER_SEC + 1;
    assert_eq!(sb.timestamp_truncate(t), t, "normalized gran is the identity");
}

#[test]
fn epoch_zero_is_fixed_point() {
    let sb = sb();
    sb.set_time_gran(NSEC_PER_SEC as u32);
    assert_eq!(sb.timestamp_truncate(0), 0, "epoch 0 truncates to 0 at any gran");
}
