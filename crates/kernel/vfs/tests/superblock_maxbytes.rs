//! superblock-D (`s_maxbytes` consumer): the SB stores the largest file size a
//! backend can represent (`s_maxbytes`, default `MAX_LFS_FILESIZE`). Before this
//! the field existed but had NO consumer — a write past the cap was never
//! clamped or rejected. `generic_write_check_limits` (Linux fs/read_write.c)
//! clamps a write to the cap and reports the `EFBIG` case so the write(2) path
//! can shorten or fail a write that would exceed the fs's representable size.

use std::sync::Arc;

use vfs::fs::FileSystem;
use vfs::superblock::{next_anon_dev, MAX_LFS_FILESIZE};
use vfs::SuperBlock;

/// Backend reporting a SMALL maxbytes so the cap is reachable in a hosted test
/// (the real `s_maxbytes` comes from `for_backend`'s `MAX_LFS_FILESIZE`).
struct CapFs;
impl FileSystem for CapFs {
    fn name(&self) -> &str { "capfs" }
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::for_backend(Arc::new(CapFs), None, next_anon_dev(), String::from("capfs"))
}

#[test]
fn default_maxbytes_is_max_lfs() {
    let sb = sb();
    assert_eq!(sb.s_maxbytes(), MAX_LFS_FILESIZE, "for_backend defaults to MAX_LFS_FILESIZE");
}

#[test]
fn write_well_below_cap_is_unclamped() {
    let sb = sb();
    // 100 bytes at offset 0 — far below i64::MAX — passes through unchanged.
    assert_eq!(sb.generic_write_check_limits(0, 100), Some(100));
    assert!(!sb.write_exceeds_maxbytes(0));
}

#[test]
fn write_straddling_cap_is_clamped() {
    let sb = sb();
    let max = sb.s_maxbytes();
    // Start 10 bytes below the cap, ask for 1000: only 10 bytes fit.
    let pos = max - 10;
    assert_eq!(sb.generic_write_check_limits(pos, 1000), Some(10),
        "count clamped so pos + n == s_maxbytes");
    assert!(!sb.write_exceeds_maxbytes(pos), "below the cap → not EFBIG");
}

#[test]
fn write_exactly_at_cap_is_efbig() {
    let sb = sb();
    let max = sb.s_maxbytes();
    // pos == s_maxbytes: no room at all → EFBIG (None).
    assert_eq!(sb.generic_write_check_limits(max, 1), None);
    assert!(sb.write_exceeds_maxbytes(max));
    // ...and beyond the cap likewise.
    assert_eq!(sb.generic_write_check_limits(max + 4096, 1), None);
    assert!(sb.write_exceeds_maxbytes(max + 4096));
}

#[test]
fn empty_write_at_cap_short_circuits_ok() {
    let sb = sb();
    let max = sb.s_maxbytes();
    // A zero-length write is admissible even at the cap (Linux returns 0 before
    // the size check), so it is Some(0), never EFBIG.
    assert_eq!(sb.generic_write_check_limits(max, 0), Some(0));
    assert_eq!(sb.generic_write_check_limits(0, 0), Some(0));
}
