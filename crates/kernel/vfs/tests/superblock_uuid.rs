//! superblock-D (`s_uuid`): a `SuperBlock` carries the Linux
//! `super_block.s_uuid` (a 16-byte `uuid_t`) plus `s_uuid_len`, published by a
//! backend's `fill_super` from its on-disk superblock and consumed by
//! `name_to_handle_at` FID generation and UUID display. A fresh `for_backend`
//! SB has no UUID (all-zero, len 0); `set_uuid` publishes one without rebuilding
//! the SB. None of this existed before — the SB modelled `s_id`/`s_dev` but had
//! no filesystem-UUID field at all.

use std::sync::Arc;

use vfs::fs::FileSystem;
use vfs::superblock::next_anon_dev;
use vfs::SuperBlock;

struct UFs;
impl FileSystem for UFs {
    fn name(&self) -> &str { "ufs" }
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::for_backend(Arc::new(UFs), None, next_anon_dev(), String::from("ufs"))
}

#[test]
fn fresh_sb_has_no_uuid() {
    let sb = sb();
    assert!(!sb.has_uuid(), "a fresh SB has no published UUID");
    assert_eq!(sb.s_uuid_len(), 0);
    assert_eq!(sb.s_uuid(), [0u8; 16], "default UUID is all-zero");
}

#[test]
fn set_uuid_publishes_full_16_bytes() {
    let sb = sb();
    let u: [u8; 16] = [
        0x55, 0xaa, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    ];
    sb.set_uuid(u, 16);
    assert!(sb.has_uuid(), "UUID now present");
    assert_eq!(sb.s_uuid_len(), 16);
    assert_eq!(sb.s_uuid(), u, "round-trips the published bytes verbatim");
}

#[test]
fn short_uuid_zero_fills_tail() {
    let sb = sb();
    // A 4-byte significant prefix; the rest of the input array is garbage that
    // must NOT leak into the stored UUID beyond len.
    let input: [u8; 16] = [
        0xde, 0xad, 0xbe, 0xef, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    sb.set_uuid(input, 4);
    assert_eq!(sb.s_uuid_len(), 4);
    let got = sb.s_uuid();
    assert_eq!(&got[..4], &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(&got[4..], &[0u8; 12], "unused tail zero-filled, no stale leak");
    assert!(sb.has_uuid());
}

#[test]
fn over_length_len_clamped_to_16() {
    let sb = sb();
    let u: [u8; 16] = [0x11; 16];
    sb.set_uuid(u, 200); // absurd len → clamp to 16, no panic / overrun
    assert_eq!(sb.s_uuid_len(), 16);
    assert_eq!(sb.s_uuid(), u);
}

#[test]
fn republish_overwrites_previous() {
    let sb = sb();
    sb.set_uuid([0x11; 16], 16);
    sb.set_uuid([0x22; 16], 16);
    assert_eq!(sb.s_uuid(), [0x22; 16], "a second fill_super overwrites the UUID");
}
