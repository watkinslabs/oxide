//! D47 — name_to_handle_at -> open_by_handle_at round-trip mechanism.
//! name_to_handle_at (303) encodes an inode as an 8-byte little-endian FID;
//! open_by_handle_at (304) decodes it and resolves it on the mount_fd's
//! superblock via `sb.ilookup(ino)`. The syscall handlers are kernel-only
//! (`cfg(target_os = "oxide-kernel")`), so this exercises the FID codec +
//! the superblock resolution step the reopen path is built on: a handle
//! resolves back to the SAME inode, and a stale (gone) inode does not.

use std::sync::Arc;

use vfs::fs::FileSystem;
use vfs::inode::InodeBuilder;
use vfs::superblock::next_anon_dev;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeRef, SuperBlock};

struct FidFs;
impl FileSystem for FidFs {
    fn name(&self) -> &str { "fidfs" }
}

fn make_ramfile(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::for_backend(Arc::new(FidFs), None, next_anon_dev(), String::from("fidfs"))
}

// The 8-byte inode FID codec shared by slots 303/304.
fn encode_fid(ino: u64) -> [u8; 8] { ino.to_le_bytes() }
fn decode_fid(fid: [u8; 8]) -> u64 { u64::from_le_bytes(fid) }

#[test]
fn fid_codec_is_lossless() {
    for ino in [1u64, 2, 42, 0xdead_beef, u64::MAX] {
        assert_eq!(decode_fid(encode_fid(ino)), ino);
    }
}

#[test]
fn handle_resolves_back_to_same_inode() {
    let sb = sb();
    // name_to_handle_at side: resolve an inode, emit its FID.
    let resident = sb.iget(77, || make_ramfile(77));
    let fid = encode_fid(resident.ino());

    // open_by_handle_at side: decode the FID, resolve on the same superblock.
    let ino = decode_fid(fid);
    let reopened = sb.ilookup(ino).expect("resident inode resolves");
    assert!(Arc::ptr_eq(&resident, &reopened), "handle round-trips to the SAME inode");
    assert_eq!(reopened.ino(), 77);
}

#[test]
fn stale_handle_yields_no_inode() {
    let sb = sb();
    // An inode that was resolved once but whose last reference dropped is gone
    // from the icache → open_by_handle_at returns ESTALE (modeled as a miss).
    let fid = {
        let tmp = sb.iget(99, || make_ramfile(99));
        encode_fid(tmp.ino())
    }; // tmp dropped here → Weak dead
    assert!(sb.ilookup(decode_fid(fid)).is_none(), "stale handle does not resolve");
}
