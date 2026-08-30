//! P6-06 integration: parse a real mke2fs-built image.
//!
//! Image at `tests/mini.img` is 1 MiB, 1 KiB blocks, no
//! has_journal, default ext4 features (extents on), one
//! file `hello.txt` containing `hello-from-ext4-mini\n` at
//! inode 12. Built via:
//!
//!   dd if=/dev/zero of=mini.img bs=1M count=1
//!   mkfs.ext4 -F -O ^has_journal -L oxide mini.img
//!   debugfs -w -R 'write hello.txt hello.txt' mini.img
//!
//! This test verifies the full chain: superblock parse, GDT
//! parse, root inode read, root dir lookup, target inode read,
//! file data block read.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini.img");
const BLOCK_SIZE: u32 = 512;  // backing-block size; ext4 fs's own block_size is 1024.

/// Wrap MemDisk in a BlockDevice that exposes raw 512-byte sectors,
/// preloaded with IMAGE bytes.
fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (BLOCK_SIZE as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(BLOCK_SIZE, cap);
    // MemDisk doesn't expose a raw write-bytes API; fake it via
    // submit_sync with a Write request covering the whole image.
    let mut req = BlockRequest {
        op: BlockOp::Write,
        start_block: 0,
        len_blocks: cap as u32,
        buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).expect("memdisk write");
    disk
}

#[test]
fn open_parses_superblock() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).expect("mount");
    assert_eq!(m.sb.magic, ext4::EXT4_SUPER_MAGIC);
    assert_eq!(m.sb.block_size, 1024, "mke2fs picked 1 KiB blocks for 1 MiB fs");
    assert!(m.sb.has_extents(), "ext4 default has extents");
    assert_eq!(m.behaviour().errors, ext4::mount_opts::ErrorsPolicy::Continue,
        "an open without errors= must inherit this image's s_errors=continue");
}

#[test]
fn root_inode_is_directory() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).expect("mount");
    let root = m.read_inode(2).expect("read root");
    assert!(root.is_dir(), "inode 2 is /");
}

#[test]
fn lookup_path_hello_txt() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).expect("mount");
    let ino = m.lookup_path(b"/hello.txt").expect("lookup");
    assert!(ino > 11, "inode num for first user file > reserved (11)");
    let ino_struct = m.read_inode(ino).expect("read");
    assert!(ino_struct.is_reg(), "hello.txt is a regular file");
    let n: u64 = "hello-from-ext4-mini\n".len() as u64;
    assert_eq!(ino_struct.size, n, "file size matches debugfs payload");
}

#[test]
fn read_file_block_returns_payload() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).expect("mount");
    let ino = m.lookup_path(b"/hello.txt").expect("lookup");
    let inode = m.read_inode(ino).expect("read");
    let blk = m.read_file_block(&inode, 0).expect("read blk0");
    let want = b"hello-from-ext4-mini\n";
    assert_eq!(&blk[..want.len()], want, "first bytes of blk 0 = file content");
}

#[test]
fn inline_file_converts_to_extents_when_it_outgrows_ibody() {
    let m = ext4::Mount::open(build_disk()).expect("mount");
    let ino = m.create_file(2, b"inline-convert", 0o644, 0, 0).expect("create");
    let mut raw = m.read_inode_bytes(ino).expect("read raw inode").0;
    let first = [0x41u8; ext4::inode::I_BLOCK_LEN];
    raw[0x20..0x24].copy_from_slice(&ext4::inode::EXT4_INLINE_DATA_FL.to_le_bytes());
    raw[0x28..0x28 + ext4::inode::I_BLOCK_LEN].copy_from_slice(&first);
    raw[0x04..0x08].copy_from_slice(&70u32.to_le_bytes());
    raw[0x6C..0x70].copy_from_slice(&0u32.to_le_bytes());
    raw[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes());
    let extra = u16::from_le_bytes([raw[0x80], raw[0x81]]) as usize;
    let hdr = ext4::csum::EXT4_GOOD_OLD_INODE_SIZE + extra;
    ext4::xattr::encode_ibody(
        &mut raw,
        hdr,
        m.sb.inode_size as usize,
        &[("system.data".into(), vec![0x42u8; 10])],
    ).expect("encode inline tail");
    m.write_inode_bytes(ino, &raw).expect("publish inline inode");

    let inline = m.read_inode(ino).expect("read inline inode");
    assert_ne!(inline.i_flags & ext4::inode::EXT4_INLINE_DATA_FL, 0);
    assert_eq!(inline.size, 60 + 10);
    assert_eq!(&m.read_file_block(&inline, 0).expect("read inline")[..70],
        &[0x41u8; 60].iter().chain([0x42u8; 10].iter()).copied().collect::<Vec<_>>()[..]);

    let bs = m.sb.block_size as u64;
    m.write_at(ino, bs * 2 + 7, &[0xEF]).expect("convert and write");
    let converted = m.read_inode(ino).expect("read converted inode");
    assert_eq!(converted.i_flags & ext4::inode::EXT4_INLINE_DATA_FL, 0);
    assert_ne!(converted.i_flags & ext4::inode::EXT4_EXTENTS_FL, 0);
    assert_eq!(converted.size, bs * 2 + 8);
    let block = m.read_file_block(&converted, 0).expect("read converted block");
    assert_eq!(&block[..60], &[0x41u8; 60]);
    assert_eq!(&block[60..70], &[0x42u8; 10]);
    assert!(m.read_file_block(&converted, 1).unwrap().iter().all(|b| *b == 0));
    let last = m.read_file_block(&converted, 2).expect("read converted tail block");
    assert_eq!(last[7], 0xEF);
}

#[test]
fn legacy_inode_direct_block_reads_through_same_mount_owner() {
    let m = ext4::Mount::open(build_disk()).expect("mount");
    let extent_inode = m.read_inode(2).expect("read root");
    let header = ext4::inode::parse_extent_header(&extent_inode.i_block).expect("extent root");
    let extent = ext4::inode::parse_inline_extent(&extent_inode.i_block, &header, 0)
        .expect("root extent");
    let expected = m.read_file_block(&extent_inode, 0).expect("extent data");

    // A real ext4 volume may contain legacy inodes even when the filesystem
    // advertises INCOMPAT_EXTENTS. Clear only the per-inode layout flag and
    // point its first direct slot at the same already-valid data block.
    let mut legacy = extent_inode;
    legacy.i_flags &= !ext4::inode::EXT4_EXTENTS_FL;
    legacy.i_block = [0; ext4::inode::I_BLOCK_LEN];
    legacy.i_block[..4].copy_from_slice(&(extent.start_lba() as u32).to_le_bytes());
    assert_eq!(m.read_file_block(&legacy, 0).expect("legacy data"), expected);
}

#[test]
fn legacy_inode_triple_indirect_read_uses_same_mapper() {
    let m = ext4::Mount::open(build_disk()).expect("mount");
    let block_size = m.sb.block_size as u64;
    let ptrs = block_size / 4;
    let logical = 12 + ptrs + ptrs * ptrs;
    let level2 = m.alloc_block(0).expect("allocate triple root child");
    let level1 = m.alloc_block(0).expect("allocate triple middle child");
    let leaf = m.alloc_block(0).expect("allocate triple leaf");
    let data = m.alloc_block(0).expect("allocate triple data");
    let table = |child: u64, slot: u64| {
        let mut bytes = vec![0u8; block_size as usize];
        let off = (slot * 4) as usize;
        bytes[off..off + 4].copy_from_slice(&(child as u32).to_le_bytes());
        bytes
    };
    m.metadata_write(level2 * block_size, &table(level1, 0)).expect("write triple root child");
    m.metadata_write(level1 * block_size, &table(leaf, 0)).expect("write triple middle child");
    m.metadata_write(leaf * block_size, &table(data, 0)).expect("write triple leaf");
    let payload = vec![0xA5u8; block_size as usize];
    m.metadata_write(data * block_size, &payload).expect("write triple data");

    let mut inode = m.read_inode(2).expect("read root");
    inode.i_flags &= !ext4::inode::EXT4_EXTENTS_FL;
    inode.i_block = [0; ext4::inode::I_BLOCK_LEN];
    inode.i_block[56..60].copy_from_slice(&(level2 as u32).to_le_bytes());
    inode.size = (logical + 1) * block_size;
    let got = m.read_file_block(&inode, logical as u32).expect("read triple data");
    assert_eq!(got, payload);
}

#[test]
fn generated_legacy_inode_reads_single_indirect_block() {
    use std::process::Command;

    let stem = format!("oxide-ext4-legacy-{}", std::process::id());
    let image = std::env::temp_dir().join(format!("{stem}.img"));
    let source = std::env::temp_dir().join(format!("{stem}.data"));
    let payload: Vec<u8> = (0..(300 * 1024)).map(|n| (n as u8).wrapping_mul(37)).collect();
    std::fs::write(&source, &payload).expect("write source");
    let _ = std::fs::remove_file(&image);
    let status = Command::new("truncate").args(["-s", "32M", image.to_str().unwrap()]).status().unwrap();
    assert!(status.success(), "truncate failed");
    let status = Command::new("mkfs.ext4").args(["-q", "-F", "-O", "^extent,^64bit", image.to_str().unwrap()]).status().unwrap();
    assert!(status.success(), "mkfs failed");
    let request = format!("write {} /legacy", source.display());
    let status = Command::new("debugfs").args(["-w", "-R", &request, image.to_str().unwrap()]).status().unwrap();
    assert!(status.success(), "debugfs write failed");

    let bytes = std::fs::read(&image).expect("read generated image");
    let cap = (bytes.len() / BLOCK_SIZE as usize) as u64;
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(BLOCK_SIZE, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: bytes, ..Default::default() };
    disk.submit_sync(&mut req).expect("load generated image");
    let m = ext4::Mount::open(disk).expect("mount generated image");
    let ino = m.lookup_path(b"/legacy").expect("lookup legacy file");
    let inode = m.read_inode(ino).expect("read legacy inode");
    assert_eq!(inode.i_flags & ext4::inode::EXT4_EXTENTS_FL, 0);
    assert_eq!(&m.read_file_block(&inode, 0).unwrap()[..], &payload[..1024]);
    assert_eq!(&m.read_file_block(&inode, 12).unwrap()[..], &payload[12 * 1024..13 * 1024]);
    m.write_at(ino, 0, b"LEG!").expect("write existing legacy block");
    let rewritten = m.read_inode(ino).expect("read rewritten legacy inode");
    assert_eq!(rewritten.i_flags & ext4::inode::EXT4_EXTENTS_FL, 0);
    let first = m.read_file_block(&rewritten, 0).expect("read rewritten block");
    assert_eq!(&first[..4], b"LEG!");
    assert_eq!(&first[4..], &payload[4..1024]);
    m.write_at(ino, 1300 * 1024, b"NEW!").expect("allocate legacy double-indirect block");
    let grown = m.read_inode(ino).expect("read grown legacy inode");
    assert_eq!(grown.i_flags & ext4::inode::EXT4_EXTENTS_FL, 0);
    assert_eq!(&m.read_file_block(&grown, 1300).unwrap()[..4], b"NEW!");
    m.truncate_inode(ino, 13 * 1024).expect("truncate legacy indirect tree");
    let truncated = m.read_inode(ino).expect("read truncated legacy inode");
    assert_eq!(truncated.i_flags & ext4::inode::EXT4_EXTENTS_FL, 0);
    assert_eq!(truncated.size, 13 * 1024);
    assert_eq!(&m.read_file_block(&truncated, 12).unwrap()[..], &payload[12 * 1024..13 * 1024]);
    assert!(m.read_file_block(&truncated, 13).unwrap().iter().all(|&b| b == 0));
    m.punch_hole_inode(ino, 1024, 1024).expect("punch legacy mapped block");
    let punched = m.read_inode(ino).expect("read punched legacy inode");
    assert_eq!(punched.size, 13 * 1024);
    assert!(m.read_file_block(&punched, 1).unwrap().iter().all(|&b| b == 0));
    assert_eq!(&m.read_file_block(&punched, 2).unwrap()[..], &payload[2 * 1024..3 * 1024]);
    m.fallocate_inode(ino, 13 * 1024, 2 * 1024, true).expect("fallocate legacy holes");
    let preallocated = m.read_inode(ino).expect("read preallocated legacy inode");
    assert_eq!(preallocated.size, 13 * 1024);
    assert!(m.read_file_block(&preallocated, 13).unwrap().iter().all(|&b| b == 0));
    let _ = std::fs::remove_file(&image);
    let _ = std::fs::remove_file(&source);
}

#[test]
fn lookup_path_missing_returns_notfound() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).expect("mount");
    let err = m.lookup_path(b"/no-such-file").err().expect("err");
    assert_eq!(err, ext4::MountError::NotFound);
}

// Per-component child lookup — the primitive the dentry path-walk
// (docs/16§3) drives via Inode::lookup, and which rootfs::lookup_child_ino
// wraps. Resolving "hello.txt" within the root dir must match the
// whole-path result; an absent child returns NotFound.
#[test]
fn lookup_in_dir_resolves_child() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).expect("mount");
    let root = m.read_inode(2).expect("read root");
    let via_dir = m.lookup_in_dir(&root, b"hello.txt").expect("child");
    let via_path = m.lookup_path(b"/hello.txt").expect("path");
    assert_eq!(via_dir, via_path, "per-component lookup == whole-path lookup");
}

#[test]
fn lookup_in_dir_missing_returns_notfound() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).expect("mount");
    let root = m.read_inode(2).expect("read root");
    let err = m.lookup_in_dir(&root, b"no-such-child").err().expect("err");
    assert_eq!(err, ext4::MountError::NotFound);
}

#[test]
fn open_refuses_unsupported_incompat_feature() {
    // Set an unknown INCOMPAT bit in the SB. The feature gate must refuse the
    // mount rather than misinterpret it (Linux EXT4_FEATURE_INCOMPAT_SUPP).
    let mut img = IMAGE.to_vec();
    img[1024 + 0x60 + 1] |= 0x40; // s_feature_incompat |= 0x4000
    let cap = (img.len() as u64) / (BLOCK_SIZE as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(BLOCK_SIZE, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: img, ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    let disk: Arc<dyn BlockDevice> = disk;
    assert!(matches!(ext4::Mount::open(disk), Err(ext4::MountError::UnsupportedFeature)),
        "unsupported INCOMPAT feature must refuse the mount");
}

#[test]
fn generated_inline_directory_mounts_and_mutates() {
    use std::process::Command;

    let stem = format!("oxide-ext4-inline-{}", std::process::id());
    let image = std::env::temp_dir().join(format!("{stem}.img"));
    let _ = std::fs::remove_file(&image);
    let status = Command::new("truncate").args(["-s", "32M", image.to_str().unwrap()]).status().unwrap();
    assert!(status.success(), "truncate failed");
    let status = Command::new("mkfs.ext4").args(["-q", "-F", "-O", "inline_data,^64bit", image.to_str().unwrap()]).status().unwrap();
    assert!(status.success(), "mkfs failed");
    let status = Command::new("debugfs").args(["-w", "-R", "mkdir /inline", image.to_str().unwrap()]).status().unwrap();
    assert!(status.success(), "debugfs mkdir failed");

    let bytes = std::fs::read(&image).expect("read image");
    let cap = (bytes.len() / BLOCK_SIZE as usize) as u64;
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(BLOCK_SIZE, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: bytes, ..Default::default() };
    disk.submit_sync(&mut req).expect("load image");
    let m = ext4::Mount::open(disk).expect("mount inline image");
    let dir = m.lookup_path(b"/inline").expect("lookup inline directory");
    let dir_inode = m.read_inode(dir).expect("read inline directory");
    assert_ne!(dir_inode.i_flags & ext4::inode::EXT4_INLINE_DATA_FL, 0);
    assert_eq!(m.lookup_in_dir(&dir_inode, b".").expect("dot"), dir);
    assert_eq!(m.lookup_in_dir(&dir_inode, b"..").expect("dotdot"), 2);

    let child = m.create_file(dir, b"child", 0o644, 0, 0).expect("create in inline directory");
    assert_eq!(m.lookup_in_dir(&m.read_inode(dir).unwrap(), b"child").unwrap(), child);
    let mut last = child;
    for n in 0..24 {
        let name = std::format!("entry-{n:02}-inline-directory-growth");
        last = m.create_file(dir, name.as_bytes(), 0o644, 0, 0)
            .unwrap_or_else(|e| panic!("grow inline directory {n}: {e:?}"));
    }
    let converted = m.read_inode(dir).expect("read grown directory");
    assert_eq!(converted.i_flags & ext4::inode::EXT4_INLINE_DATA_FL, 0);
    assert_eq!(m.lookup_in_dir(&converted, b"entry-23-inline-directory-growth").unwrap(), last);
    assert_eq!(m.dir_unlink(dir, b"child").unwrap(), child);
    assert_eq!(m.lookup_path(b"/inline/child"), Err(ext4::MountError::NotFound));
    let _ = std::fs::remove_file(&image);
}

#[test]
fn open_refuses_unsupported_ro_compat_feature() {
    // Set RO_COMPAT_BIGALLOC (0x0200) — a cluster-bitmap layout we'd misread as
    // per-block. No RO-mount path, so refuse rather than risk write corruption.
    let mut img = IMAGE.to_vec();
    img[1024 + 0x64 + 1] |= 0x02; // s_feature_ro_compat |= 0x0200
    let cap = (img.len() as u64) / (BLOCK_SIZE as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(BLOCK_SIZE, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: img, ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    let disk: Arc<dyn BlockDevice> = disk;
    assert!(matches!(ext4::Mount::open(disk), Err(ext4::MountError::UnsupportedFeature)),
        "unsupported RO_COMPAT feature must refuse the mount");
}

#[test]
fn open_accepts_supported_features() {
    // Stock mini.img (filetype/extent/64bit/flex_bg/csum_seed + metadata_csum
    // family) must still mount cleanly through the gate.
    assert!(ext4::Mount::open(build_disk()).is_ok(), "supported-feature image mounts");
}
