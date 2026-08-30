//! B9 integration: external xattr block write against mini.img.
//! A large xattr overflows the ibody and spills to an `i_file_acl` block;
//! shrinking back frees it. `e2fsck -fn` proves the block (header/hash/csum)
//! is Linux-valid.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const MINI: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;

fn build_disk() -> (Arc<dyn BlockDevice>, u64) {
    let cap = (MINI.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: MINI.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    (disk, cap)
}

fn read_fs_block(disk: &Arc<dyn BlockDevice>, fs_lba: u64, fs_bs: u32) -> std::vec::Vec<u8> {
    let sectors = fs_bs / SECTOR;
    let mut req = BlockRequest {
        op: BlockOp::Read, start_block: fs_lba * sectors as u64, len_blocks: sectors,
        buffer: std::vec![0u8; fs_bs as usize], ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    req.buffer
}

fn write_fs_block(disk: &Arc<dyn BlockDevice>, fs_lba: u64, fs_bs: u32, buffer: std::vec::Vec<u8>) {
    let sectors = fs_bs / SECTOR;
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: fs_lba * sectors as u64, len_blocks: sectors,
        buffer, ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
}

fn dump_disk(disk: &Arc<dyn BlockDevice>, cap: u64) -> std::vec::Vec<u8> {
    let mut req = BlockRequest::new_read(0, cap as u32, SECTOR);
    disk.submit_sync(&mut req).unwrap();
    req.buffer
}

/// i_file_acl (external xattr block LBA) from a raw inode buffer.
fn file_acl(ino_bytes: &[u8]) -> u64 {
    let lo = u32::from_le_bytes([ino_bytes[0x68], ino_bytes[0x69], ino_bytes[0x6A], ino_bytes[0x6B]]) as u64;
    let hi = u16::from_le_bytes([ino_bytes[0x76], ino_bytes[0x77]]) as u64;
    lo | (hi << 32)
}

fn entry(name: &str, val: &[u8]) -> (String, std::vec::Vec<u8>) {
    (String::from(name), val.to_vec())
}

/// Run `e2fsck -fn`; Some(clean?), None if e2fsck absent.
fn e2fsck_clean(bytes: &[u8]) -> Option<bool> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let uniq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(std::format!("oxide-ext4-xattr-{}-{}.img", std::process::id(), uniq));
    { let mut f = std::fs::File::create(&path).ok()?; f.write_all(bytes).ok()?; }
    let out = std::process::Command::new("e2fsck").arg("-fn").arg(&path).output();
    let _ = std::fs::remove_file(&path);
    match out {
        Ok(o) => {
            if !o.status.success() {
                eprintln!("--- e2fsck ---\n{}", String::from_utf8_lossy(&o.stdout));
            }
            Some(o.status.success())
        }
        Err(_) => None,
    }
}

#[test]
fn large_xattr_spills_to_external_block_and_reads_back() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk.0.clone()).unwrap();
    let n = m.create_file(2, b"big.bin", 0o644, 0, 0).unwrap();

    // ~200 bytes far exceeds the ~68-byte ibody value budget of a 256-byte inode.
    let big: std::vec::Vec<u8> = (0..200u32).map(|i| (i & 0xFF) as u8).collect();
    m.store_xattrs(n, &[entry("user.big", &big)]).unwrap();

    let (ino_bytes, _) = m.read_inode_bytes(n).unwrap();
    let facl = file_acl(&ino_bytes);
    assert!(facl != 0, "overflowing xattr allocated an external block");

    let blk = read_fs_block(&disk.0, facl, m.sb.block_size);
    let decoded = ext4::xattr::decode_block(&blk);
    let got = decoded.iter().find(|(k, _)| k == "user.big").expect("xattr in external block");
    assert_eq!(got.1, big, "external xattr value round-trips");
}

#[test]
fn shrinking_back_to_ibody_frees_external_block() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk.0.clone()).unwrap();
    let n = m.create_file(2, b"shrink.bin", 0o644, 0, 0).unwrap();

    let pre_free = m.state_free_blocks();
    let big: std::vec::Vec<u8> = std::vec![0xAB; 200];
    m.store_xattrs(n, &[entry("user.big", &big)]).unwrap();
    let (b1, _) = m.read_inode_bytes(n).unwrap();
    assert!(file_acl(&b1) != 0, "external block allocated");
    assert_eq!(m.state_free_blocks(), pre_free - 1, "one block consumed by xattr");

    // Replace with a tiny value that fits the ibody → external block freed.
    m.store_xattrs(n, &[entry("user.s", b"hi")]).unwrap();
    let (b2, _) = m.read_inode_bytes(n).unwrap();
    assert_eq!(file_acl(&b2), 0, "external block detached");
    assert_eq!(m.state_free_blocks(), pre_free, "xattr block returned to the allocator");
}

#[test]
fn identical_external_xattrs_share_and_release_mbcache_block() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk.0.clone()).unwrap();
    let a = m.create_file(2, b"share-a.bin", 0o644, 0, 0).unwrap();
    let b = m.create_file(2, b"share-b.bin", 0o644, 0, 0).unwrap();
    let before = m.state_free_blocks();
    let value = std::vec![0x5Au8; 200];
    m.store_xattrs(a, &[entry("user.same", &value)]).unwrap();
    m.store_xattrs(b, &[entry("user.same", &value)]).unwrap();
    let (a_raw, _) = m.read_inode_bytes(a).unwrap();
    let (b_raw, _) = m.read_inode_bytes(b).unwrap();
    let block = file_acl(&a_raw);
    assert_ne!(block, 0);
    assert_eq!(file_acl(&b_raw), block, "mbcache should reuse the physical block");
    let shared = read_fs_block(&disk.0, block, m.sb.block_size);
    assert_eq!(u32::from_le_bytes([shared[4], shared[5], shared[6], shared[7]]), 2);

    let changed = std::vec![0x33u8; 200];
    m.store_xattrs(b, &[entry("user.changed", &changed)]).unwrap();
    let (a_after, _) = m.read_inode_bytes(a).unwrap();
    assert_eq!(file_acl(&a_after), block, "the unchanged inode keeps the shared block");
    let once = read_fs_block(&disk.0, block, m.sb.block_size);
    let decoded = ext4::xattr::decode_block(&once);
    assert_eq!(decoded.iter().find(|(k, _)| k == "user.same").map(|(_, v)| v), Some(&value),
        "copy-on-write preserves the other inode's physical xattrs");
    assert_eq!(u32::from_le_bytes([once[4], once[5], once[6], once[7]]), 1);
    m.store_xattrs(a, &[entry("user.small", b"x")]).unwrap();
    assert_eq!(m.state_free_blocks(), before - 1, "the changed inode still owns its replacement block");
    m.store_xattrs(b, &[entry("user.small", b"x")]).unwrap();
    assert_eq!(m.state_free_blocks(), before, "final mbcache put frees the block");
}

#[test]
fn external_block_is_e2fsck_clean() {
    let (disk, cap) = build_disk();
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let n = m.create_file(2, b"xa.bin", 0o644, 0, 0).unwrap();
        // Several namespaces + sizes to exercise sort + hash + value packing.
        let big: std::vec::Vec<u8> = (0..300u32).map(|i| (i * 7 & 0xFF) as u8).collect();
        m.store_xattrs(n, &[
            entry("user.comment", b"a-medium-length-user-comment-value-here"),
            entry("user.big", &big),
            entry("security.selinux", b"system_u:object_r:etc_t:s0"),
        ]).unwrap();
        let (ino_bytes, _) = m.read_inode_bytes(n).unwrap();
        assert!(file_acl(&ino_bytes) != 0, "spilled to external block");
    }
    let bytes = dump_disk(&disk, cap);
    match e2fsck_clean(&bytes) {
        Some(true)  => {}
        Some(false) => panic!("e2fsck flagged the external xattr block"),
        None        => eprintln!("e2fsck not available — skipped fsck assertion"),
    }
}

#[test]
fn value_too_big_for_one_block_is_nospace() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk.0).unwrap();
    let n = m.create_file(2, b"huge.bin", 0o644, 0, 0).unwrap();
    // mini.img has 1 KiB blocks; a 2 KiB value fits neither ibody nor one block.
    let huge = std::vec![0xCDu8; 2048];
    assert!(m.store_xattrs(n, &[entry("user.huge", &huge)]).is_err(),
        "a value larger than one xattr block is rejected, not silently dropped");
}

#[test]
fn ea_inode_value_round_trips_from_linux_layout() {
    let disk = build_disk();
    let mut sb_block = read_fs_block(&disk.0, 1, 1024);
    let mut sb = ext4::Superblock::parse(&sb_block).unwrap();
    sb_block[0x60..0x64].copy_from_slice(&(sb.feature_incompat | 0x0400).to_le_bytes());
    sb = ext4::Superblock::parse(&sb_block).unwrap();
    ext4::csum::stamp_superblock_csum(&sb, &mut sb_block);
    write_fs_block(&disk.0, 1, 1024, sb_block);

    let m = ext4::Mount::open(disk.0.clone()).unwrap();
    let n = m.create_file(2, b"ea-inode.bin", 0o644, 0, 0).unwrap();
    let value: std::vec::Vec<u8> = (0..5000u32).map(|i| (i.wrapping_mul(13) & 0xff) as u8).collect();
    m.store_xattrs(n, &[entry("user.large", &value)]).unwrap();
    let (raw, _) = m.read_inode_bytes(n).unwrap();
    let block = file_acl(&raw);
    let xattr_block = read_fs_block(&disk.0, block, m.sb.block_size);
    let ea_ino = u32::from_le_bytes([xattr_block[36], xattr_block[37], xattr_block[38], xattr_block[39]]);
    assert_ne!(ea_ino, 0, "large value uses e_value_inum");
    let ea = m.read_inode(ea_ino).unwrap();
    assert_ne!(ea.i_flags & 0x0020_0000, 0, "EA inode flag is persisted");
    assert_eq!(ea.size, value.len() as u64);
    let mut got = std::vec::Vec::new();
    for logical in 0..ea.size.div_ceil(m.sb.block_size as u64) as u32 {
        got.extend_from_slice(&m.read_file_block(&ea, logical).unwrap());
    }
    got.truncate(value.len());
    assert_eq!(got, value, "EA inode extent data round-trips");
    let free_with_ea = m.state_free_inodes();
    m.store_xattrs(n, &[entry("user.small", b"x")]).unwrap();
    assert_eq!(m.state_free_inodes(), free_with_ea + 1,
        "replacing the large xattr releases its hidden EA inode");
}

#[test]
fn identical_large_xattrs_share_one_ea_inode_and_release_last_reference() {
    let disk = build_disk();
    let mut sb_block = read_fs_block(&disk.0, 1, 1024);
    let mut sb = ext4::Superblock::parse(&sb_block).unwrap();
    sb_block[0x60..0x64].copy_from_slice(&(sb.feature_incompat | 0x0400).to_le_bytes());
    sb = ext4::Superblock::parse(&sb_block).unwrap();
    ext4::csum::stamp_superblock_csum(&sb, &mut sb_block);
    write_fs_block(&disk.0, 1, 1024, sb_block);

    let m = ext4::Mount::open(disk.0.clone()).unwrap();
    let n = m.create_file(2, b"ea-share.bin", 0o644, 0, 0).unwrap();
    let value = std::vec![0xA5u8; 5000];
    let free_before = m.state_free_inodes();
    m.store_xattrs(n, &[entry("user.a", &value), entry("user.b", &value)]).unwrap();
    assert_eq!(m.state_free_inodes(), free_before - 1, "equal values share one EA inode");
    let (raw, _) = m.read_inode_bytes(n).unwrap();
    let block = read_fs_block(&disk.0, file_acl(&raw), m.sb.block_size);
    let first = u32::from_le_bytes(block[36..40].try_into().unwrap());
    let second = u32::from_le_bytes(block[56..60].try_into().unwrap());
    assert_ne!(first, 0);
    assert_eq!(second, first, "both entries reference one hidden inode");
    let ea_raw = m.read_inode_bytes(first).unwrap().0;
    let refs = u32::from_le_bytes(ea_raw[0x24..0x28].try_into().unwrap()) as u64
        | (u32::from_le_bytes(ea_raw[0x0C..0x10].try_into().unwrap()) as u64) << 32;
    assert_eq!(refs, 2, "shared inode persists Linux ctime/i_version refcount");

    m.store_xattrs(n, &[entry("user.small", b"x")]).unwrap();
    assert_eq!(m.state_free_inodes(), free_before, "last parent reference releases the EA inode");
}
