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
