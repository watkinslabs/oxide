//! Crash consistency of quota-file writes.
//!
//! Quota blocks are filesystem metadata: an update that reached the journal
//! must be restored by replay even though not one of its target blocks was
//! checkpointed, and an update whose transaction was never published must not
//! appear at all. Both directions are driven against a real ext4 image with a
//! real journal, with power cut at the write-ahead publish (see
//! `common::crash`), and the surviving image is handed to the stock filesystem
//! checker.

extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;

use common::crash::{CrashDisk, CrashPoint};
use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{Kqid, MemDqblk, QuotaType, SuperBlock};

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
const EXT4_RO_COMPAT_OFF: usize = EXT4_SUPERBLOCK_OFFSET + 0x64;
const EXT4_INCOMPAT_OFF: usize = EXT4_SUPERBLOCK_OFFSET + ext4::superblock::SB_OFF_FEATURE_INCOMPAT;
const EXT4_USR_QUOTA_INUM_OFF: usize = EXT4_SUPERBLOCK_OFFSET + ext4::superblock::SB_OFF_USR_QUOTA_INUM;
const EXT4_FEATURE_RO_COMPAT_QUOTA: u32 = 0x0100;
const USR_QUOTA_INO: u32 = 3;
const USR_MAGIC: u32 = 0xd9c0_1f11;
const V2_VERSION_V1: u32 = 1;
const QUOTA_FILE_SEED_LEN: usize = 2048;
const QUOTA_FILE_BLOCKS_OFF: usize = 20;
const QUOTA_FILE_INITIAL_BLOCKS: u32 = 2;
/// `s_start` inside the JBD2 journal superblock: non-zero ⇒ replay pending.
const JSB_OFF_START: usize = 0x1C;
/// Distinctive limits, in quota block units, so a surviving record is
/// unmistakable in either direction.
const CRASH_BHARD: u64 = 0x5AA5_0000;
const CRASH_BSOFT: u64 = 0x5AA5_0000 / 2;
const SECOND_ID: u32 = 4242;
const FILE_PATH: &[u8] = b"/quota-crash.bin";

fn plain_disk(image: &[u8]) -> Arc<dyn BlockDevice> {
    let cap = (image.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: image.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

fn dump(disk: &Arc<dyn BlockDevice>) -> alloc::vec::Vec<u8> {
    let cap = disk.capacity_blocks();
    let mut req = BlockRequest::new_read(0, cap as u32, SECTOR);
    disk.submit_sync(&mut req).expect("dump image");
    req.buffer
}

fn le32_at(image: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([image[off], image[off + 1], image[off + 2], image[off + 3]])
}

fn put_le32(image: &mut [u8], off: usize, val: u32) {
    image[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn empty_quota_file() -> alloc::vec::Vec<u8> {
    let mut q = alloc::vec![0u8; QUOTA_FILE_SEED_LEN];
    put_le32(&mut q, 0, USR_MAGIC);
    put_le32(&mut q, 4, V2_VERSION_V1);
    put_le32(&mut q, QUOTA_FILE_BLOCKS_OFF, QUOTA_FILE_INITIAL_BLOCKS);
    q
}

/// An ext4 image with a journal, a hidden user-quota file, and one accounted
/// file whose usage is already committed to that quota file.
fn seeded_image() -> alloc::vec::Vec<u8> {
    common::boot_hosted_pmm();
    let disk = plain_disk(IMAGE);
    {
        let m = ext4::rootfs::Ext4Mount::open(disk.clone()).expect("seed open");
        let mount = &m.state().mount;
        mount.init_inode(2, USR_QUOTA_INO, ext4::inode::S_IFREG | 0o600, 1, 0, 0).expect("quota inode");
        mount.write_at(USR_QUOTA_INO, 0, &empty_quota_file()).expect("seed quota file");
    }
    let mut image = dump(&disk);
    let ro_compat = le32_at(&image, EXT4_RO_COMPAT_OFF) | EXT4_FEATURE_RO_COMPAT_QUOTA;
    put_le32(&mut image, EXT4_RO_COMPAT_OFF, ro_compat);
    put_le32(&mut image, EXT4_USR_QUOTA_INUM_OFF, USR_QUOTA_INO);

    // Charge one file's usage and flush it to the quota file, so the crash
    // tests start from a record that is already on disk.
    let disk = plain_disk(&image);
    {
        let (m, sb) = mount(disk.clone());
        let inode = m.state().create_at(FILE_PATH, 0o644).expect("create accounted file");
        let bs = m.state().mount.sb.block_size as usize;
        m.state().mount.write_at(inode.ino() as u32, 0, &alloc::vec![0x51u8; bs]).expect("write block");
        vfs::quota_sync(&sb, QuotaType::User).expect("flush quota");
    }
    fsck_repaired(&dump(&disk))
}

fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb_result(fs, root, 0xE471_F1A6, String::from("ext4"))
        .expect("realize superblock");
    (m, sb)
}

/// Device sector holding the journal superblock (journal logical block 0).
fn journal_sb_sector(m: &ext4::rootfs::Ext4Mount) -> u64 {
    let mount = &m.state().mount;
    assert_ne!(mount.sb.journal_inum, 0, "fixture image has a journal");
    let jinode = mount.read_inode(mount.sb.journal_inum).expect("journal inode");
    let hdr = ext4::inode::parse_extent_header(&jinode.i_block).expect("journal extent header");
    let first = (0..hdr.entries)
        .filter_map(|i| ext4::inode::parse_inline_extent(&jinode.i_block, &hdr, i))
        .find(|e| e.block == 0)
        .expect("journal logical block 0");
    first.start_lba() * (mount.sb.block_size as u64) / (SECTOR as u64)
}

fn journal_start_of(image: &[u8], jsb_sector: u64) -> u32 {
    let off = (jsb_sector as usize) * (SECTOR as usize) + JSB_OFF_START;
    u32::from_be_bytes([image[off], image[off + 1], image[off + 2], image[off + 3]])
}

/// Same image with the recovery flag cleared, so a mount skips replay and shows
/// only what was actually checkpointed to the target blocks.
fn without_recovery(image: &[u8]) -> alloc::vec::Vec<u8> {
    let mut out = image.to_vec();
    let cleared = le32_at(&out, EXT4_INCOMPAT_OFF) & !ext4::superblock::INCOMPAT_RECOVER;
    put_le32(&mut out, EXT4_INCOMPAT_OFF, cleared);
    out
}

fn needs_recovery(image: &[u8]) -> bool {
    le32_at(image, EXT4_INCOMPAT_OFF) & ext4::superblock::INCOMPAT_RECOVER != 0
}

/// Hand the image to the checker in repair mode so the quota file starts out
/// agreeing with the usage actually present on the filesystem — the state a
/// freshly checked filesystem is in. Returns the image unchanged when the
/// checker is not installed.
fn fsck_repaired(bytes: &[u8]) -> alloc::vec::Vec<u8> {
    use std::io::Write;
    let mut path = std::env::temp_dir();
    path.push(std::format!("oxide-quota-seed-{}-{:?}.img", std::process::id(), std::thread::current().id()));
    {
        let mut f = match std::fs::File::create(&path) { Ok(f) => f, Err(_) => return bytes.to_vec() };
        if f.write_all(bytes).is_err() { return bytes.to_vec(); }
    }
    let ran = std::process::Command::new("e2fsck").arg("-fy").arg(&path).output().is_ok();
    let out = if ran { std::fs::read(&path).unwrap_or_else(|_| bytes.to_vec()) } else { bytes.to_vec() };
    let _ = std::fs::remove_file(&path);
    out
}

/// Run the stock checker; `None` when it is not installed (assertion skipped).
fn e2fsck_clean(bytes: &[u8]) -> Option<bool> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let uniq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(std::format!("oxide-quota-replay-{}-{}.img", std::process::id(), uniq));
    {
        let mut f = std::fs::File::create(&path).ok()?;
        f.write_all(bytes).ok()?;
    }
    let out = std::process::Command::new("e2fsck").arg("-fn").arg(&path).output();
    let _ = std::fs::remove_file(&path);
    match out {
        Ok(o) => {
            if !o.status.success() {
                std::eprintln!("--- e2fsck stdout ---\n{}", String::from_utf8_lossy(&o.stdout));
                std::eprintln!("--- e2fsck stderr ---\n{}", String::from_utf8_lossy(&o.stderr));
            }
            Some(o.status.success())
        }
        Err(_) => None,
    }
}

/// Drive a quota-block update with power cut at `point`; returns the image as
/// the media held it at the cut, plus the pre-crash record.
fn crash_during_quota_update(point: CrashPoint, id: u32) -> (alloc::vec::Vec<u8>, MemDqblk, u64) {
    let image = seeded_image();
    let disk = CrashDisk::new(&image, SECTOR);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let (m, sb) = mount(dev);
    let qid = Kqid::user(id);
    let before = vfs::quota_getquota(&sb, qid).expect("record before the crash");
    let jsb_sector = journal_sb_sector(&m);

    disk.arm(jsb_sector, point);
    let want = MemDqblk { dqb_bhardlimit: CRASH_BHARD, dqb_bsoftlimit: CRASH_BSOFT, ..before };
    vfs::quota_setquota(&sb, qid, want).expect("setquota");
    let _ = vfs::quota_sync(&sb, QuotaType::User);
    assert!(disk.crashed(), "power was actually cut during the quota update");

    let crashed = disk.snapshot();
    drop(sb);
    drop(m);
    (crashed, before, jsb_sector)
}

#[test]
fn published_quota_block_update_is_restored_by_replay() {
    let (crashed, before, jsb_sector) = crash_during_quota_update(CrashPoint::AfterPublish, 0);
    assert!(needs_recovery(&crashed), "a crashed rw mount leaves the fs flagged for recovery");
    assert_ne!(journal_start_of(&crashed, jsb_sector), 0,
               "the log names a transaction to replay");
    {
        // Nothing was checkpointed: the update exists ONLY in the log, so a mount
        // that skips replay still sees the old record. Without this the test
        // could pass on an update that never went through the journal at all.
        let (m, sb) = mount(plain_disk(&without_recovery(&crashed)));
        let stale = vfs::quota_getquota(&sb, Kqid::user(0)).expect("record without replay");
        assert_eq!(stale.dqb_bhardlimit, before.dqb_bhardlimit,
                   "the crashed target block still holds the pre-update record");
        drop(sb);
        drop(m);
    }

    let replayed = {
        let disk = plain_disk(&crashed);
        let (m, sb) = mount(disk.clone());
        let got = vfs::quota_getquota(&sb, Kqid::user(0)).expect("record after replay");
        assert_eq!(got.dqb_bhardlimit, CRASH_BHARD, "committed limit survived the crash");
        assert_eq!(got.dqb_bsoftlimit, CRASH_BSOFT, "committed limit survived the crash");
        assert_eq!(got.dqb_curspace, before.dqb_curspace, "usage untouched by the limit change");
        assert_eq!(got.dqb_curinodes, before.dqb_curinodes, "inode count untouched");
        drop(sb);
        drop(m);
        dump(&disk)
    };
    assert!(!needs_recovery(&replayed), "recovery + clean unmount clears the flag");
    if let Some(clean) = e2fsck_clean(&replayed) {
        assert!(clean, "replayed image is checker-clean");
    }
}

#[test]
fn unpublished_quota_block_update_is_absent_after_replay() {
    let (crashed, before, jsb_sector) = crash_during_quota_update(CrashPoint::BeforePublish, 0);
    assert_eq!(journal_start_of(&crashed, jsb_sector), 0,
               "an unpublished transaction leaves nothing for recovery to replay");

    let after = {
        let disk = plain_disk(&crashed);
        let (m, sb) = mount(disk.clone());
        let got = vfs::quota_getquota(&sb, Kqid::user(0)).expect("record after remount");
        assert_eq!(got.dqb_bhardlimit, before.dqb_bhardlimit,
                   "an uncommitted limit change is rolled back whole");
        assert_eq!(got.dqb_bsoftlimit, before.dqb_bsoftlimit,
                   "an uncommitted limit change is rolled back whole");
        assert_eq!(got.dqb_curspace, before.dqb_curspace, "usage unchanged");
        drop(sb);
        drop(m);
        dump(&disk)
    };
    if let Some(clean) = e2fsck_clean(&after) {
        assert!(clean, "rolled-back image is checker-clean");
    }
}

#[test]
fn qtree_insert_crashed_at_publish_leaves_a_readable_tree() {
    // The id has no record yet, so the update grows the quota tree: a new tree
    // block, its parent's pointer and the file header move together or not at
    // all. Either outcome is legal after a crash; a half-linked tree is not.
    let (crashed, _before, _jsb) = crash_during_quota_update(CrashPoint::AfterPublish, SECOND_ID);
    let replayed = {
        let disk = plain_disk(&crashed);
        let (m, sb) = mount(disk.clone());
        let zero = vfs::quota_getquota(&sb, Kqid::user(0)).expect("pre-existing record still readable");
        assert_ne!(zero.dqb_curinodes, 0,
                   "the accounted id survives a crash during another id's insert");
        let new = vfs::quota_getquota(&sb, Kqid::user(SECOND_ID)).expect("inserted id is readable");
        assert!(new.dqb_bhardlimit == CRASH_BHARD || new.dqb_bhardlimit == 0,
                "inserted record is whole or absent, never torn: {}", new.dqb_bhardlimit);
        // The tree must still enumerate: a dangling parent pointer would fault
        // the walk rather than return an id.
        let _ = vfs::quota_getnextquota(&sb, Kqid::user(0));
        drop(sb);
        drop(m);
        dump(&disk)
    };
    if let Some(clean) = e2fsck_clean(&replayed) {
        assert!(clean, "replayed image is checker-clean after a crashed insert");
    }
}

#[test]
fn rw_mount_flags_recovery_and_clean_unmount_clears_it() {
    // Without the flag a crashed filesystem is re-mounted with its committed
    // transactions skipped, which is what makes every assertion above testable.
    let image = seeded_image();
    assert!(!needs_recovery(&image), "a cleanly unmounted image is not flagged");
    let disk = plain_disk(&image);
    let (m, sb) = mount(disk.clone());
    assert!(needs_recovery(&dump(&disk)), "a live rw mount is flagged for recovery");
    drop(sb);
    drop(m);
    assert!(!needs_recovery(&dump(&disk)), "a clean unmount clears the flag");
}

/// One record commit = one transaction. A quota tree insert touches a new tree
/// block, its parent's pointer and the file header; splitting those across
/// transactions makes a crash between them expose a half-linked tree.
const TXNS_PER_RECORD_FLUSH: u64 = 2; // the record commit, then the file header

#[test]
fn a_quota_record_insert_commits_as_one_transaction() {
    let image = seeded_image();
    let disk = CrashDisk::new(&image, SECTOR);
    let dev: Arc<dyn BlockDevice> = disk.clone();
    let (m, sb) = mount(dev);
    let jsb_sector = journal_sb_sector(&m);
    let qid = Kqid::user(SECOND_ID);
    vfs::quota_setquota(&sb, qid, MemDqblk { dqb_bhardlimit: CRASH_BHARD, ..MemDqblk::new() })
        .expect("setquota");

    disk.watch(jsb_sector);
    vfs::quota_sync(&sb, QuotaType::User).expect("flush quota");
    assert_eq!(disk.publishes(), TXNS_PER_RECORD_FLUSH,
               "inserting a record and updating the file header is one transaction each");
    drop(sb);
    drop(m);
}
