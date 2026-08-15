use super::*;
use crate::dirent::{ATTR_ARCH, ATTR_DIR, ATTR_RO};
use alloc::vec::Vec;
use block::{BlockDevice, BlockError, BlockOp, BlockRequest};

const VOL_SECTOR: usize = 512;
const SEC_PER_CLUS: usize = 1;
const RESERVED: usize = 1;
const FATS: usize = 1;
const FAT_SECTORS: usize = 64;
const ROOT_ENTRIES: usize = 16;
const TOTAL_SECTORS: usize = 16384;

/// A block device holding a FAT16 image, with a block size that is
/// deliberately NOT the volume's sector size — the translation between the two
/// is a real decision and this is what exercises it.
struct Disk { bytes: Vec<u8>, block_size: u32 }

impl BlockDevice for Disk {
    fn block_size(&self) -> u32 { self.block_size }
    fn capacity_blocks(&self) -> u64 { self.bytes.len() as u64 / u64::from(self.block_size) }
    fn submit_sync(&self, req: &mut BlockRequest) -> block::KResult<()> {
        if req.op != BlockOp::Read { return Err(BlockError::Eopnotsupp); }
        let bs = self.block_size as usize;
        let at = req.start_block as usize * bs;
        let len = req.len_blocks as usize * bs;
        if at + len > self.bytes.len() { return Err(BlockError::Eio); }
        req.buffer = self.bytes[at..at + len].to_vec();
        Ok(())
    }
    fn flush(&self) -> block::KResult<()> { Ok(()) }
}

fn image(block_size: u32) -> Arc<Disk> {
    let mut b = vec![0u8; TOTAL_SECTORS * VOL_SECTOR];
    b[0x0b..0x0d].copy_from_slice(&(VOL_SECTOR as u16).to_le_bytes());
    b[0x0d] = SEC_PER_CLUS as u8;
    b[0x0e..0x10].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    b[0x10] = FATS as u8;
    b[0x11..0x13].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    b[0x13..0x15].copy_from_slice(&(TOTAL_SECTORS as u16).to_le_bytes());
    b[0x15] = 0xf8;
    b[0x16..0x18].copy_from_slice(&(FAT_SECTORS as u16).to_le_bytes());

    let fat = RESERVED * VOL_SECTOR;
    let root = (RESERVED + FATS * FAT_SECTORS) * VOL_SECTOR;
    let data = root + ROOT_ENTRIES * crate::dirent::ENTRY_BYTES;
    let put_fat = |b: &mut Vec<u8>, cluster: usize, value: u16| {
        b[fat + cluster * 2..fat + cluster * 2 + 2].copy_from_slice(&value.to_le_bytes());
    };
    put_fat(&mut b, 0, 0xFFF8);
    put_fat(&mut b, 1, 0xFFFF);
    // Cluster 2: a file. Cluster 3: a subdirectory holding one file in 4.
    put_fat(&mut b, 2, 0xFFFF);
    put_fat(&mut b, 3, 0xFFFF);
    put_fat(&mut b, 4, 0xFFFF);
    let cluster_at = |c: usize| data + (c - 2) * SEC_PER_CLUS * VOL_SECTOR;
    b[cluster_at(2)..cluster_at(2) + 5].copy_from_slice(b"hello");
    b[cluster_at(4)..cluster_at(4) + 6].copy_from_slice(b"nested");

    let write_entry = |b: &mut Vec<u8>, at: usize, name: &[u8; 11], attr: u8, cluster: u16, size: u32| {
        b[at..at + 11].copy_from_slice(name);
        b[at + 11] = attr;
        b[at + 26..at + 28].copy_from_slice(&cluster.to_le_bytes());
        b[at + 28..at + 32].copy_from_slice(&size.to_le_bytes());
    };
    let e = crate::dirent::ENTRY_BYTES;
    write_entry(&mut b, root, b"HELLO   TXT", ATTR_ARCH, 2, 5);
    write_entry(&mut b, root + e, b"SUBDIR     ", ATTR_DIR, 3, 0);
    write_entry(&mut b, root + 2 * e, b"LOCKED  CFG", ATTR_ARCH | ATTR_RO, 2, 5);
    let sub = cluster_at(3);
    write_entry(&mut b, sub, b".          ", ATTR_DIR, 3, 0);
    write_entry(&mut b, sub + e, b"..         ", ATTR_DIR, 0, 0);
    write_entry(&mut b, sub + 2 * e, b"NESTED  TXT", ATTR_ARCH, 4, 6);

    Arc::new(Disk { bytes: b, block_size })
}

fn mounted(block_size: u32) -> Arc<FatFs> {
    FatFs::open(image(block_size) as Arc<dyn BlockDevice>, "/dev/loop0").expect("mount")
}

/// The whole path from a block device to a file's bytes, through the VFS
/// operations a caller actually uses.
#[test]
fn a_volume_mounts_and_its_files_read_through_the_vfs_operations() {
    let fs = mounted(512);
    let root = fs.root_inode();
    assert_eq!(root.file_type(), FileType::Directory);

    let hello = root.lookup("HELLO.TXT").expect("lookup");
    assert_eq!(hello.file_type(), FileType::Regular);
    assert_eq!(hello.size(), 5);
    let mut buf = [0u8; 8];
    let got = hello.read(0, &mut buf).expect("read");
    assert_eq!(&buf[..got], b"hello");
}

/// The device's block size need not be the volume's sector size. A reader
/// that assumes they match reads the wrong offset on any 4 KiB-sector device,
/// which is most modern media.
#[test]
fn a_device_whose_blocks_are_not_the_volumes_sectors_still_reads() {
    for block_size in [512u32, 1024, 2048, 4096] {
        let fs = mounted(block_size);
        let root = fs.root_inode();
        let hello = root.lookup("hello.txt").expect("lookup is case-insensitive");
        let mut buf = [0u8; 8];
        let got = hello.read(0, &mut buf).expect("read");
        assert_eq!(&buf[..got], b"hello", "block size {block_size}");
    }
}

/// A subdirectory resolves and its file reads, so the tree is walkable.
#[test]
fn a_subdirectorys_file_resolves_and_reads() {
    let fs = mounted(4096);
    let root = fs.root_inode();
    let sub = root.lookup("SUBDIR").expect("subdir");
    assert_eq!(sub.file_type(), FileType::Directory);
    let nested = sub.lookup("NESTED.TXT").expect("nested");
    let mut buf = [0u8; 16];
    let got = nested.read(0, &mut buf).expect("read");
    assert_eq!(&buf[..got], b"nested");
}

/// A read-only entry presents without write bits, rather than reporting
/// itself writable and failing at the first write.
#[test]
fn a_read_only_entry_presents_without_write_bits() {
    let fs = mounted(512);
    let root = fs.root_inode();
    let locked = root.lookup("LOCKED.CFG").expect("lookup");
    assert_eq!(locked.perm().unwrap_or(0) & 0o222, 0, "no write bits anywhere");
    let plain = root.lookup("HELLO.TXT").expect("lookup");
    assert_ne!(plain.perm().unwrap_or(0) & 0o200, 0, "an ordinary file keeps its owner write bit");
}

/// A missing name is `ENOENT`, and a file is not a directory.
#[test]
fn the_refusals_reach_the_caller_unchanged() {
    let fs = mounted(512);
    let root = fs.root_inode();
    assert_eq!(root.lookup("absent.txt").err(), Some(VfsError::Enoent));
    let hello = root.lookup("HELLO.TXT").expect("lookup");
    assert_eq!(hello.lookup("anything").err(), Some(VfsError::Enotdir));
}

/// The same file looked up twice reports the same inode number, and two
/// different files do not share one — the property a dentry cache above this
/// depends on.
#[test]
fn identity_is_stable_across_lookups_and_distinct_between_files() {
    let fs = mounted(512);
    let root = fs.root_inode();
    let a = root.lookup("HELLO.TXT").expect("lookup").ino();
    let b = root.lookup("HELLO.TXT").expect("lookup").ino();
    assert_eq!(a, b, "the same file keeps its identity");
    let sub = root.lookup("SUBDIR").expect("lookup").ino();
    assert_ne!(a, sub);
    assert_ne!(a, root.ino());
    assert_ne!(sub, root.ino());
}

/// The filesystem reports itself as the reference names it, so `/proc/mounts`
/// and `statfs(2)` agree with what a caller asked to mount.
#[test]
fn the_filesystem_reports_the_reference_identity() {
    let fs = mounted(512);
    use vfs::fs::FileSystem;
    assert_eq!(fs.name(), "vfat");
    assert_eq!(fs.magic(), MSDOS_SUPER_MAGIC);
    assert_eq!(fs.magic(), 0x4d44);
    assert!(fs.requires_dev(), "a FAT mount needs a device");
    assert_eq!(fs.block_size(), VOL_SECTOR as u32);
}

/// A device holding something that is not a FAT volume is refused at mount.
#[test]
fn a_device_without_a_volume_is_refused() {
    let disk = Arc::new(Disk { bytes: vec![0u8; 4096], block_size: 512 });
    assert!(FatFs::open(disk as Arc<dyn BlockDevice>, "/dev/loop0").is_err());
}
