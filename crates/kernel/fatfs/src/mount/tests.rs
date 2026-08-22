use super::*;
use alloc::string::String;
use alloc::vec;
use vfs::FileType;
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

/// A saved cursor names the next on-medium record, not the entry's ordinal in
/// a filtered listing. Removing an earlier name therefore cannot shift it.
#[test]
fn a_readdir_cookie_survives_deleting_an_earlier_name() {
    struct Page { names: Vec<String>, cap: usize }
    impl vfs::DirEmit for Page {
        fn emit(&mut self, name: &str, _ino: u64, _kind: FileType, _next: u64) -> bool {
            if self.names.len() >= self.cap { return false; }
            self.names.push(name.into());
            true
        }
    }

    let fs = writable_mount("vfat", crate::opts::Options::vfat());
    let root = fs.root_inode();
    let mut first = Page { names: Vec::new(), cap: 4 };
    let mut ctx = vfs::DirContext::new(0, &mut first);
    root.readdir(&mut ctx).expect("first page");
    let cookie = ctx.pos;
    drop(ctx);
    assert_eq!(first.names, [".", "..", "HELLO.TXT", "SUBDIR"]);
    assert_eq!(cookie, (2 * crate::dirent::ENTRY_BYTES) as u64,
               "cookie is the byte offset after SUBDIR's record");

    root.unlink_child("HELLO.TXT").expect("delete the earlier record");
    let mut rest = Page { names: Vec::new(), cap: usize::MAX };
    let mut resumed = vfs::DirContext::new(cookie, &mut rest);
    root.readdir(&mut resumed).expect("resumed page");
    assert_eq!(rest.names, ["LOCKED.CFG"]);
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

/// The same image on a device that accepts writes, so the VFS operations can
/// be driven end to end rather than only their refusals.
struct RwDisk { bytes: sync::Spinlock<Vec<u8>, sync::TaskList>, block_size: u32 }

impl BlockDevice for RwDisk {
    fn block_size(&self) -> u32 { self.block_size }
    fn capacity_blocks(&self) -> u64 {
        self.bytes.lock().len() as u64 / u64::from(self.block_size)
    }
    fn submit_sync(&self, req: &mut BlockRequest) -> block::KResult<()> {
        let bs = self.block_size as usize;
        let at = req.start_block as usize * bs;
        let len = req.len_blocks as usize * bs;
        let mut bytes = self.bytes.lock();
        if at + len > bytes.len() { return Err(BlockError::Eio); }
        match req.op {
            BlockOp::Read => { req.buffer = bytes[at..at + len].to_vec(); Ok(()) }
            BlockOp::Write => {
                if req.buffer.len() < len { return Err(BlockError::Eio); }
                bytes[at..at + len].copy_from_slice(&req.buffer[..len]);
                Ok(())
            }
            _ => Err(BlockError::Eopnotsupp),
        }
    }
    fn flush(&self) -> block::KResult<()> { Ok(()) }
}

fn writable_mount(type_name: &'static str, opts: crate::opts::Options) -> Arc<FatFs> {
    let disk = image(512);
    let rw = Arc::new(RwDisk { bytes: sync::Spinlock::new(disk.bytes.clone()), block_size: 512 });
    FatFs::open_typed(rw as Arc<dyn BlockDevice>, "/dev/loop0", true, type_name, opts)
        .expect("mount")
}

/// A writable FAT instance realized through the same superblock boundary a
/// production mount uses. # C: O(image bytes)
fn writable_vfs_mount() -> (Arc<FatFs>, Arc<vfs::SuperBlock>) {
    let fs = writable_mount("vfat", crate::opts::Options::vfat());
    let any: Arc<dyn vfs::fs::FileSystem> = fs.clone();
    let root = Some(fs.root_inode());
    let s_op = any.super_ops().expect("FAT super operations");
    let ty: Arc<dyn vfs::FileSystemType> = vfs::fs::FsType::new(
        any.name(), any.magic(), any.fs_flags(),
        alloc::boxed::Box::new(|_, _, _, _, _, _| unreachable!("fixture is already mounted")));
    let sb = vfs::SuperBlock::from_ops(ty, s_op, root, any.magic(), 0xFA70_0001,
        any.block_size(), String::from("fatfs"), Arc::new(()));
    any.set_sb(Arc::downgrade(&sb)).expect("set superblock");
    (fs, sb)
}

fn ctx() -> vfs::CreateCtx<'static> { vfs::CreateCtx::root() }

/// Every namei operation reaches the volume through the VFS vector a real
/// `mount -t vfat` uses. Anything short of this is machinery with no caller.
#[test]
fn the_vfs_operations_create_remove_and_rename_on_the_medium() {
    let fs = writable_mount("vfat", {
        let mut o = crate::opts::Options::vfat();
        o.settle();
        o
    });
    let root = fs.root_inode();

    let made = root.create_child("A New File.txt", 0o644, &ctx()).expect("create");
    assert_eq!(made.file_type(), FileType::Regular);
    assert_eq!(made.size(), 0);
    made.write(0, b"contents").expect("write");
    let found = root.lookup("A New File.txt").expect("lookup finds the long name");
    let mut buf = [0u8; 16];
    let got = found.read(0, &mut buf).expect("read");
    assert_eq!(&buf[..got], b"contents");

    let dir = root.mkdir("MADEDIR", 0o755, &ctx()).expect("mkdir");
    assert_eq!(dir.file_type(), FileType::Directory);
    dir.create_child("inner.txt", 0o644, &ctx()).expect("create inside it");
    assert!(dir.lookup("inner.txt").is_ok());
    // A directory with something in it is not removable.
    assert_eq!(root.rmdir("MADEDIR").err(), Some(VfsError::Enotempty));
    dir.unlink_child("inner.txt").expect("unlink");
    root.rmdir("MADEDIR").expect("now it goes");
    assert_eq!(root.lookup("MADEDIR").err(), Some(VfsError::Enoent));

    root.rename_child("A New File.txt", &root, "renamed.txt", 0, &ctx()).expect("rename");
    assert_eq!(root.lookup("A New File.txt").err(), Some(VfsError::Enoent));
    let moved = root.lookup("renamed.txt").expect("under its new name");
    let got = moved.read(0, &mut buf).expect("read");
    assert_eq!(&buf[..got], b"contents");

    root.unlink_child("renamed.txt").expect("unlink");
    assert_eq!(root.lookup("renamed.txt").err(), Some(VfsError::Enoent));
}

/// The last name and the last open reference are different lifetime edges.
/// Unlink removes the first; only eviction after close may release the chain.
#[test]
fn an_open_file_keeps_its_cluster_until_the_last_reference_goes() {
    let (fs, sb) = writable_vfs_mount();
    let root = sb.s_root_inode().expect("root");
    let inode = root.lookup("HELLO.TXT").expect("existing file");
    let dentry = vfs::Dentry::new_root(inode.clone());
    let file = vfs::File::new(inode.clone(), dentry.clone(), vfs::OpenFlags::O_RDONLY);
    let before = fs.volume.lock().free_clusters();

    root.unlink_child_with_victim("HELLO.TXT", &inode).expect("unlink");
    assert_eq!(fs.volume.lock().free_clusters(), before,
        "unlink released a cluster still owned by the open file");
    let mut bytes = [0u8; 5];
    assert_eq!(file.pread(&mut bytes, 0).expect("read after unlink"), bytes.len());
    assert_eq!(&bytes, b"hello");

    drop(file);
    drop(dentry);
    vfs::file::iput(inode);
    assert_eq!(fs.volume.lock().free_clusters(), before + 1,
        "the final eviction did not release the unlinked file's cluster");
}

#[test]
fn an_open_directory_keeps_its_cluster_until_the_last_reference_goes() {
    let (fs, sb) = writable_vfs_mount();
    let root = sb.s_root_inode().expect("root");
    let inode = root.mkdir("EMPTY", 0o755, &ctx()).expect("mkdir");
    let dentry = vfs::Dentry::new_root(inode.clone());
    let file = vfs::File::new(inode.clone(), dentry.clone(), vfs::OpenFlags::O_RDONLY);
    let before = fs.volume.lock().free_clusters();

    root.rmdir_with_victim("EMPTY", &inode).expect("rmdir");
    assert_eq!(fs.volume.lock().free_clusters(), before,
        "rmdir released a cluster still owned by the open directory");

    drop(file);
    drop(dentry);
    vfs::file::iput(inode);
    assert_eq!(fs.volume.lock().free_clusters(), before + 1,
        "the final eviction did not release the unlinked directory's cluster");
}

/// FAT has no link count and no way to name one file twice, so the slot is
/// absent and the answer is `EPERM` — what a filesystem without the operation
/// reports, and not `EROFS`, which is the read-only-mount verdict.
#[test]
fn a_hard_link_is_refused_with_the_no_such_operation_errno() {
    let fs = writable_mount("vfat", crate::opts::Options::vfat());
    let root = fs.root_inode();
    let target = root.lookup("HELLO.TXT").expect("lookup");
    assert_eq!(root.link_child(&target, "SECOND.TXT", &ctx()).err(), Some(VfsError::Eperm));
    assert_eq!(root.symlink_child("LINK", b"/somewhere", &ctx()).err(), Some(VfsError::Eperm));
}

/// `msdos` is a TYPE, not a spelling of `vfat`: it reads no long-name slot and
/// writes none, so a name it cannot spell in eleven bytes does not exist there.
#[test]
fn the_two_types_are_not_one_type_under_two_names() {
    let vfat = writable_mount("vfat", crate::opts::Options::vfat());
    let msdos = writable_mount("msdos", crate::opts::Options::msdos());
    use vfs::fs::FileSystem;
    assert_eq!(vfat.name(), "vfat");
    assert_eq!(msdos.name(), "msdos");
    // The same call on each: one stores the long name, the other folds it.
    vfat.root_inode().create_child("MixedCaseName.txt", 0o644, &ctx()).expect("create");
    assert!(vfat.root_inode().lookup("MixedCaseName.txt").is_ok());
    msdos.root_inode().create_child("MixedCaseName.txt", 0o644, &ctx()).expect("create");
    // Folded to eleven bytes, and found under the folded spelling.
    assert!(msdos.root_inode().lookup("MIXEDCAS.TXT").is_ok(),
            "the 8.3-only type stored the folded name");
    assert!(vfat.root_inode().lookup("MIXEDCAS.TXT").is_err(),
            "and the long-name type did not");
}

/// The option tail reaches `/proc/mounts`, and it parses back. An empty tail
/// tells a reader nothing about a mount whose whole behaviour is options.
#[test]
fn the_option_tail_is_reported_and_round_trips() {
    let mut o = crate::opts::Options::vfat();
    o.uid = 1000;
    o.dmask = 0o022;
    o.settle();
    let fs = writable_mount("vfat", o);
    use vfs::fs::FileSystem;
    let line = fs.show_options();
    assert!(line.contains(",uid=1000"), "{line}");
    assert!(line.contains(",dmask=0022"), "{line}");
    assert!(line.contains(",codepage=437"), "{line}");
    let back = crate::opts::parse(crate::opts::Options::vfat(), &line).expect("its own output");
    assert_eq!(crate::opts::show(&back), line);
}

/// `statfs` counts in CLUSTERS, which is what an allocation hands out, and the
/// two types report the different longest components they accept.
#[test]
fn statfs_reports_clusters_and_the_types_name_length() {
    use vfs::fs::FileSystem;
    let fs = writable_mount("vfat", crate::opts::Options::vfat());
    let ops = fs.super_ops().expect("a FAT mount owns its superblock operations");
    let st = ops.statfs().expect("statfs");
    assert_eq!(st.f_type, MSDOS_SUPER_MAGIC);
    assert_eq!(u64::from(st.f_bsize), (SEC_PER_CLUS * VOL_SECTOR) as u64);
    assert!(st.f_blocks > 0);
    assert!(st.f_bfree > 0 && st.f_bfree <= st.f_blocks);
    assert_eq!(st.f_bavail, st.f_bfree, "FAT reserves nothing for a privileged caller");
    assert_eq!(st.f_namelen, crate::opts::VFAT_NAME_MAX);

    let msdos = writable_mount("msdos", crate::opts::Options::msdos());
    let st = msdos.super_ops().unwrap().statfs().expect("statfs");
    assert_eq!(st.f_namelen, crate::opts::MSDOS_NAME_MAX);
}

/// Allocating really moves the reported free count, so the check above is
/// reading a live number rather than a constant.
#[test]
fn statfs_free_count_falls_as_the_volume_fills() {
    use vfs::fs::FileSystem;
    let fs = writable_mount("vfat", crate::opts::Options::vfat());
    let ops = fs.super_ops().unwrap();
    let before = ops.statfs().unwrap().f_bfree;
    let made = fs.root_inode().create_child("BIG.BIN", 0o644, &ctx()).expect("create");
    made.write(0, &vec![0u8; SEC_PER_CLUS * VOL_SECTOR * 3]).expect("write");
    assert!(ops.statfs().unwrap().f_bfree < before);
}
