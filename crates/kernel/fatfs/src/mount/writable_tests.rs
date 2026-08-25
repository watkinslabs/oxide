use super::*;

pub(super) fn writable_mount(type_name: &'static str, opts: crate::opts::Options) -> Arc<FatFs> {
    writable_mount_with_disk(type_name, opts).0
}

fn writable_mount_with_disk(type_name: &'static str, opts: crate::opts::Options)
    -> (Arc<FatFs>, Arc<RwDisk>) {
    let disk = image(512);
    let rw = Arc::new(RwDisk { bytes: sync::Spinlock::new(disk.bytes.clone()), block_size: 512,
                               flushes: AtomicUsize::new(0) });
    let fs = FatFs::open_typed(rw.clone() as Arc<dyn BlockDevice>, "/dev/loop0", true, type_name, opts)
        .expect("mount");
    (fs, rw)
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

fn writable_vfs_mount_with_options(opts: crate::opts::Options)
    -> (Arc<FatFs>, Arc<vfs::SuperBlock>, Arc<RwDisk>) {
    let (fs, disk) = writable_mount_with_disk("vfat", opts);
    let any: Arc<dyn vfs::fs::FileSystem> = fs.clone();
    let root = Some(fs.root_inode());
    let s_op = any.super_ops().expect("FAT super operations");
    let ty: Arc<dyn vfs::FileSystemType> = vfs::fs::FsType::new(
        any.name(), any.magic(), any.fs_flags(),
        alloc::boxed::Box::new(|_, _, _, _, _, _| unreachable!("fixture is already mounted")));
    let sb = vfs::SuperBlock::from_ops(ty, s_op, root, any.magic(), 0xFA70_0002,
        any.block_size(), String::from("fatfs"), Arc::new(()));
    any.set_sb(Arc::downgrade(&sb)).expect("set superblock");
    (fs, sb, disk)
}

/// Linux's `nfs=nostale_ro` uses FAT's on-medium entry position rather than
/// the generic cluster-derived inode identity, and it makes the mount
/// read-only so that position cannot be reused.
#[test]
fn nfs_nostale_ro_exports_and_decodes_position_handles() {
    let mut opts = crate::opts::Options::vfat();
    opts.nfs = crate::opts::Nfs::NostaleRo;
    let (fs, sb, _) = writable_vfs_mount_with_options(opts);
    assert!(!fs.is_writable());
    let root = sb.s_root_inode().expect("root");
    let file = root.lookup("HELLO.TXT").expect("file");
    let mut bytes = vec![0u8; sb.s_op.export_fid_len(true, false) as usize];
    let (len, ty) = sb.s_op.export_encode_fh(&file, Some((root.ino(), root.i_generation())), &mut bytes);
    assert_eq!(len, 20);
    assert_eq!(ty, 0x72);
    let fid = sb.s_op.export_decode_fh(&bytes[..len as usize], ty).expect("decode");
    let decoded = sb.s_op.fh_to_dentry(&sb, fid.ino, fid.generation).expect("file");
    assert_eq!(decoded.ino(), file.ino());
    let (parent_ino, parent_generation) = fid.parent.expect("connectable parent");
    let parent = sb.s_op.fh_to_parent(&sb, parent_ino, parent_generation).expect("parent");
    assert_eq!(parent.ino(), root.ino());
    let sub = root.lookup("SUBDIR").expect("subdir");
    let mut dir_bytes = vec![0u8; sb.s_op.export_fid_len(true, true) as usize];
    let (dir_len, dir_type) = sb.s_op.export_encode_fh(&sub, None, &mut dir_bytes);
    assert_eq!(dir_len, 12);
    let dir_fid = sb.s_op.export_decode_fh(&dir_bytes[..dir_len as usize], dir_type)
        .expect("directory decode");
    assert_eq!(sb.s_op.fh_to_dentry(&sb, dir_fid.ino, dir_fid.generation)
        .expect("directory").ino(), sub.ino());
    let nested = sub.lookup("NESTED.TXT").expect("nested file");
    let mut nested_bytes = vec![0u8; sb.s_op.export_fid_len(true, false) as usize];
    let (nested_len, nested_type) = sb.s_op.export_encode_fh(
        &nested, Some((sub.ino(), sub.i_generation())), &mut nested_bytes);
    let nested_fid = sb.s_op.export_decode_fh(&nested_bytes[..nested_len as usize], nested_type)
        .expect("nested decode");
    let nested_parent = sb.s_op.fh_to_parent(
        &sb, nested_fid.parent.expect("nested parent").0,
        nested_fid.parent.expect("nested parent").1).expect("nested parent");
    assert_eq!(nested_parent.ino(), sub.ino());
    assert_eq!(root.create_child("NOPE.TXT", 0o644, &ctx()).err(), Some(VfsError::Erofs));
}

#[test]
fn nfs_default_advertises_the_linux_stale_rw_handles() {
    let (_fs, sb) = writable_vfs_mount();
    assert!(sb.s_op.export_can_decode_fh());
}

fn ctx() -> vfs::CreateCtx<'static> { vfs::CreateCtx::root() }

/// The Linux `flush` mount option is consumed by the per-close file hook and
/// reaches the block-device barrier.
#[test]
fn flush_option_barriers_a_writable_file_close() {
    let mut opts = crate::opts::Options::vfat();
    opts.flush = true;
    let (_fs, sb, disk) = writable_vfs_mount_with_options(opts);
    let root = sb.s_root_inode().expect("root");
    let inode = root.lookup("HELLO.TXT").expect("file");
    let dentry = vfs::Dentry::new_root(inode.clone());
    let file = vfs::File::new(inode, dentry, vfs::OpenFlags::O_WRONLY);
    file.flush(vfs::RecordOwner::Ofd(1)).expect("flush");
    assert_eq!(disk.flushes.load(Ordering::Relaxed), 1);
}

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
