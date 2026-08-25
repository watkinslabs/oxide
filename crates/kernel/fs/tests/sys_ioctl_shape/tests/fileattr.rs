use super::*;

#[test]
fn fibmap_requires_rawio_and_writes_bmap_result() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let ops = Arc::new(IoctlOps::default());
    ops.bmap_block.store(100, Ordering::SeqCst);
    let fdt = Arc::new(FdTable::new());
    let file = mk_file_with_ops(OpenFlags::O_RDONLY, 0, ops);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut block: i32 = 7;

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIBMAP, &mut block as *mut i32 as u64), Some(0));
    assert_eq!(block, 107);
    assert_eq!(userbuf::READABLE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn preallocate_ioctls_adjust_whence_and_call_fallocate_keep_size() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let ops = Arc::new(IoctlOps::default());
    let fdt = Arc::new(FdTable::new());
    let file = mk_file_with_ops(OpenFlags::O_RDWR, 40, Arc::clone(&ops));
    file.set_pos(5);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let sr = SpaceResv { l_type: 0, l_whence: 1, l_start: 3, l_len: 9, l_sysid: 0, l_pid: 0, l_pad: [0; 4] };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_RESVSP, &sr as *const SpaceResv as u64), Some(0));
    let hole = SpaceResv { l_type: 0, l_whence: 2, l_start: -10, l_len: 4, l_sysid: 0, l_pid: 0, l_pad: [0; 4] };
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_UNRESVSP, &hole as *const SpaceResv as u64), Some(0));
    // Linux `ioctl_preallocate` hands `vfs_fallocate` the ioctl's own mode OR'd
    // with FALLOC_FL_KEEP_SIZE — these ioctls reserve space, never resize.
    assert_eq!(*ops.fallocate_calls.lock().unwrap(), vec![
        (vfs::uapi::FALLOC_FL_KEEP_SIZE, 8, 9),
        (vfs::uapi::FALLOC_FL_PUNCH_HOLE | vfs::uapi::FALLOC_FL_KEEP_SIZE, 30, 4),
    ]);
    reset();
}

#[test]
fn fsxattr_get_and_set_translate_linux_xflags() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let ops = Arc::new(IoctlOps::default());
    *ops.attr.lock().unwrap() = FileAttr { flags: 0x10 | 0x80 | uapi::FS_CASEFOLD_FL, fsx_extsize: 64, fsx_nextents: 3, fsx_cowextsize: 128, ..Default::default() };
    let fdt = Arc::new(FdTable::new());
    let file = mk_file_with_ops(OpenFlags::O_RDWR, 0, Arc::clone(&ops));
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut xattr = [0u8; 28];
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_FSGETXATTR, xattr.as_mut_ptr() as u64), Some(0));
    assert_eq!(u32::from_ne_bytes(xattr[0..4].try_into().unwrap()), 0x08 | 0x40 | uapi::FS_XFLAG_CASEFOLD);
    assert_eq!(u32::from_ne_bytes(xattr[4..8].try_into().unwrap()), 64);
    assert_eq!(u32::from_ne_bytes(xattr[8..12].try_into().unwrap()), 3);
    assert_eq!(u32::from_ne_bytes(xattr[16..20].try_into().unwrap()), 128);
    xattr[0..4].copy_from_slice(&(0x10u32 | 0x80u32 | vfs::inode::FS_XFLAG_EXTSIZE | vfs::inode::FS_XFLAG_COWEXTSIZE).to_ne_bytes());
    xattr[4..8].copy_from_slice(&256u32.to_ne_bytes());
    xattr[8..12].copy_from_slice(&7u32.to_ne_bytes());
    xattr[12..16].copy_from_slice(&42u32.to_ne_bytes());
    xattr[16..20].copy_from_slice(&512u32.to_ne_bytes());
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_FSSETXATTR, xattr.as_ptr() as u64), Some(0));
    assert_eq!(*ops.attr.lock().unwrap(), FileAttr {
        flags: 0x20 | 0x40 | uapi::FS_CASEFOLD_FL,
        fsx_xflags: 0x10 | 0x80 | vfs::inode::FS_XFLAG_EXTSIZE | vfs::inode::FS_XFLAG_COWEXTSIZE,
        fsx_extsize: 256,
        fsx_nextents: 7,
        fsx_projid: 42,
        fsx_cowextsize: 512,
    });
    reset();
}

#[test]
fn fsxattr_set_rejects_extsize_hint_on_non_regular_file() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let ops = Arc::new(IoctlOps::default());
    let fdt = Arc::new(FdTable::new());
    let file = mk_file_with_ops_type(FileType::Directory, OpenFlags::O_RDWR, 0, Arc::clone(&ops));
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut xattr = [0u8; 28];
    xattr[0..4].copy_from_slice(&vfs::inode::FS_XFLAG_EXTSIZE.to_ne_bytes());
    xattr[4..8].copy_from_slice(&64u32.to_ne_bytes());
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_FSSETXATTR, xattr.as_ptr() as u64), Some(-(Errno::Einval.as_i32() as i64)));
    assert_eq!(*ops.attr.lock().unwrap(), FileAttr::default());
    reset();
}

#[test]
fn unsupported_fileattr_ioctls_return_enotty() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let file = mk_file(FileType::Regular, OpenFlags::O_RDWR, 0);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut flags = 0u32;
    let mut xattr = [0u8; 28];

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_GETFLAGS, &mut flags as *mut u32 as u64),
        Some(-(Errno::Enotty.as_i32() as i64)));
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_SETFLAGS, &flags as *const u32 as u64),
        Some(-(Errno::Enotty.as_i32() as i64)));
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_FSGETXATTR, xattr.as_mut_ptr() as u64),
        Some(-(Errno::Enotty.as_i32() as i64)));
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_FSSETXATTR, xattr.as_ptr() as u64),
        Some(-(Errno::Enotty.as_i32() as i64)));
    reset();
}

#[test]
fn getfsuuid_copies_superblock_uuid_or_enotty_without_one() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let uuid = [0xAB; 16];
    let file = mk_file_with_uuid(uuid);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut out = [0u8; 17];

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_GETFSUUID, out.as_mut_ptr() as u64), Some(0));
    assert_eq!(out[0], 16);
    assert_eq!(&out[1..], &uuid);
    reset();
}

#[test]
fn getfssysfspath_uses_superblock_sysfs_name_or_enotty() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let empty = mk_file_with_sysfs_name(None);
    let empty_fd = fdt.alloc(Arc::clone(&empty)).unwrap();
    let file = mk_file_with_sysfs_name(Some("vda1"));
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut out = [0xAAu8; 129];

    assert_eq!(ioctl_common::handle_common_ioctl(task, &empty, &fdt, empty_fd, uapi::FS_IOC_GETFSSYSFSPATH, out.as_mut_ptr() as u64),
        Some(-(Errno::Enotty.as_i32() as i64)));
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FS_IOC_GETFSSYSFSPATH, out.as_mut_ptr() as u64), Some(0));
    assert_eq!(out[0], b"sysfsnamefs/vda1".len() as u8);
    assert_eq!(&out[1..17], b"sysfsnamefs/vda1");
    assert_eq!(out[17], 0);
    assert!(out[18..].iter().all(|b| *b == 0));
    reset();
}

