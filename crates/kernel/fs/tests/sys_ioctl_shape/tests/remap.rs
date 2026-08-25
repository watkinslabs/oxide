use super::*;

#[test]
fn ficlone_bad_source_fd_precedes_destination_mode_checks() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let dst = mk_file(FileType::Regular, OpenFlags::O_RDONLY, 0);
    let fd = fdt.alloc(Arc::clone(&dst)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));

    assert_eq!(ioctl_common::handle_common_ioctl(task, &dst, &fdt, fd, uapi::FICLONE, 99),
        Some(-(Errno::Ebadf.as_i32() as i64)));
    reset();
}

#[test]
fn ficlone_zero_length_expands_to_source_eof_like_linux() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new(Ok(20));
    let fdt = Arc::new(FdTable::new());
    let src = mk_file_with_fop(FileType::Regular, OpenFlags::O_RDONLY, 20, remap.clone());
    let dst = mk_file_with_fop(FileType::Regular, OpenFlags::O_RDWR, 0, remap.clone());
    let src_fd = fdt.alloc(src).unwrap();
    let dst_fd = fdt.alloc(Arc::clone(&dst)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));

    assert_eq!(ioctl_common::handle_common_ioctl(task, &dst, &fdt, dst_fd, uapi::FICLONE, src_fd as u64), Some(0));
    assert_eq!(*remap.calls.lock().unwrap(), vec![(0, 0, 20, 0)]);
    reset();
}

#[test]
fn ficlonerange_rejects_unshortenable_range_past_source_eof_before_backend() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new(Ok(1));
    let fdt = Arc::new(FdTable::new());
    let src = mk_file_with_fop(FileType::Regular, OpenFlags::O_RDONLY, 20, remap.clone());
    let dst = mk_file_with_fop(FileType::Regular, OpenFlags::O_RDWR, 0, remap.clone());
    let src_fd = fdt.alloc(src).unwrap();
    let dst_fd = fdt.alloc(Arc::clone(&dst)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let range = FileCloneRange { src_fd: src_fd as i64, src_offset: 12, src_length: 16, dest_offset: 0 };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &dst, &fdt, dst_fd, uapi::FICLONERANGE, &range as *const FileCloneRange as u64),
        Some(-(Errno::Einval.as_i32() as i64)));
    assert!(remap.calls.lock().unwrap().is_empty());
    reset();
}

#[test]
fn ficlone_uses_linux_vfs_admission_and_reports_missing_remap_op() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let src = mk_file(FileType::Regular, OpenFlags::O_RDONLY, 20);
    let dst = mk_file(FileType::Regular, OpenFlags::O_RDWR, 0);
    let src_fd = fdt.alloc(src).unwrap();
    let dst_fd = fdt.alloc(Arc::clone(&dst)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));

    assert_eq!(ioctl_common::handle_common_ioctl(task, &dst, &fdt, dst_fd, uapi::FICLONE, src_fd as u64),
        Some(-(Errno::Eopnotsupp.as_i32() as i64)));
    reset();
}

#[test]
fn ficlonerange_copies_struct_and_rejects_short_backend_clone() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new(Ok(9));
    let fdt = Arc::new(FdTable::new());
    let src = mk_file_with_fop(FileType::Regular, OpenFlags::O_RDONLY, 20, remap.clone());
    let dst = mk_file(FileType::Regular, OpenFlags::O_RDWR, 0);
    let src_fd = fdt.alloc(src).unwrap();
    let dst_fd = fdt.alloc(Arc::clone(&dst)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let range = FileCloneRange { src_fd: src_fd as i64, src_offset: 3, src_length: 10, dest_offset: 5 };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &dst, &fdt, dst_fd, uapi::FICLONERANGE, &range as *const FileCloneRange as u64),
        Some(-(Errno::Einval.as_i32() as i64)));
    assert_eq!(*remap.calls.lock().unwrap(), vec![(3, 5, 10, 0)]);
    reset();
}

#[test]
fn fideduperange_writes_per_destination_linux_statuses() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let remap = RemapOps::new(Ok(4));
    let fdt = Arc::new(FdTable::new());
    let src = mk_file_with_fop(FileType::Regular, OpenFlags::O_RDONLY, 20, remap.clone());
    let dst_ok = mk_file_with_fop(FileType::Regular, OpenFlags::O_RDWR, 20, remap.clone());
    let dst_no_remap = mk_file(FileType::Regular, OpenFlags::O_RDWR, 20);
    let dst_ok_fd = fdt.alloc(dst_ok).unwrap();
    let dst_no_remap_fd = fdt.alloc(dst_no_remap).unwrap();
    let src_fd = fdt.alloc(Arc::clone(&src)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut range = FileDedupeRangeOne {
        src_offset: 2,
        src_length: 4,
        dest_count: 2,
        reserved1: 0,
        reserved2: 0,
        info: [
            FileDedupeRangeInfo { dest_fd: dst_ok_fd as i64, dest_offset: 6, bytes_deduped: 99, status: -99, reserved: 0 },
            FileDedupeRangeInfo { dest_fd: dst_no_remap_fd as i64, dest_offset: 8, bytes_deduped: 99, status: -99, reserved: 0 },
        ],
    };

    assert_eq!(ioctl_common::handle_common_ioctl(task, &src, &fdt, src_fd, uapi::FIDEDUPERANGE, &mut range as *mut FileDedupeRangeOne as u64),
        Some(0));
    assert_eq!(range.info[0].bytes_deduped, 4);
    assert_eq!(range.info[0].status, 0);
    assert_eq!(range.info[1].bytes_deduped, 0);
    assert_eq!(range.info[1].status, -(Errno::Einval.as_i32()));
    assert_eq!(*remap.calls.lock().unwrap(), vec![(2, 6, 4, 3)]);
    reset();
}

