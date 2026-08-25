use super::*;

#[test]
fn fioclex_and_fionclex_update_fdtable_close_on_exec() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file(FileType::Regular, OpenFlags::O_RDONLY, 0)).unwrap();

    let task = install_current_with_fdt(Arc::clone(&fdt));

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file_for(&fdt, fd), &fdt, fd, uapi::FIOCLEX, 0), Some(0));
    assert_eq!(fdt.cloexec(fd), Ok(true));
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file_for(&fdt, fd), &fdt, fd, uapi::FIONCLEX, 0), Some(0));
    assert_eq!(fdt.cloexec(fd), Ok(false));
    reset();
}

#[test]
fn fionbio_is_common_before_chardev_fallback_and_bad_pointer_faults() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let file = mk_file(FileType::CharDev, OpenFlags::O_RDONLY, 0);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut on: i32 = 1;

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIONBIO, &mut on as *mut i32 as u64), Some(0));
    assert!(file.flags().contains(OpenFlags::O_NONBLOCK));
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIONBIO, 0), Some(-(Errno::Efault.as_i32() as i64)));
    reset();
}

#[test]
fn regular_fionread_reports_size_minus_position_as_linux_common_ioctl() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let file = mk_file(FileType::Regular, OpenFlags::O_RDONLY, 12);
    file.set_pos(5);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut out: i32 = -1;

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIONREAD, &mut out as *mut i32 as u64), Some(0));
    assert_eq!(out, 7);
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 1);
    reset();
}

#[test]
fn regular_fionread_reports_negative_size_minus_position_past_eof() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let file = mk_file(FileType::Regular, OpenFlags::O_RDONLY, 12);
    file.set_pos(20);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));
    let mut out: i32 = 99;

    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIONREAD, &mut out as *mut i32 as u64), Some(0));
    assert_eq!(out, -8);
    reset();
}

#[test]
fn socket_fionread_rejects_null_out_pointer_instead_of_succeeding() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(mk_file_with_fop(FileType::Socket, OpenFlags::O_RDWR, 0, RemapOps::new(Ok(0)))).unwrap();
    let task = install_current_with_fdt(Arc::clone(&fdt));

    let file = file_for(&fdt, fd);
    assert_eq!(ioctl_common::handle_common_ioctl(task, &file, &fdt, fd, uapi::FIONREAD, 0), None);
    assert_eq!(ioctl_common::handle_nonchar_queue_ioctl(&file, uapi::FIONREAD, 0), Some(-(Errno::Efault.as_i32() as i64)));
    assert_eq!(userbuf::WRITABLE_CALLS.load(Ordering::SeqCst), 1);
    reset();
}

