use super::*;

#[test]
fn epoll_ctl_add_duplicate_fd_is_eexist() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset(); let fdt = Arc::new(FdTable::new()); install_current_with_fdt(Arc::clone(&fdt)); let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let fd = fdt.alloc(mk_poll_file(Arc::new(AtomicU32::new(0)))).unwrap(); let mut add = epoll_event(vfs::POLL_IN, 1);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, add.as_mut_ptr() as u64)), 0); assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, add.as_mut_ptr() as u64)), -(Errno::Eexist.as_i32() as i64)); reset();
}

#[test]
fn epoll_ctl_mod_and_del_of_unregistered_fd_is_enoent() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset(); let fdt = Arc::new(FdTable::new()); install_current_with_fdt(Arc::clone(&fdt)); let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let fd = fdt.alloc(mk_poll_file(Arc::new(AtomicU32::new(0)))).unwrap(); let mut ev = epoll_event(vfs::POLL_IN, 1);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_MOD, fd as u64, ev.as_mut_ptr() as u64)), -(Errno::Enoent.as_i32() as i64)); assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_DEL, fd as u64, 0)), -(Errno::Enoent.as_i32() as i64)); reset();
}

#[test]
fn epoll_hup_is_reported_even_when_not_requested() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset(); let fdt = Arc::new(FdTable::new()); install_current_with_fdt(Arc::clone(&fdt)); let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let fd = fdt.alloc(mk_poll_file(Arc::new(AtomicU32::new(EPOLLHUP)))).unwrap(); let mut add = epoll_event(vfs::POLL_OUT, 0x8100_0060);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, add.as_mut_ptr() as u64)), 0); let mut out = [0u8; 12]; assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1); assert_eq!(read_epoll_event(&out).0, EPOLLHUP); reset();
}

#[test]
fn epoll_exclusive_rejects_mod() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset(); let fdt = Arc::new(FdTable::new()); install_current_with_fdt(Arc::clone(&fdt)); let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let fd = fdt.alloc(mk_poll_file(Arc::new(AtomicU32::new(0)))).unwrap(); let mut add = epoll_event(vfs::POLL_IN | EPOLLEXCLUSIVE, 1);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, add.as_mut_ptr() as u64)), 0); let mut modev = epoll_event(vfs::POLL_IN | EPOLLEXCLUSIVE, 2); assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_MOD, fd as u64, modev.as_mut_ptr() as u64)), -(Errno::Einval.as_i32() as i64)); reset();
}

#[test]
fn epoll_exclusive_rejects_nested_epoll_target() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset(); let fdt = Arc::new(FdTable::new()); install_current_with_fdt(fdt); let outer = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let inner = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let mut add = epoll_event(vfs::POLL_IN | EPOLLEXCLUSIVE, 1);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(outer as u64, EPOLL_CTL_ADD, inner as u64, add.as_mut_ptr() as u64)), -(Errno::Einval.as_i32() as i64)); reset();
}

#[test]
fn epoll_exclusive_rejects_bits_outside_ok_mask() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset(); let fdt = Arc::new(FdTable::new()); install_current_with_fdt(Arc::clone(&fdt)); let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let fd = fdt.alloc(mk_poll_file(Arc::new(AtomicU32::new(0)))).unwrap(); let mut add = epoll_event(vfs::POLL_IN | EPOLLPRI | EPOLLEXCLUSIVE, 1);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, add.as_mut_ptr() as u64)), -(Errno::Einval.as_i32() as i64)); let mut ok = epoll_event(vfs::POLL_IN | EPOLLWAKEUP | EPOLLET | EPOLLEXCLUSIVE, 2); assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, ok.as_mut_ptr() as u64)), 0); reset();
}

#[test]
fn epoll_wait_maxevents_out_of_range_is_einval() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset(); let fdt = Arc::new(FdTable::new()); install_current_with_fdt(fdt); let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let mut out = [0u8; 12];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 0, 0)), -(Errno::Einval.as_i32() as i64)); assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, u32::MAX as u64, 0)), -(Errno::Einval.as_i32() as i64)); reset();
}

#[test]
fn epoll_ctl_bad_event_pointer_takes_precedence_over_bad_fds() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset(); let fdt = Arc::new(FdTable::new()); install_current_with_fdt(fdt);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(9999, EPOLL_CTL_ADD, 9998, 0)), -(Errno::Efault.as_i32() as i64)); reset();
}
