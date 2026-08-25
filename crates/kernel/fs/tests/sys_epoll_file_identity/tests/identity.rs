use super::*;

#[test]
fn duplicate_fd_preserves_epoll_interest_after_fd_reuse() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset();
    let fdt = Arc::new(FdTable::new()); install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); assert_eq!(epfd, 0);
    let old_mask = Arc::new(AtomicU32::new(0));
    let old_fd = fdt.alloc(mk_poll_file(Arc::clone(&old_mask))).unwrap(); assert_eq!(old_fd, 1);
    let old_dup = fdt.dup(old_fd).unwrap(); assert_eq!(old_dup, 2);
    let mut add = epoll_event(vfs::POLL_IN, 0x1002_68d0);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, 1, old_fd as u64, add.as_mut_ptr() as u64)), 0);
    assert_eq!(fdt.close(old_fd), Ok(()));
    let reused_fd = fdt.alloc(mk_poll_file(Arc::new(AtomicU32::new(0)))).unwrap(); assert_eq!(reused_fd, old_fd);
    let mut add_reused = epoll_event(vfs::POLL_IN, 0x2002_68d0);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, 1, reused_fd as u64, add_reused.as_mut_ptr() as u64)), 0);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, 2, reused_fd as u64, 0)), 0);
    old_mask.store(vfs::POLL_IN, Ordering::Release);
    fdt.get(old_dup).unwrap().poll_subscribers().unwrap().notify_mask(vfs::POLL_IN);
    let mut out = [0u8; 12];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1);
    assert_eq!(read_epoll_event(&out), (vfs::POLL_IN, 0x1002_68d0)); reset();
}

#[test]
fn epoll_rejects_direct_self_add() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset();
    let fdt = Arc::new(FdTable::new()); install_current_with_fdt(fdt);
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let mut add = epoll_event(vfs::POLL_IN, 1);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, 1, epfd as u64, add.as_mut_ptr() as u64)), -(Errno::Einval.as_i32() as i64)); reset();
}

#[test]
fn unrelated_global_wake_does_not_retrigger_epollet_ready_file() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset();
    let fdt = Arc::new(FdTable::new()); install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let ready = Arc::new(AtomicU32::new(vfs::POLL_IN));
    let fd = fdt.alloc(mk_poll_file(ready)).unwrap(); let mut add = epoll_event(vfs::POLL_IN | EPOLLET, 0x8100_0001);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, add.as_mut_ptr() as u64)), 0);
    let mut out = [0u8; 12]; assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0);
    fs::epoll::GLOBAL_EPOLL_GEN.fetch_add(1, Ordering::AcqRel);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0);
    fdt.get(fd).unwrap().poll_subscribers().unwrap().notify_mask(vfs::POLL_IN);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1); reset();
}

#[test]
fn inbound_source_event_does_not_retrigger_epollet_pollout() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset();
    let fdt = Arc::new(FdTable::new()); install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let ready = Arc::new(AtomicU32::new(vfs::POLL_OUT));
    let source = Arc::new(vfs::PollSubscribers::new()); let fd = fdt.alloc(mk_poll_file_with_source(ready, Arc::clone(&source))).unwrap();
    let mut add = epoll_event(vfs::POLL_OUT | EPOLLET, 0x8100_0003);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, add.as_mut_ptr() as u64)), 0);
    let mut out = [0u8; 12]; assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0); source.notify_mask(vfs::POLL_IN);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0); reset();
}
