use super::*;

#[test]
fn signalfd_registers_current_tasks_pending_source() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset();
    let fdt = Arc::new(FdTable::new()); let creator = install_current_with_fdt(Arc::clone(&fdt));
    let sig = sched::signum::Signum::Sigusr1; let sig_inode = fs::signalfd::make_signalfd_inode(sig.bit());
    let sigfd = fdt.alloc(File::new(sig_inode.clone(), Dentry::new_root(sig_inode), OpenFlags::O_NONBLOCK)).unwrap();
    let consumer = install_current_with_fdt(Arc::clone(&fdt)); let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let mut add = epoll_event(vfs::POLL_IN | EPOLLET, 0x8100_0002);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, sigfd as u64, add.as_mut_ptr() as u64)), 0);
    let mut out = [0u8; 12]; assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0);
    creator.sigpending.fetch_or(sig.bit(), Ordering::Release);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0);
    consumer.sigpending.fetch_or(sig.bit(), Ordering::Release);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1);
    assert_eq!(read_epoll_event(&out), (vfs::POLL_IN, 0x8100_0002)); reset();
}

#[test]
fn shared_source_keeps_one_subscription_per_epitem() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset();
    let fdt = Arc::new(FdTable::new()); install_current_with_fdt(Arc::clone(&fdt)); let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0));
    let ready = Arc::new(AtomicU32::new(0)); let source = Arc::new(vfs::PollSubscribers::new());
    let fd1 = fdt.alloc(mk_poll_file_with_source(Arc::clone(&ready), Arc::clone(&source))).unwrap(); let fd2 = fdt.alloc(mk_poll_file_with_source(Arc::clone(&ready), Arc::clone(&source))).unwrap();
    let mut add1 = epoll_event(vfs::POLL_IN | EPOLLET, 0x8100_0011); let mut add2 = epoll_event(vfs::POLL_IN | EPOLLET, 0x8100_0012);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd1 as u64, add1.as_mut_ptr() as u64)), 0); assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd2 as u64, add2.as_mut_ptr() as u64)), 0);
    ready.store(vfs::POLL_IN, Ordering::Release); source.notify_mask(vfs::POLL_IN); let mut out = [0u8; 24];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 2, 0)), 2);
    ready.store(0, Ordering::Release); assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, 2, fd1 as u64, 0)), 0);
    ready.store(vfs::POLL_IN, Ordering::Release); source.notify_mask(vfs::POLL_IN);
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 2, 0)), 1); reset();
}

#[test]
fn epoll_oneshot_disarms_until_mod() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset(); let fdt = Arc::new(FdTable::new()); install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let fd = fdt.alloc(mk_poll_file(Arc::new(AtomicU32::new(vfs::POLL_IN)))).unwrap(); let mut event = epoll_event(vfs::POLL_IN | EPOLLONESHOT, 0x8100_0020);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, event.as_mut_ptr() as u64)), 0); let mut out = [0u8; 12];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1); assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_MOD, fd as u64, event.as_mut_ptr() as u64)), 0); assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1); reset();
}

#[test]
fn epoll_rejects_nested_cycle() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset(); let fdt = Arc::new(FdTable::new()); install_current_with_fdt(fdt);
    let a = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let b = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let mut event = epoll_event(vfs::POLL_IN, 0x8100_0030);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(a as u64, EPOLL_CTL_ADD, b as u64, event.as_mut_ptr() as u64)), 0); assert_eq!(fs::epoll::sys_epoll_ctl(&args(b as u64, EPOLL_CTL_ADD, a as u64, event.as_mut_ptr() as u64)), -(Errno::Eloop.as_i32() as i64)); reset();
}

#[test]
fn final_file_reference_drop_unlinks_epoll_interest() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset(); let fdt = Arc::new(FdTable::new()); install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let ready = Arc::new(AtomicU32::new(0)); let source = Arc::new(vfs::PollSubscribers::new()); let fd = fdt.alloc(mk_poll_file_with_source(Arc::clone(&ready), Arc::clone(&source))).unwrap(); let mut event = epoll_event(vfs::POLL_IN, 0x8100_0040);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, event.as_mut_ptr() as u64)), 0); assert_eq!(fdt.close(fd), Ok(())); ready.store(vfs::POLL_IN, Ordering::Release); source.notify_mask(vfs::POLL_IN); let mut out = [0u8; 12];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0); reset();
}

#[test]
fn non_fd_file_reference_delays_epoll_unlink() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()); reset(); let fdt = Arc::new(FdTable::new()); install_current_with_fdt(Arc::clone(&fdt));
    let epfd = fs::epoll::sys_epoll_create1(&args(0, 0, 0, 0)); let ready = Arc::new(AtomicU32::new(0)); let source = Arc::new(vfs::PollSubscribers::new()); let file = mk_poll_file_with_source(Arc::clone(&ready), Arc::clone(&source)); let held = Arc::clone(&file); let fd = fdt.alloc(file).unwrap(); let mut event = epoll_event(vfs::POLL_IN, 0x8100_0050);
    assert_eq!(fs::epoll::sys_epoll_ctl(&args(epfd as u64, EPOLL_CTL_ADD, fd as u64, event.as_mut_ptr() as u64)), 0); assert_eq!(fdt.close(fd), Ok(())); ready.store(vfs::POLL_IN, Ordering::Release); source.notify_mask(vfs::POLL_IN); let mut out = [0u8; 12];
    assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 1); drop(held); source.notify_mask(vfs::POLL_IN); assert_eq!(fs::epoll::sys_epoll_wait(&args(epfd as u64, out.as_mut_ptr() as u64, 1, 0)), 0); reset();
}
