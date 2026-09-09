use super::*;

fn check_wait_site(vector: bool) {
    let word = Arc::new(AtomicU32::new(2));
    let addr = Arc::as_ptr(&word) as u64;
    let mm = 0x9010_0000 + u64::from(vector);
    let waiter = Arc::new(Task::new(9010 + u32::from(vector), mm));
    let watch = waiter.clone();
    let (tx, rx) = mpsc::channel();
    let child = std::thread::spawn(move || {
        live::set_current(waiter);
        park_site::note(core::panic::Location::caller());
        let result = if vector {
            futex::waitv::dispatch_waitv_timed(&[futex::waitv::WaitvEntry {
                uaddr: addr, val: 2, private: true,
            }], 0)
        } else {
            futex::wait::dispatch(addr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 2)
        };
        tx.send((result, park_site::get().unwrap().file())).unwrap();
    });
    wait_until_parked(&watch);
    live::set_current(Arc::new(Task::new(9020 + u32::from(vector), mm)));
    assert_eq!(futex::wait::dispatch(addr, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1), 1);
    let (result, site) = rx.recv_timeout(Duration::from_secs(5)).expect("wait completed");
    child.join().unwrap();
    assert_eq!(result, 0);
    let expected = if vector { "src/live/futex/waitv.rs" } else { "src/live/futex/wait.rs" };
    assert!(site.ends_with(expected), "wait retained old blocking site: {site}");
}

#[test]
fn ordinary_wait_replaces_previous_blocking_site() { check_wait_site(false); }
#[test]
fn vector_wait_replaces_previous_blocking_site() { check_wait_site(true); }

#[test]
fn refused_wait_preserves_previous_site() {
    let word = AtomicU32::new(3);
    let addr = &word as *const AtomicU32 as u64;
    live::set_current(Arc::new(Task::new(9030, 0x9030_0000)));
    let before = core::panic::Location::caller();
    park_site::note(before);
    assert_eq!(futex::wait::dispatch(addr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 2),
               -(syscall::errno::Errno::Eagain.as_i32() as i64));
    assert_eq!(park_site::get(), Some(before));
    assert_eq!(futex::waitv::dispatch_waitv_timed(&[futex::waitv::WaitvEntry {
        uaddr: addr, val: 2, private: true,
    }], 0), -(syscall::errno::Errno::Eagain.as_i32() as i64));
    assert_eq!(park_site::get(), Some(before));
}
