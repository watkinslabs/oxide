use super::*;

#[test]
fn admission_limit_rejects_then_recovers_without_count_leak() {
    let active = Arc::new(AtomicUsize::new(0));
    let first = Permit::acquire(&active, 2).unwrap();
    let second = Permit::acquire(&active, 2).unwrap();
    assert!(Permit::acquire(&active, 2).is_none());
    assert_eq!(active.load(Ordering::Acquire), 2);
    drop(first);
    let replacement = Permit::acquire(&active, 2).unwrap();
    assert!(Permit::acquire(&active, 2).is_none());
    drop(second); drop(replacement);
    assert_eq!(active.load(Ordering::Acquire), 0);
}

#[test]
fn unstarted_worker_drop_releases_permit_and_socket() {
    let active = Arc::new(AtomicUsize::new(0));
    let permit = Permit::acquire(&active, 1).unwrap();
    let (stream, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(std::time::Duration::from_secs(1))).unwrap();
    let worker = move || { let _permit = permit; let _stream = stream; };
    // A failed thread spawn drops this same captured closure without executing it.
    drop(worker);
    assert_eq!(active.load(Ordering::Acquire), 0);
    assert_eq!(std::io::Read::read(&mut peer, &mut [0]).unwrap(), 0);
    assert!(Permit::acquire(&active, 1).is_some());
}

#[test]
fn worker_unwind_releases_admission() {
    let active = Arc::new(AtomicUsize::new(0));
    let permit = Permit::acquire(&active, 1).unwrap();
    assert!(std::panic::catch_unwind(move || { let _permit = permit; panic!("worker failure control"); }).is_err());
    assert_eq!(active.load(Ordering::Acquire), 0);
}

#[test]
fn concurrent_admission_never_exceeds_limit() {
    const CONTENDERS: usize = 16;
    const LIMIT: usize = 3;
    let active = Arc::new(AtomicUsize::new(0));
    let start = Arc::new(std::sync::Barrier::new(CONTENDERS));
    let acquired = Arc::new(std::sync::Barrier::new(CONTENDERS));
    let observed = Arc::new(std::sync::Barrier::new(CONTENDERS));
    thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 0..CONTENDERS {
            let (active, start, acquired, observed) = (active.clone(), start.clone(), acquired.clone(), observed.clone());
            workers.push(scope.spawn(move || {
                start.wait();
                let permit = Permit::acquire(&active, LIMIT);
                acquired.wait();
                let count = active.load(Ordering::Acquire);
                observed.wait();
                let admitted = permit.is_some(); drop(permit); (admitted, count)
            }));
        }
        let results: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|(admitted, _)| *admitted).count(), LIMIT);
        assert!(results.iter().all(|(_, count)| *count == LIMIT));
    });
    assert_eq!(active.load(Ordering::Acquire), 0);
}

#[test]
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn failed_os_spawn_releases_permit_and_socket() {
    // Exceeds the userspace virtual address range, without exhausting real threads or RAM.
    const IMPOSSIBLE_STACK: usize = 1usize << 62;
    let active = Arc::new(AtomicUsize::new(0));
    let permit = Permit::acquire(&active, 1).unwrap();
    let (stream, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(std::time::Duration::from_secs(1))).unwrap();
    let result = thread::Builder::new().stack_size(IMPOSSIBLE_STACK).spawn(move || {
        let _permit = permit; let _stream = stream;
    });
    if let Ok(worker) = result { worker.join().unwrap(); panic!("impossible stack unexpectedly admitted"); }
    assert_eq!(active.load(Ordering::Acquire), 0);
    assert_eq!(std::io::Read::read(&mut peer, &mut [0]).unwrap(), 0);
    assert!(Permit::acquire(&active, 1).is_some());
}
