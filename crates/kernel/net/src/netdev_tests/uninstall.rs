use super::*;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct LifecycleDev {
    resume_started: Arc<AtomicBool>,
    resume_release: Arc<AtomicBool>,
    resumes:        Arc<AtomicUsize>,
    retires:        Arc<AtomicUsize>,
}

impl NetDev for LifecycleDev {
    fn name(&self) -> &str { "lifecycle0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn retire_namespace(&self) { self.retires.fetch_add(1, Ordering::AcqRel); }
    fn resume_namespace(&self) {
        self.resumes.fetch_add(1, Ordering::AcqRel);
        self.resume_started.store(true, Ordering::Release);
        while !self.resume_release.load(Ordering::Acquire) { std::thread::yield_now(); }
    }
    fn namespace_drop_action(&self) -> NamespaceDropAction { NamespaceDropAction::MoveToInitial }
    fn xmit(&self, _pkt: Pkt) -> NetResult<()> { Ok(()) }
}

#[test]
fn current_unregister_waits_through_namespace_move_then_destroys() {
    let stack = Arc::new(crate::NetStack::new());
    let owner = owner();
    let net_ns = owner.id().as_u64();
    let resume_started = Arc::new(AtomicBool::new(false));
    let resume_release = Arc::new(AtomicBool::new(false));
    let resumes = Arc::new(AtomicUsize::new(0));
    let retires = Arc::new(AtomicUsize::new(0));
    let iface = stack.ifaces.register_in_ns(Arc::new(LifecycleDev {
        resume_started: resume_started.clone(), resume_release: resume_release.clone(),
        resumes: resumes.clone(), retires: retires.clone(),
    }), net_ns);
    let lease = stack.ifaces.acquire_ingress(iface).unwrap();
    let generation = lease.generation();
    let teardown_stack = stack.clone();
    let teardown = std::thread::spawn(move || {
        teardown_stack.teardown_iface_in(net_ns, iface)
    });
    while stack.ifaces.namespace(iface).is_some() { std::thread::yield_now(); }
    let unregister_stack = stack.clone();
    let (unregister_tx, unregister_rx) = std::sync::mpsc::channel();
    let unregister = std::thread::spawn(move || {
        unregister_tx.send(unregister_stack.unregister_iface_current(iface)).unwrap();
    });
    while stack.ifaces.unregister_waiters(iface, generation) == 0 {
        std::thread::yield_now();
    }

    drop(lease);
    while !resume_started.load(Ordering::Acquire) { std::thread::yield_now(); }
    let pending = stack.ifaces.acquire_ingress(iface).unwrap();
    assert_eq!(pending.net_ns(), 0);
    assert_eq!(pending.generation(), generation + 1);
    drop(pending);
    assert!(matches!(unregister_rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));
    resume_release.store(true, Ordering::Release);

    assert!(teardown.join().unwrap());
    assert!(unregister_rx.recv().unwrap());
    unregister.join().unwrap();
    assert!(!stack.ifaces.registered(iface));
    assert_eq!(resumes.load(Ordering::Acquire), 1);
    assert_eq!(retires.load(Ordering::Acquire), 2);
}

#[test]
fn current_unregister_cannot_claim_resume_pending_generation() {
    let stack = Arc::new(crate::NetStack::new());
    let owner = owner();
    let net_ns = owner.id().as_u64();
    let resume_started = Arc::new(AtomicBool::new(false));
    let resume_release = Arc::new(AtomicBool::new(false));
    let resumes = Arc::new(AtomicUsize::new(0));
    let retires = Arc::new(AtomicUsize::new(0));
    let iface = stack.ifaces.register_in_ns(Arc::new(LifecycleDev {
        resume_started: resume_started.clone(), resume_release: resume_release.clone(),
        resumes, retires,
    }), net_ns);
    let teardown_stack = stack.clone();
    let teardown = std::thread::spawn(move || teardown_stack.teardown_iface_in(net_ns, iface));
    while !resume_started.load(Ordering::Acquire) { std::thread::yield_now(); }

    let unregister_stack = stack.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let unregister = std::thread::spawn(move || {
        done_tx.send(unregister_stack.unregister_iface_current(iface)).unwrap();
    });
    while stack.ifaces.resume_waiters(iface) == 0 { std::thread::yield_now(); }
    assert!(matches!(done_rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));

    resume_release.store(true, Ordering::Release);
    assert!(teardown.join().unwrap());
    assert!(done_rx.recv().unwrap());
    unregister.join().unwrap();
    assert!(!stack.ifaces.registered(iface));
}
