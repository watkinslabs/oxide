use super::*;
use core::sync::atomic::AtomicBool;

// proc_dointvec_minmax: read formats the live var; write reflects in it.
#[test]
fn intvar_read_write_reflects_live() {
    static CELL: AtomicI64 = AtomicI64::new(60);
    let h = IntVar { cell: &CELL, bounds: Some((0, 200)) };
    assert_eq!(h.format(), b"60\n".to_vec());
    // a write updates the LIVE variable...
    h.store(b"99\n").unwrap();
    assert_eq!(CELL.load(Ordering::Relaxed), 99);
    assert_eq!(h.format(), b"99\n".to_vec());
    // ...and an external mutation of the live var shows up on read.
    CELL.store(7, Ordering::Relaxed);
    assert_eq!(h.format(), b"7\n".to_vec());
}

// proc_dointvec_minmax: out-of-range / non-integer write rejected, live var
// unchanged.
#[test]
fn intvar_bounds_rejected() {
    static CELL: AtomicI64 = AtomicI64::new(1);
    let h = IntVar { cell: &CELL, bounds: Some((0, 2)) };
    assert!(h.store(b"3\n").is_err());
    assert!(h.store(b"-1\n").is_err());
    assert!(h.store(b"abc\n").is_err());
    assert!(h.store(b"\n").is_err());
    assert_eq!(CELL.load(Ordering::Relaxed), 1, "rejected write must not mutate live var");
    assert!(h.store(b"2\n").is_ok());
    assert_eq!(CELL.load(Ordering::Relaxed), 2);
}

#[test]
fn intvar_negative_window() {
    static CELL: AtomicI64 = AtomicI64::new(2);
    let h = IntVar { cell: &CELL, bounds: Some((-1, 4)) }; // perf_event_paranoid
    assert!(h.store(b"-1\n").is_ok());
    assert_eq!(CELL.load(Ordering::Relaxed), -1);
    assert!(h.store(b"-2\n").is_err());
}

#[test]
fn intvar_unbounded_accepts_any_int() {
    static CELL: AtomicI64 = AtomicI64::new(0);
    let h = IntVar { cell: &CELL, bounds: None };
    assert!(h.store(b"123456\n").is_ok());
    assert_eq!(CELL.load(Ordering::Relaxed), 123456);
    assert!(h.store(b"notanint").is_err());
}

#[test]
fn inthook_updates_subsystem_owned_value() {
    static CELL: AtomicI64 = AtomicI64::new(4096);
    fn get() -> i64 { CELL.load(Ordering::Relaxed) }
    fn set(v: i64) { CELL.store(v, Ordering::Relaxed); }
    let h = IntHook { get, set, bounds: Some((0, i32::MAX as i64)) };
    assert_eq!(h.format(), b"4096\n".to_vec());
    h.store(b"1024\n").unwrap();
    assert_eq!(CELL.load(Ordering::Relaxed), 1024);
    assert!(h.store(b"-1").is_err());
    assert_eq!(CELL.load(Ordering::Relaxed), 1024);
}

#[test]
fn u16_pair_hook_accepts_partial_vector_and_rejects_excess() {
    static PAIR: AtomicU64 = AtomicU64::new((32_768u64 << 16) | 60_999);
    fn get() -> (u16, u16) {
        let raw = PAIR.load(Ordering::Relaxed);
        ((raw >> 16) as u16, raw as u16)
    }
    fn set(first: u16, second: u16) -> Result<(), ()> {
        if first == 0 || first > second { return Err(()); }
        PAIR.store((first as u64) << 16 | second as u64, Ordering::Relaxed);
        Ok(())
    }
    let h = U16PairHook { get, set };
    assert_eq!(h.format(), b"32768\t60999\n".to_vec());
    h.store(b"40000 40009\n").unwrap();
    assert_eq!(get(), (40_000, 40_009));
    h.store(b"40001").unwrap();
    assert_eq!(get(), (40_001, 40_009));
    assert!(h.store(b"40010 40000").is_err());
    assert!(h.store(b"1 2 3").is_err());
    assert_eq!(get(), (40_001, 40_009));
}

#[test]
fn per_net_handlers_capture_namespace_and_keep_vector_validation_coherent() {
    const fn pack(start: u16, end: u16, floor: u16) -> u64 {
        (start as u64) << 32 | (end as u64) << 16 | floor as u64
    }
    static CURRENT: std::sync::Mutex<Option<NetworkNamespaceRef>> =
        std::sync::Mutex::new(None);
    static STATE: [AtomicU64; 2] = [
        AtomicU64::new(pack(32_768, 60_999, 1_024)),
        AtomicU64::new(pack(40_000, 40_009, 2_048)),
    ];
    fn current() -> NetworkNamespaceRef {
        Arc::clone(CURRENT.lock().unwrap().as_ref().unwrap())
    }
    fn slot(namespace: &NetworkNamespaceRef) -> usize {
        usize::from(!namespace.is_initial())
    }
    fn pair(namespace: &NetworkNamespaceRef) -> Result<(u16, u16), ()> {
        let raw = STATE[slot(namespace)].load(Ordering::Relaxed);
        Ok(((raw >> 32) as u16, (raw >> 16) as u16))
    }
    fn set_pair(namespace: &NetworkNamespaceRef, start: u16, end: u16) -> Result<(), ()> {
        let index = slot(namespace);
        let old = STATE[index].load(Ordering::Relaxed);
        let floor = old as u16;
        if start == 0 || start > end || start < floor { return Err(()); }
        STATE[index].store(pack(start, end, floor), Ordering::Relaxed);
        Ok(())
    }
    fn floor(namespace: &NetworkNamespaceRef, _key: usize) -> Result<i64, ()> {
        Ok(STATE[slot(namespace)].load(Ordering::Relaxed) as u16 as i64)
    }
    fn set_floor(namespace: &NetworkNamespaceRef, _key: usize, floor: i64) -> Result<(), ()> {
        let index = slot(namespace);
        let old = STATE[index].load(Ordering::Relaxed);
        let start = (old >> 32) as u16;
        if floor < 0 || floor > start as i64 { return Err(()); }
        STATE[index].store((old & !(u16::MAX as u64)) | floor as u64, Ordering::Relaxed);
        Ok(())
    }

    *CURRENT.lock().unwrap() = Some(network_namespace::initial());
    let pair_open = PerNetU16PairHook { current_ns: current, get: pair, set: set_pair }
        .bind().unwrap();
    let floor_open = PerNetIntHook {
        current_ns: current, key: 0, get: floor, set: set_floor,
        bounds: Some((0, u16::MAX as i64)),
    }.bind().unwrap();
    let _ = net::net_ns::install_final_drop_pending_notifier();
    *CURRENT.lock().unwrap() = Some(network_namespace::allocate(
        namespace_identity::initial(namespace_identity::NamespaceKind::User)).unwrap());

    assert_eq!(pair_open.format(), b"32768\t60999\n".to_vec());
    assert_eq!(floor_open.format(), b"1024\n".to_vec());
    pair_open.store(b"35000").unwrap();
    assert_eq!(pair(&network_namespace::initial()).unwrap(), (35_000, 60_999));
    pair_open.store(b"36000 36009\n").unwrap();
    assert_eq!(pair(&network_namespace::initial()).unwrap(), (36_000, 36_009));
    assert_eq!(pair(CURRENT.lock().unwrap().as_ref().unwrap()).unwrap(), (40_000, 40_009));
    floor_open.store(b"35000").unwrap();
    assert_eq!(floor(&network_namespace::initial(), 0).unwrap(), 35_000);
    assert_eq!(floor(CURRENT.lock().unwrap().as_ref().unwrap(), 0).unwrap(), 2_048);
    assert!(pair_open.store(b"34999 36009").is_err());
    assert!(floor_open.store(b"36001").is_err());
    assert_eq!(pair(&network_namespace::initial()).unwrap(), (36_000, 36_009));
    assert_eq!(floor(&network_namespace::initial(), 0).unwrap(), 35_000);
}

#[test]
fn per_pid_handler_follows_current_namespace_and_preserves_policy_errno() {
    static CURRENT: std::sync::Mutex<Option<NamespaceRef>> = std::sync::Mutex::new(None);
    static STATE: [AtomicI64; 2] = [AtomicI64::new(0), AtomicI64::new(1)];
    static ALLOW: AtomicBool = AtomicBool::new(true);
    fn current() -> NamespaceRef { CURRENT.lock().unwrap().as_ref().unwrap().clone() }
    fn slot(namespace: &NamespaceRef) -> usize { usize::from(!namespace.is_initial()) }
    fn check_write(_namespace: &NamespaceRef) -> KResult<()> {
        if ALLOW.load(Ordering::Relaxed) { Ok(()) } else { Err(VfsError::Eperm) }
    }
    fn get(namespace: &NamespaceRef) -> Result<i64, ()> {
        Ok(STATE[slot(namespace)].load(Ordering::Relaxed))
    }
    fn set(namespace: &NamespaceRef, value: i64) -> KResult<()> {
        if value == 2 { return Err(VfsError::Eperm); }
        STATE[slot(namespace)].store(value, Ordering::Relaxed);
        Ok(())
    }

    *CURRENT.lock().unwrap() = Some(namespace_identity::initial(
        namespace_identity::NamespaceKind::Pid));
    let handler = PerPidIntHook {
        current_ns: current, check_write, get, set, bounds: Some((0, 2)),
    };
    assert_eq!(handler.format(), b"0\n".to_vec());
    *CURRENT.lock().unwrap() = Some(namespace_identity::allocate(
        namespace_identity::NamespaceKind::Pid,
        namespace_identity::initial(namespace_identity::NamespaceKind::User), None).unwrap());

    assert_eq!(handler.format(), b"1\n".to_vec());
    handler.store_vfs(b"0\n").unwrap();
    assert_eq!(STATE[0].load(Ordering::Relaxed), 0);
    assert_eq!(STATE[1].load(Ordering::Relaxed), 0);
    handler.store_vfs(b"1\n").unwrap();
    assert_eq!(STATE[1].load(Ordering::Relaxed), 1);
    ALLOW.store(false, Ordering::Relaxed);
    assert_eq!(handler.store_vfs(b"not-an-int"), Err(VfsError::Eperm),
        "the namespace capability gate precedes value parsing");
    ALLOW.store(true, Ordering::Relaxed);
    assert_eq!(handler.store_vfs(b"2\n"), Err(VfsError::Eperm));
    assert_eq!(handler.store_vfs(b"3\n"), Err(VfsError::Einval));
    assert_eq!(handler.store_vfs(b"not-an-int"), Err(VfsError::Einval));
}

#[test]
fn ulongvar_bounds() {
    static CELL: AtomicU64 = AtomicU64::new(4096);
    let h = ULongVar { cell: &CELL, bounds: Some((0, 1 << 30)) };
    assert_eq!(h.format(), b"4096\n".to_vec());
    h.store(b"8192\n").unwrap();
    assert_eq!(CELL.load(Ordering::Relaxed), 8192);
    assert!(h.store(b"99999999999\n").is_err()); // > 2^30
    assert!(h.store(b"-1\n").is_err());          // not unsigned
}

#[test]
fn strhook_adds_newline() {
    static SLOT: AtomicI64 = AtomicI64::new(0); // marker; real slot below
    let _ = &SLOT;
    fn get() -> Vec<u8> { b"oxide".to_vec() }
    fn set(_s: &[u8]) {}
    let h = StrHook { get, set };
    assert_eq!(h.format(), b"oxide\n".to_vec());
}
