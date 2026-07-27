use super::*;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicUsize as TestAtomicUsize, Ordering as TestOrdering};
use crate::PlacedSection;

static INIT_COUNT: TestAtomicUsize = TestAtomicUsize::new(0);
static EXIT_COUNT: TestAtomicUsize = TestAtomicUsize::new(0);

unsafe extern "C" fn ok_init() -> i32 {
    INIT_COUNT.fetch_add(1, TestOrdering::SeqCst);
    0
}

unsafe extern "C" fn bad_init() -> i32 {
    INIT_COUNT.fetch_add(1, TestOrdering::SeqCst);
    -1
}

unsafe extern "C" fn ok_exit() {
    EXIT_COUNT.fetch_add(1, TestOrdering::SeqCst);
}

fn reset() {
    REGISTRY.lock().clear();
    NEXT_ID.store(0, Ordering::Relaxed);
    crate::symtab::_reset();
    INIT_COUNT.store(0, TestOrdering::SeqCst);
    EXIT_COUNT.store(0, TestOrdering::SeqCst);
}

fn empty_module() -> LoadedModule {
    LoadedModule { sections: Vec::new(), symbols: BTreeMap::new(), info: ModuleInfo::default() }
}

fn ptr_section(name: &str, ptr: usize) -> PlacedSection {
    PlacedSection::from_bytes(String::from(name), ptr.to_ne_bytes().to_vec(), 0)
}

fn insert(name: &str, refcnt: usize) {
    REGISTRY.lock().push(Some(ModuleRecord {
        name: String::from(name),
        module: empty_module(),
        refcnt,
        taints: 0,
        state: ModuleState::Live,
        unload_pending: false,
    }));
}

// `REGISTRY` (`registry.rs:75`) and `NEXT_ID` are the process-global loaded-
// module table — a kernel-wide singleton these tests insert into, look up by
// id, and assert refcounts against. Parallel threads interleave one test's
// insert with another's id lookup. Not test-ownable without a per-test module
// registry in the kernel.
static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn snapshot_reports_name_state_and_counts() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let mut m = empty_module();
    m.sections.push(PlacedSection::from_bytes(String::from(".text"), alloc::vec![0u8; 12], 0));
    m.symbols.insert(String::from("init_module"), 1);
    REGISTRY.lock().push(Some(ModuleRecord {
        name: String::from("sample"),
        module: m,
        refcnt: 2,
        taints: 0x1000,
        state: ModuleState::Live,
        unload_pending: false,
    }));
    let s = snapshot();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].name, "sample");
    assert_eq!(s[0].license, None);
    assert_eq!(s[0].vermagic, None);
    assert_eq!(s[0].params.len(), 0);
    assert_eq!(s[0].size, 12);
    assert_eq!(s[0].refcnt, 2);
    assert_eq!(s[0].taints, 0x1000);
    assert_eq!(s[0].state.as_str(), "Live");
    assert_eq!(s[0].sections, 1);
    assert_eq!(s[0].symbols, 1);
}

#[test]
fn register_runs_initcall_and_marks_live() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let mut m = empty_module();
    m.sections.push(ptr_section(".initcall6.init", ok_init as *const () as usize));
    let idx = register_loaded_module(String::from("sample"), m).unwrap();
    assert_eq!(idx, 0);
    assert_eq!(INIT_COUNT.load(TestOrdering::SeqCst), 1);
    let s = snapshot();
    assert_eq!(s[0].state, ModuleState::Live);
}

#[test]
fn register_drops_module_when_init_fails() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let mut m = empty_module();
    m.sections.push(ptr_section(".initcall6.init", bad_init as *const () as usize));
    assert_eq!(register_loaded_module(String::from("sample"), m), Err(RegistryError::Init));
    assert_eq!(INIT_COUNT.load(TestOrdering::SeqCst), 1);
    assert_eq!(count(), 0);
}

#[test]
fn unload_runs_exitcall_before_removing_record() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let mut m = empty_module();
    m.sections.push(ptr_section(".exitcall.exit", ok_exit as *const () as usize));
    REGISTRY.lock().push(Some(ModuleRecord {
        name: String::from("sample"),
        module: m,
        refcnt: 0,
        taints: 0,
        state: ModuleState::Live,
        unload_pending: false,
    }));
    assert_eq!(unload_by_name("sample"), Ok(()));
    assert_eq!(EXIT_COUNT.load(TestOrdering::SeqCst), 1);
    assert_eq!(count(), 0);
}

#[test]
fn unload_by_name_removes_only_matching_live_record() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    insert("one", 0);
    insert("two", 0);
    assert_eq!(unload_by_name("one"), Ok(()));
    assert_eq!(count(), 1);
    assert_eq!(module_name(1), Some(String::from("two")));
    assert_eq!(unload_by_name("one"), Err(RegistryError::Noent));
}

#[test]
fn unload_busy_module_fails() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    insert("busy", 1);
    assert_eq!(unload_by_name("busy"), Err(RegistryError::Busy));
    assert_eq!(count(), 1);
    assert_eq!(snapshot()[0].state, ModuleState::Going);
    assert!(!try_get_by_name("busy"));
    assert_eq!(put_by_name("busy"), Ok(()));
    assert_eq!(count(), 0);
}

#[test]
fn module_refs_pin_until_last_put() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    insert("pinned", 0);
    assert!(try_get_by_name("pinned"));
    assert!(try_get_by_name("pinned"));
    assert_eq!(snapshot()[0].refcnt, 2);
    assert_eq!(unload_by_name("pinned"), Err(RegistryError::Busy));
    assert!(!try_get_by_name("pinned"));
    assert_eq!(put_by_name("pinned"), Ok(()));
    assert_eq!(count(), 1);
    assert_eq!(put_by_name("pinned"), Ok(()));
    assert_eq!(count(), 0);
}

#[test]
fn final_unload_removes_module_exports() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    insert("exporter", 0);
    crate::symtab::export_module("sample_export", 0x1234, false, "exporter");
    assert!(crate::symtab::is_exported("sample_export"));
    assert_eq!(unload_by_name("exporter"), Ok(()));
    assert!(!crate::symtab::is_exported("sample_export"));
}

#[test]
fn module_taints_track_out_of_tree_and_license() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let mut m = empty_module();
    m.info.license = Some(String::from("GPL"));
    let gpl = module_taints(&m);
    m.info.license = Some(String::from("Proprietary"));
    let proprietary = module_taints(&m);
    assert_ne!(gpl, 0);
    assert_ne!(proprietary & gpl, 0);
    assert_ne!(proprietary, gpl);
}

#[test]
fn forced_unload_marks_taint_while_waiting_for_refs() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    insert("forced", 1);
    assert_eq!(unload_by_name_flags("forced", true), Err(RegistryError::Busy));
    let s = snapshot();
    assert_eq!(s[0].state, ModuleState::Going);
    assert_ne!(s[0].taints & super::TAINT_FORCED_RMMOD, 0);
}

#[test]
fn invalid_names_are_rejected() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    assert_eq!(unload_by_name(""), Err(RegistryError::Inval));
    assert_eq!(unload_by_name("bad/name"), Err(RegistryError::Inval));
}
