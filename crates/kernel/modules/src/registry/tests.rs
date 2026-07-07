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
        state: ModuleState::Live,
    }));
}

#[test]
fn snapshot_reports_name_state_and_counts() {
    reset();
    let mut m = empty_module();
    m.sections.push(PlacedSection::from_bytes(String::from(".text"), alloc::vec![0u8; 12], 0));
    m.symbols.insert(String::from("init_module"), 1);
    REGISTRY.lock().push(Some(ModuleRecord {
        name: String::from("sample"),
        module: m,
        refcnt: 2,
        state: ModuleState::Live,
    }));
    let s = snapshot();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].name, "sample");
    assert_eq!(s[0].license, None);
    assert_eq!(s[0].vermagic, None);
    assert_eq!(s[0].params.len(), 0);
    assert_eq!(s[0].size, 12);
    assert_eq!(s[0].refcnt, 2);
    assert_eq!(s[0].state.as_str(), "Live");
    assert_eq!(s[0].sections, 1);
    assert_eq!(s[0].symbols, 1);
}

#[test]
fn register_runs_initcall_and_marks_live() {
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
    reset();
    let mut m = empty_module();
    m.sections.push(ptr_section(".initcall6.init", bad_init as *const () as usize));
    assert_eq!(register_loaded_module(String::from("sample"), m), Err(RegistryError::Init));
    assert_eq!(INIT_COUNT.load(TestOrdering::SeqCst), 1);
    assert_eq!(count(), 0);
}

#[test]
fn unload_runs_exitcall_before_removing_record() {
    reset();
    let mut m = empty_module();
    m.sections.push(ptr_section(".exitcall.exit", ok_exit as *const () as usize));
    REGISTRY.lock().push(Some(ModuleRecord {
        name: String::from("sample"),
        module: m,
        refcnt: 0,
        state: ModuleState::Live,
    }));
    assert_eq!(unload_by_name("sample"), Ok(()));
    assert_eq!(EXIT_COUNT.load(TestOrdering::SeqCst), 1);
    assert_eq!(count(), 0);
}

#[test]
fn unload_by_name_removes_only_matching_live_record() {
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
    reset();
    insert("busy", 1);
    assert_eq!(unload_by_name("busy"), Err(RegistryError::Busy));
    assert_eq!(count(), 1);
}

#[test]
fn invalid_names_are_rejected() {
    reset();
    assert_eq!(unload_by_name(""), Err(RegistryError::Inval));
    assert_eq!(unload_by_name("bad/name"), Err(RegistryError::Inval));
}
