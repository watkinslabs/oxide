//! Scope selection, handle uniqueness and the thread-before-global walk.
use super::*;

fn request<'a>(id: i32, thread: Option<u64>, proc_address: u64) -> HookRequest<'a> {
    HookRequest { id, process: None, thread, owner: 1, event_min: EVENT_MIN, event_max: EVENT_MAX,
        flags: 0, proc_address, unicode: true, module: &[] }
}

fn here() -> HookThread { HookThread { thread: 1, process: 1 } }

#[test]
fn handles_are_unique_across_the_global_and_thread_scopes() {
    let mut registry = HookRegistry::new();
    let global = registry.install(HookScope::Global, &request(WH_CBT, None, 0x10)).unwrap();
    let local = registry.install(HookScope::Thread(1), &request(WH_CBT, Some(1), 0x20)).unwrap();
    assert_ne!(global, local);
    assert_eq!(registry.get(global).map(|hook| hook.proc_address), Some(0x10));
    assert_eq!(registry.get(local).map(|hook| hook.proc_address), Some(0x20));
}

#[test]
fn the_calling_threads_own_hooks_run_before_the_global_ones() {
    let mut registry = HookRegistry::new();
    let global = registry.install(HookScope::Global, &request(WH_CBT, None, 0x10)).unwrap();
    let local = registry.install(HookScope::Thread(1), &request(WH_CBT, Some(1), 0x20)).unwrap();
    assert_eq!(registry.next_hook(WH_CBT, None, here(), EVENT_MIN),
        Some(HookLocation { handle: local, global: false }));
    assert_eq!(registry.next_hook(WH_CBT, Some(local), here(), EVENT_MIN),
        Some(HookLocation { handle: global, global: true }));
    assert_eq!(registry.next_hook(WH_CBT, Some(global), here(), EVENT_MIN), None);
}

#[test]
fn a_thread_with_no_table_of_its_own_walks_straight_into_the_global_chain() {
    let mut registry = HookRegistry::new();
    let global = registry.install(HookScope::Global, &request(WH_CBT, None, 0x10)).unwrap();
    registry.install(HookScope::Thread(9), &request(WH_CBT, Some(9), 0x20)).unwrap();
    assert_eq!(registry.next_hook(WH_CBT, None, here(), EVENT_MIN),
        Some(HookLocation { handle: global, global: true }));
}

#[test]
fn the_chain_count_covers_both_scopes_and_honours_the_thread_filter() {
    let mut registry = HookRegistry::new();
    registry.install(HookScope::Global, &request(WH_CBT, None, 0x10)).unwrap();
    registry.install(HookScope::Thread(1), &request(WH_CBT, Some(1), 0x20)).unwrap();
    registry.install(HookScope::Thread(9), &request(WH_CBT, Some(9), 0x30)).unwrap();
    assert_eq!(registry.chain_count(WH_CBT, here()), 2);
    assert_eq!(registry.chain_count(WH_GETMESSAGE, here()), 0);
}

#[test]
fn removal_reaches_either_scope_and_reports_an_unknown_handle() {
    let mut registry = HookRegistry::new();
    let global = registry.install(HookScope::Global, &request(WH_CBT, None, 0x10)).unwrap();
    let local = registry.install(HookScope::Thread(1), &request(WH_CBT, Some(1), 0x20)).unwrap();
    assert!(registry.remove(global).is_ok());
    assert!(registry.remove(local).is_ok());
    assert_eq!(registry.remove(local).err(), Some(HookError::InvalidHandle));
}

#[test]
fn removal_by_procedure_only_reaches_the_calling_threads_own_table() {
    let mut registry = HookRegistry::new();
    registry.install(HookScope::Thread(9), &request(WH_CBT, Some(9), 0x20)).unwrap();
    assert_eq!(registry.remove_by_proc(1, WH_CBT, 0x20).err(), Some(HookError::InvalidParameter));
    assert!(registry.remove_by_proc(9, WH_CBT, 0x20).is_ok());
}

#[test]
fn an_exiting_thread_takes_its_own_table_and_the_global_hooks_it_installed() {
    let mut registry = HookRegistry::new();
    let mut owned = request(WH_CBT, None, 0x10);
    owned.owner = 9;
    let global = registry.install(HookScope::Global, &owned).unwrap();
    let local = registry.install(HookScope::Thread(9), &request(WH_CBT, Some(9), 0x20)).unwrap();
    let survivor = registry.install(HookScope::Global, &request(WH_CBT, None, 0x30)).unwrap();
    registry.cleanup_thread(9);
    assert!(registry.get(global).is_none());
    assert!(registry.get(local).is_none());
    assert!(registry.get(survivor).is_some());
}
