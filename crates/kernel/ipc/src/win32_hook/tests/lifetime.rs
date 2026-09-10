//! Removal while walking, nested lifetime and scope transitions.
use super::*;
fn caller() -> HookThread { HookThread { thread: 1, process: 1 } }
fn add(registry: &mut HookRegistry, scope: HookScope, proc_address: u64) -> u32 {
    registry.install(scope, &HookRequest { id: WH_WINEVENT, process: None,
        thread: match scope { HookScope::Thread(tid) => Some(tid), _ => None }, owner: 1,
        event_min: EVENT_MIN, event_max: EVENT_MAX, flags: WINEVENT_INCONTEXT,
        proc_address, unicode: true, module: &[] }).unwrap()
}
#[test]
fn removed_current_hook_keeps_its_successor_until_walk_finishes() {
    let mut registry = HookRegistry::new();
    let next = add(&mut registry, HookScope::Global, 10);
    let first = add(&mut registry, HookScope::Global, 20);
    let lease = registry.hold_chain(WH_WINEVENT, caller()).unwrap();
    assert_eq!(registry.remove(first).unwrap().proc_address, 20);
    assert_eq!(registry.get(first).unwrap().proc_address, 0);
    assert_eq!(registry.chain_count(WH_WINEVENT, caller()), 1);
    assert_eq!(registry.next_hook(WH_WINEVENT, Some(first), caller(), EVENT_MIN).unwrap().handle, next);
    registry.release_chain(lease);
    assert!(registry.get(first).is_none());
}
#[test]
fn removed_local_cursor_still_transitions_into_current_global_head() {
    let mut registry = HookRegistry::new();
    add(&mut registry, HookScope::Global, 10);
    let first = add(&mut registry, HookScope::Thread(1), 20);
    let lease = registry.hold_chain(WH_WINEVENT, caller()).unwrap();
    registry.remove(first).unwrap();
    let new_global = add(&mut registry, HookScope::Global, 30);
    assert_eq!(registry.next_hook(WH_WINEVENT, Some(first), caller(), EVENT_MIN).unwrap().handle, new_global);
    registry.release_chain(lease);
}
#[test]
fn deleted_successor_is_skipped_and_new_predecessor_is_not_replayed() {
    let mut registry = HookRegistry::new();
    let last = add(&mut registry, HookScope::Global, 10);
    let deleted = add(&mut registry, HookScope::Global, 20);
    let first = add(&mut registry, HookScope::Global, 30);
    let lease = registry.hold_chain(WH_WINEVENT, caller()).unwrap();
    registry.remove(deleted).unwrap();
    add(&mut registry, HookScope::Global, 40);
    assert_eq!(registry.next_hook(WH_WINEVENT, Some(first), caller(), EVENT_MIN).unwrap().handle, last);
    registry.release_chain(lease);
}
#[test]
fn nested_walks_reclaim_only_after_last_release() {
    let mut registry = HookRegistry::new();
    let hook = add(&mut registry, HookScope::Global, 10);
    let outer = registry.hold_chain(WH_WINEVENT, caller()).unwrap();
    let inner = registry.hold_chain(WH_WINEVENT, caller()).unwrap();
    registry.remove(hook).unwrap();
    registry.release_chain(inner);
    assert_eq!(registry.get(hook).unwrap().proc_address, 0);
    registry.release_chain(outer);
    assert!(registry.get(hook).is_none());
}
#[test]
fn cleanup_during_foreign_walk_preserves_cursor_without_counting_deleted_hooks() {
    let mut registry = HookRegistry::new();
    let hook = add(&mut registry, HookScope::Global, 10);
    let lease = registry.hold_chain(WH_WINEVENT, HookThread { thread: 2, process: 2 }).unwrap();
    registry.cleanup_thread(1);
    assert_eq!(registry.chain_count(WH_WINEVENT, caller()), 0);
    assert_eq!(registry.get(hook).unwrap().proc_address, 0);
    registry.release_chain(lease);
    assert!(registry.get(hook).is_none());
}
