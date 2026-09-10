//! Drive real notification admission through actual completion routing and reentrant edits.
use super::{callbacks, environment::*, families::hook_api::*};
use ipc::win32_hook::{HookRequest, HookScope, HookThread, WH_WINEVENT, WINEVENT_INCONTEXT};
use std::sync::atomic::Ordering;
fn caller() -> HookThread { HookThread { thread: 1, process: 1 } }
fn add(scope: HookScope, low: u32, high: u32, proc_address: u64) -> u32 {
    hook_install(scope, &HookRequest { id: WH_WINEVENT, process: None,
        thread: match scope { HookScope::Thread(tid) => Some(tid), _ => None }, owner: 1,
        event_min: low, event_max: high, flags: WINEVENT_INCONTEXT, proc_address,
        unicode: true, module: &[] }).unwrap()
}
fn last() -> (u32, ::sched::nt_callback::Completion) {
    let calls = CALLS.lock().unwrap(); let (bytes, completion) = calls.last().unwrap();
    (u64::from_le_bytes(bytes[24..32].try_into().unwrap()) as u32, *completion)
}
fn announce() -> u64 { hook_notify_win_event(0x800a, 0x100001, -4, 0, caller()) }
fn complete() -> u64 { callbacks::complete_callback(last().1, u64::MAX) }
#[test]
fn every_matching_hook_runs_in_order_and_callback_results_do_not_stop_delivery() {
    let _guard = reset();
    let older = add(HookScope::Global, 1, 0xffff, 10);
    add(HookScope::Global, 0x9000, 0xffff, 20);
    let newer = add(HookScope::Global, 0x8000, 0x8010, 30);
    assert_eq!(announce(), STATUS_PENDING); assert_eq!(last().0, newer);
    assert_eq!(complete(), STATUS_PENDING); assert_eq!(last().0, older);
    assert_eq!(complete(), 0);
    assert_eq!(CALLS.lock().unwrap().len(), 2);
}
#[test]
fn self_removal_and_deleted_successor_do_not_truncate_chain() {
    let _guard = reset();
    let last_hook = add(HookScope::Global, 1, 0xffff, 10);
    let deleted = add(HookScope::Global, 1, 0xffff, 20);
    let first = add(HookScope::Global, 1, 0xffff, 30);
    assert_eq!(announce(), STATUS_PENDING); assert_eq!(last().0, first);
    hook_remove(first).unwrap(); hook_remove(deleted).unwrap();
    assert_eq!(complete(), STATUS_PENDING); assert_eq!(last().0, last_hook);
    assert_eq!(complete(), 0);
    assert!(hook_remove(first).is_err());
}
#[test]
fn local_callback_can_insert_a_global_hook_seen_at_scope_transition() {
    let _guard = reset();
    let older = add(HookScope::Global, 1, 0xffff, 10);
    let local = add(HookScope::Thread(1), 1, 0xffff, 20);
    assert_eq!(announce(), STATUS_PENDING); assert_eq!(last().0, local);
    hook_remove(local).unwrap();
    let inserted = add(HookScope::Global, 1, 0xffff, 30);
    assert_eq!(complete(), STATUS_PENDING); assert_eq!(last().0, inserted);
    assert_eq!(complete(), STATUS_PENDING); assert_eq!(last().0, older);
    assert_eq!(complete(), 0);
}
#[test]
fn nested_announcements_have_independent_cursors_and_lifetimes() {
    let _guard = reset();
    let older = add(HookScope::Global, 1, 0xffff, 10);
    let newer = add(HookScope::Global, 1, 0xffff, 20);
    assert_eq!(announce(), STATUS_PENDING); let outer = last().1;
    assert_eq!(announce(), STATUS_PENDING); let inner = last().1;
    assert_ne!(outer.argument, inner.argument);
    hook_remove(newer).unwrap();
    assert_eq!(callbacks::complete_callback(inner, 0), STATUS_PENDING); assert_eq!(last().0, older);
    assert_eq!(complete(), 0);
    assert_eq!(callbacks::complete_callback(outer, 0), STATUS_PENDING); assert_eq!(last().0, older);
    assert_eq!(complete(), 0);
    assert!(hook_remove(newer).is_err());
}
#[test]
fn callback_admission_failure_advances_and_releases_the_walk() {
    let _guard = reset();
    let first = add(HookScope::Global, 1, 0xffff, 10);
    add(HookScope::Global, 1, 0xffff, 20);
    FAIL_CALLBACK.store(true, Ordering::Relaxed);
    assert_eq!(announce(), 0);
    assert_eq!(CALLS.lock().unwrap().len(), 2);
    hook_remove(first).unwrap(); assert!(hook_remove(first).is_err());
}
#[test]
fn exiting_announcer_retires_pending_delivery() {
    let _guard = reset();
    add(HookScope::Global, 1, 0xffff, 10);
    assert_eq!(announce(), STATUS_PENDING); let saved = last().1;
    hook_forget_thread(1);
    assert_eq!(callbacks::complete_callback(saved, 0), 0);
    assert_eq!(CALLS.lock().unwrap().len(), 1);
    assert_eq!(hook_chain_count(WH_WINEVENT, caller()), 0);
}
#[test]
fn continuation_filters_with_announced_event_not_previous_hooks_lower_bound() {
    let _guard = reset();
    let exact = add(HookScope::Global, 0x800a, 0x800a, 10);
    let broad = add(HookScope::Global, 0x8000, 0x8010, 20);
    assert_eq!(announce(), STATUS_PENDING); assert_eq!(last().0, broad);
    assert_eq!(complete(), STATUS_PENDING); assert_eq!(last().0, exact);
    assert_eq!(complete(), 0);
    for (record, _) in CALLS.lock().unwrap().iter() {
        assert_eq!(u32::from_le_bytes(record[..4].try_into().unwrap()), 0x800a);
    }
}
fn add_posted(owner:u64)->u32 {
    hook_install(HookScope::Global,&HookRequest{id:WH_WINEVENT,process:None,thread:None,owner,
        event_min:1,event_max:0xffff,flags:0,proc_address:99,unicode:true,module:&[]}).unwrap()
}
#[test]
fn out_of_context_hooks_are_posted_even_when_owner_is_announcer() {
    let _guard=reset();let older=add_posted(2);let newer=add_posted(1);
    assert_eq!(announce(),0);assert!(CALLS.lock().unwrap().is_empty());
    hook_remove(older).unwrap();hook_remove(newer).unwrap();
    let posts=POSTED.lock().unwrap();assert_eq!(posts.len(),2);
    assert_eq!((posts[0].0.handle,posts[0].0.owner),(newer,1));
    assert_eq!((posts[1].0.handle,posts[1].0.owner),(older,2));
    for (_,event) in posts.iter(){assert_eq!((event.event,event.hwnd,event.thread,event.time),(0x800a,0x100001,1,123));}
}
#[test]
fn mixed_chain_posts_on_each_side_of_synchronous_callback() {
    let _guard=reset();let older=add_posted(2);
    let synchronous=add(HookScope::Global,1,0xffff,10);let newer=add_posted(2);
    assert_eq!(announce(),STATUS_PENDING);assert_eq!(last().0,synchronous);
    assert_eq!(POSTED.lock().unwrap().len(),1);assert_eq!(POSTED.lock().unwrap()[0].0.handle,newer);
    assert_eq!(complete(),0);assert_eq!(POSTED.lock().unwrap().len(),2);
    assert_eq!(POSTED.lock().unwrap()[1].0.handle,older);assert_eq!(CALLS.lock().unwrap().len(),1);
}
