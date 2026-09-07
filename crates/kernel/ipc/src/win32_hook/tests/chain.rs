//! Chain order, removal and the thread/event filters of the walk.
use super::*;

fn request<'a>(id: i32, proc_address: u64) -> HookRequest<'a> {
    HookRequest { id, process: None, thread: None, owner: 1, event_min: EVENT_MIN, event_max: EVENT_MAX,
        flags: 0, proc_address, unicode: true, module: &[] }
}

fn here() -> HookThread { HookThread { thread: 1, process: 1 } }

#[test]
fn the_most_recently_installed_hook_runs_first() {
    let mut table = HookTable::new();
    let first = table.install(&request(WH_CBT, 0x10)).unwrap();
    let second = table.install(&request(WH_CBT, 0x20)).unwrap();
    assert_eq!(table.next_hook(WH_CBT, None, here(), EVENT_MIN).map(|hook| hook.handle), Some(second));
    assert_eq!(table.next_hook(WH_CBT, Some(second), here(), EVENT_MIN).map(|hook| hook.handle), Some(first));
    assert_eq!(table.next_hook(WH_CBT, Some(first), here(), EVENT_MIN).map(|hook| hook.handle), None);
}

#[test]
fn chains_do_not_see_each_other() {
    let mut table = HookTable::new();
    table.install(&request(WH_CBT, 0x10)).unwrap();
    table.install(&request(WH_GETMESSAGE, 0x20)).unwrap();
    assert_eq!(table.chain_count(WH_CBT), 1);
    assert_eq!(table.chain_count(WH_GETMESSAGE), 1);
    assert_eq!(table.chain_count(WH_MOUSE_LL), 0);
}

#[test]
fn removal_by_handle_reports_an_unknown_handle_and_removal_by_proc_an_unknown_pair() {
    let mut table = HookTable::new();
    let handle = table.install(&request(WH_CBT, 0x10)).unwrap();
    assert_eq!(table.remove(handle + 99).err(), Some(HookError::InvalidHandle));
    assert_eq!(table.remove_by_proc(WH_CBT, 0x99).err(), Some(HookError::InvalidParameter));
    assert_eq!(table.remove_by_proc(WH_CBT, 0).err(), Some(HookError::InvalidParameter));
    assert_eq!(table.remove_by_proc(WH_CBT, 0x10).map(|hook| hook.handle), Ok(handle));
    assert_eq!(table.chain_count(WH_CBT), 0);
    assert!(table.get(handle).is_none());
}

#[test]
fn a_thread_bound_hook_is_skipped_in_every_other_thread() {
    let mut table = HookTable::new();
    let mut bound = request(WH_CBT, 0x10);
    bound.thread = Some(7);
    table.install(&bound).unwrap();
    assert!(table.next_hook(WH_CBT, None, here(), EVENT_MIN).is_none());
    assert!(table.next_hook(WH_CBT, None, HookThread { thread: 7, process: 1 }, EVENT_MIN).is_some());
}

#[test]
fn the_skip_flags_exclude_the_installers_own_thread_and_process() {
    let mut own_thread = request(WH_WINEVENT, 0x10);
    own_thread.thread = Some(1);
    own_thread.flags = WINEVENT_SKIPOWNTHREAD;
    let mut table = HookTable::new();
    table.install(&own_thread).unwrap();
    assert!(table.next_hook(WH_WINEVENT, None, here(), EVENT_MIN).is_none());

    let mut own_process = request(WH_WINEVENT, 0x20);
    own_process.process = Some(1);
    own_process.flags = WINEVENT_SKIPOWNPROCESS;
    let mut table = HookTable::new();
    table.install(&own_process).unwrap();
    assert!(table.next_hook(WH_WINEVENT, None, here(), EVENT_MIN).is_none());
    assert!(table.next_hook(WH_WINEVENT, None, HookThread { thread: 1, process: 2 }, EVENT_MIN).is_none());
}

#[test]
fn an_event_outside_a_win_event_hooks_range_skips_it() {
    let mut narrow = request(WH_WINEVENT, 0x10);
    narrow.event_min = 0x8000;
    narrow.event_max = 0x8010;
    let mut table = HookTable::new();
    table.install(&narrow).unwrap();
    assert!(table.next_hook(WH_WINEVENT, None, here(), 0x7fff).is_none());
    assert!(table.next_hook(WH_WINEVENT, None, here(), 0x8000).is_some());
    assert!(table.next_hook(WH_WINEVENT, None, here(), 0x8011).is_none());
}

#[test]
fn a_low_level_hook_runs_in_the_thread_that_installed_it() {
    let mut table = HookTable::new();
    let handle = table.install(&request(WH_MOUSE_LL, 0x10)).unwrap();
    let hook = table.get(handle).unwrap();
    assert!(runs_in_owner_thread(hook, 2));
    assert!(!runs_in_owner_thread(hook, 1));

    let mut table = HookTable::new();
    let handle = table.install(&request(WH_CBT, 0x10)).unwrap();
    assert!(!runs_in_owner_thread(table.get(handle).unwrap(), 2));
}

#[test]
fn an_identifier_outside_the_chain_range_cannot_be_installed() {
    let mut table = HookTable::new();
    assert_eq!(table.install(&request(WH_WINEVENT + 1, 0x10)).err(), Some(HookError::InvalidParameter));
}
