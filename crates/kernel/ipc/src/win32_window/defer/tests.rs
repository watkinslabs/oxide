//! Batch capacity, merge rules and replay order.
use super::*;

fn position(window: u32, flags: u32) -> DeferredPosition {
    DeferredPosition { window: WindowId::from_raw(window).unwrap(), insert_after: 0,
        x: 1, y: 2, cx: 3, cy: 4, flags }
}

#[test]
fn a_negative_count_is_refused_and_a_zero_count_still_opens_a_batch() {
    let mut batches = DeferBatches::new();
    assert_eq!(batches.begin(-1), Err(DeferError::InvalidParameter));
    assert!(batches.begin(0).is_ok());
    assert_eq!(batches.len(), 1);
}

#[test]
fn every_batch_gets_its_own_handle_and_an_unknown_handle_is_reported() {
    let mut batches = DeferBatches::new();
    let first = batches.begin(2).unwrap();
    let second = batches.begin(2).unwrap();
    assert_ne!(first, second);
    assert_eq!(batches.defer(first + second + 1, position(1, 0)), Err(DeferError::InvalidHandle));
    assert_eq!(batches.end(first + second + 1), Err(DeferError::InvalidHandle));
}

#[test]
fn moves_replay_in_the_order_they_were_added_and_the_batch_closes() {
    let mut batches = DeferBatches::new();
    let handle = batches.begin(0).unwrap();
    batches.defer(handle, position(1, 0)).unwrap();
    batches.defer(handle, position(2, 0)).unwrap();
    let replayed = batches.end(handle).unwrap();
    assert_eq!(replayed.iter().map(|entry| entry.window.raw()).collect::<alloc::vec::Vec<_>>(), alloc::vec![1, 2]);
    assert!(batches.is_empty());
    assert_eq!(batches.end(handle), Err(DeferError::InvalidHandle));
}

#[test]
fn a_second_move_for_one_window_merges_rather_than_queueing_twice() {
    let mut batches = DeferBatches::new();
    let handle = batches.begin(0).unwrap();
    batches.defer(handle, position(1, SWP_NOSIZE)).unwrap();
    let mut second = position(1, SWP_NOMOVE);
    second.cx = 30; second.cy = 40;
    batches.defer(handle, second).unwrap();
    let replayed = batches.end(handle).unwrap();
    assert_eq!(replayed.len(), 1);
    // The move came from the first request and the size from the second.
    assert_eq!((replayed[0].x, replayed[0].y), (1, 2));
    assert_eq!((replayed[0].cx, replayed[0].cy), (30, 40));
}

#[test]
fn a_suppression_flag_survives_only_when_both_requests_carry_it() {
    let mut batches = DeferBatches::new();
    let handle = batches.begin(0).unwrap();
    batches.defer(handle, position(1, SWP_NOZORDER | SWP_NOACTIVATE)).unwrap();
    batches.defer(handle, position(1, SWP_NOACTIVATE)).unwrap();
    let replayed = batches.end(handle).unwrap();
    assert_eq!(replayed[0].flags & SWP_NOZORDER, 0);
    assert_ne!(replayed[0].flags & SWP_NOACTIVATE, 0);
}

#[test]
fn a_show_hide_or_frame_change_is_gained_from_either_request() {
    let mut batches = DeferBatches::new();
    let handle = batches.begin(0).unwrap();
    batches.defer(handle, position(1, 0)).unwrap();
    batches.defer(handle, position(1, SWP_SHOWWINDOW | SWP_FRAMECHANGED)).unwrap();
    let replayed = batches.end(handle).unwrap();
    assert_ne!(replayed[0].flags & SWP_SHOWWINDOW, 0);
    assert_ne!(replayed[0].flags & SWP_FRAMECHANGED, 0);
}

#[test]
fn the_z_order_target_is_taken_only_from_a_request_that_orders() {
    let mut batches = DeferBatches::new();
    let handle = batches.begin(0).unwrap();
    let mut first = position(1, 0);
    first.insert_after = 7;
    batches.defer(handle, first).unwrap();
    let mut second = position(1, SWP_NOZORDER);
    second.insert_after = 9;
    batches.defer(handle, second).unwrap();
    assert_eq!(batches.end(handle).unwrap()[0].insert_after, 7);
}

#[test]
fn batches_do_not_see_each_others_moves() {
    let mut batches = DeferBatches::new();
    let first = batches.begin(0).unwrap();
    let second = batches.begin(0).unwrap();
    batches.defer(first, position(1, 0)).unwrap();
    assert_eq!(batches.end(second).unwrap().len(), 0);
    assert_eq!(batches.end(first).unwrap().len(), 1);
}
