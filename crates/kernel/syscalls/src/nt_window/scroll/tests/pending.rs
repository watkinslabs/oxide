use super::*;

#[test]
fn pending_frame_does_not_release_scroll_result() {
    let mut queue = Queue::default();
    let token = queue.admit(7, 91, 1, 42, true, false).unwrap();
    assert_eq!(queue.complete(7, token, Outcome::Pending), None);
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.complete(7, token, Outcome::Complete(1)).unwrap().result, 42);
    assert_eq!(queue.len(), 0);
}

#[test]
fn terminal_completion_preserves_frame_context_and_saved_redraw() {
    let mut queue = Queue::default();
    let token = queue.admit(11, 0x44, 1, -9, true, true).unwrap();
    let pending = queue.complete(11, token, Outcome::Complete(0)).unwrap();
    assert_eq!((pending.tid, pending.root, pending.bar, pending.result, pending.redraw, pending.hidden), (11, 0x44, 1, -9, true, true));
    assert!(!pending.should_repaint());
}

#[test]
fn visible_pending_repaints_only_when_redraw_was_requested() {
    let mut queue = Queue::default();
    let token = queue.admit(11, 0x44, 1, 9, true, false).unwrap();
    let pending = queue.complete(11, token, Outcome::Complete(1)).unwrap();
    assert!(pending.should_repaint());
}

#[test]
fn completion_is_tid_and_token_owned() {
    let mut queue = Queue::default();
    let token = queue.admit(7, 91, 0, 3, false, false).unwrap();
    assert_eq!(queue.complete(8, token, Outcome::Complete(1)), None);
    assert_eq!(queue.len(), 1);
    assert!(queue.complete(7, token, Outcome::Failed).is_some());
}

#[test]
fn cancellation_is_scoped_to_tid_or_root() {
    let mut queue = Queue::default();
    queue.admit(1, 9, 0, 1, true, false).unwrap();
    queue.admit(2, 9, 1, 2, true, false).unwrap();
    queue.cancel_tid(1);
    assert_eq!(queue.len(), 1);
    queue.cancel_root(9);
    assert_eq!(queue.len(), 0);
}
