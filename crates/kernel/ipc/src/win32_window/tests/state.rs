use super::*;
use alloc::vec;
    #[test]
    fn user_message_atoms_are_case_insensitive_and_stable() {
        let mut atoms = UserAtomTable::new();
        assert_eq!(atoms.register(&[b'F' as u16, b'i' as u16, b'n' as u16]), Some(USER_ATOM_BASE + 1));
        assert_eq!(atoms.register(&[b'f' as u16, b'I' as u16, b'N' as u16]), Some(USER_ATOM_BASE + 1));
        assert_eq!(atoms.register(&[b'P' as u16, b'a' as u16, b'i' as u16, b'n' as u16]), Some(USER_ATOM_BASE + 2));
    }

    #[test]
    fn user_message_atoms_reject_invalid_and_exhausted_names() {
        let mut atoms = UserAtomTable::new();
        assert_eq!(atoms.register(&[]), None);
        assert_eq!(atoms.register(&[b'x' as u16; USER_ATOM_MAX_LENGTH + 1]), None);
        for index in 0..USER_ATOM_CAPACITY - 1 {
            assert_eq!(atoms.register(&[0x0100 + index as u16]), Some(USER_ATOM_BASE + index as u16 + 1));
        }
        assert_eq!(atoms.register(&[u16::MAX]), None);
    }

    pub(super) fn message(hwnd: Option<WindowId>, message: u32) -> WinMessage { WinMessage { hwnd, message, wparam: 1, lparam: 2 } }

    #[test]
    fn queue_filters_without_reordering_unmatched_messages() {
        let mut queue = MessageQueue::default();
        queue.post(message(None, 1)).unwrap();
        let window = WindowId(7);
        queue.post(message(Some(window), 2)).unwrap();
        queue.post(message(None, 3)).unwrap();
        let filter = MessageFilter { hwnd: Some(window), first: 2, last: 2 };
        assert_eq!(queue.peek(filter, false), Some(message(Some(window), 2)));
        assert_eq!(queue.peek(filter, true), Some(message(Some(window), 2)));
        assert_eq!(queue.peek(MessageFilter { hwnd: None, first: 0, last: u32::MAX }, true), Some(message(None, 1)));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn zero_message_bounds_select_the_entire_queue() {
        let mut queue = MessageQueue::default();
        queue.post(message(None, 0x0042)).unwrap();
        queue.post(message(None, WM_PAINT)).unwrap();
        let filter = MessageFilter { hwnd: None, first: 0, last: 0 };
        assert_eq!(queue.peek(filter, true).map(|value| value.message), Some(0x0042));
        assert_eq!(queue.peek(filter, true).map(|value| value.message), Some(WM_PAINT));
    }

    #[test]
    fn quit_is_thread_owned_and_is_consumed_after_queued_messages() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        manager.post_to_window(window, message(Some(window), WM_CLOSE)).unwrap();
        manager.post_quit(9, 37);
        let filter = MessageFilter { hwnd: None, first: 0, last: u32::MAX };
        assert!(matches!(manager.take_for_thread(9, filter), QueueResult::Message(_)));
        assert_eq!(manager.take_for_thread(9, filter), QueueResult::Quit(37));
        assert_eq!(manager.take_for_thread(8, filter), QueueResult::Empty);
        manager.post_quit(9, 41);
        assert_eq!(manager.peek_for_thread(9, filter, false).map(|value| value.message), Some(WM_QUIT));
        assert_eq!(manager.peek_for_thread(9, filter, true).map(|value| value.wparam), Some(41));
        assert_eq!(manager.peek_for_thread(9, filter, false), None);
    }

    #[test]
    fn windows_use_monotonic_handles_and_validate_parent_lifetime() {
        let mut manager = WindowManager::new();
        let first = manager.create(4, None, 0x1000).unwrap();
        let child = manager.create(4, Some(first), 0x2000).unwrap();
        assert_eq!(manager.create(4, Some(WindowId(99)), 0), Err(WindowError::InvalidParent));
        manager.destroy(first).unwrap();
        assert_eq!(manager.get(first), None);
        assert_eq!(manager.create(4, None, 0).unwrap().raw(), child.raw() + 1);
    }

    #[test]
    fn timers_replace_by_window_and_enqueue_callback_message_after_deadline() {
        let mut manager = WindowManager::new();
        let window = manager.create(7, None, 0x1000).unwrap();
        assert_eq!(manager.set_timer(7, Some(window), 3, 10, 0xfeed, 100), Ok(3));
        assert_eq!(manager.set_timer(7, Some(window), 3, 20, 0xbeef, 200), Ok(3));
        assert_eq!(manager.expire_timers(19_000_199), 0);
        assert_eq!(manager.expire_timers(20_000_200), 1);
        let filter = MessageFilter { hwnd: Some(window), first: WM_TIMER, last: WM_TIMER };
        assert_eq!(manager.peek_for_thread(7, filter, true).map(|message| (message.wparam, message.lparam)), Some((3, 0xbeef)));
        assert!(manager.kill_timer(Some(window), 3));
        assert!(!manager.kill_timer(Some(window), 3));
    }

    #[test]
    fn default_window_proc_exposes_close_and_client_hit_test_policy() {
        assert_eq!(default_window_proc(WM_CLOSE), DefaultWindowResult::RequestDestroy);
        assert_eq!(default_window_proc(WM_NCHITTEST), DefaultWindowResult::Return(HTCLIENT));
        assert_eq!(default_window_proc(WM_DESTROY), DefaultWindowResult::Return(0));
        assert_eq!(default_window_proc(WM_NCACTIVATE), DefaultWindowResult::Return(1));
    }

    #[test]
    fn dispatch_does_not_deliver_thread_quit_to_a_window_procedure() {
        assert!(!dispatches_to_window_proc(WM_QUIT));
        assert!(dispatches_to_window_proc(WM_PAINT));
        assert!(dispatches_to_window_proc(WM_CLOSE));
    }

    #[test]
    fn default_hit_test_uses_canonical_window_bounds() {
        let rect = WindowRect { left: 10, top: 20, right: 110, bottom: 120 };
        let inside = ((40u16 as u64) | ((60u16 as u64) << 16)) as i64;
        let outside = ((9u16 as u64) | ((60u16 as u64) << 16)) as i64;
        assert_eq!(default_window_proc_for_rect(WM_NCHITTEST, rect, inside), DefaultWindowResult::Return(HTCLIENT));
        assert_eq!(default_window_proc_for_rect(WM_NCHITTEST, rect, outside), DefaultWindowResult::Return(HTNOWHERE));
    }

    #[test]
    fn posting_routes_to_the_owner_queue_and_destroy_removes_the_window() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0x1234).unwrap();
        manager.post_to_window(window, message(Some(window), WM_CLOSE)).unwrap();
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(window), first: WM_CLOSE, last: WM_CLOSE }, false), Some(message(Some(window), WM_CLOSE)));
        assert_eq!(manager.peek_for_thread(8, MessageFilter { hwnd: None, first: 0, last: u32::MAX }, false), None);
        assert_eq!(manager.destroy(window).unwrap().wndproc, 0x1234);
        assert_eq!(manager.post_to_window(window, message(None, 1)), Err(WindowError::NoSuchWindow));
    }

    #[test]
    fn message_filter_accepts_null_and_live_hwnd_but_rejects_stale_hwnd() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        assert_eq!(manager.validate_message_filter(None), Ok(()));
        assert_eq!(manager.validate_message_filter(Some(window)), Ok(()));
        manager.destroy(window).unwrap();
        assert_eq!(manager.validate_message_filter(Some(window)), Err(WindowError::NoSuchWindow));
    }

    #[test]
    fn parent_hwnd_filter_includes_descendant_messages_but_not_siblings() {
        let mut manager = WindowManager::new();
        let parent = manager.create(9, None, 0).unwrap();
        let child = manager.create(9, Some(parent), 0).unwrap();
        let sibling = manager.create(9, None, 0).unwrap();
        manager.post_to_window(child, message(Some(child), WM_KEYDOWN)).unwrap();
        manager.post_to_window(sibling, message(Some(sibling), WM_KEYUP)).unwrap();
        let filter = MessageFilter { hwnd: Some(parent), first: 0, last: u32::MAX };
        assert_eq!(manager.peek_for_thread(9, filter, false).map(|value| value.hwnd), Some(Some(child)));
        assert_eq!(manager.take_for_thread(9, filter), QueueResult::Message(message(Some(child), WM_KEYDOWN)));
        assert_eq!(manager.take_for_thread(9, filter), QueueResult::Empty);
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: None, first: 0, last: u32::MAX }, true).map(|value| value.hwnd), Some(Some(sibling)));
    }

    #[test]
    fn hwnd_filtered_get_does_not_consume_thread_quit_until_unfiltered() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        manager.post_quit(9, 23);
        let filtered = MessageFilter { hwnd: Some(window), first: 0, last: u32::MAX };
        assert_eq!(manager.take_for_thread(9, filtered), QueueResult::Empty);
        assert!(manager.quit_pending(9));
        let unfiltered = MessageFilter { hwnd: None, first: 0, last: u32::MAX };
        assert_eq!(manager.take_for_thread(9, unfiltered), QueueResult::Quit(23));
        assert!(!manager.quit_pending(9));
    }

    #[test]
    fn destroying_a_parent_removes_children_before_the_parent() {
        let mut manager = WindowManager::new();
        let parent = manager.create(9, None, 0x1234).unwrap();
        let child = manager.create(9, Some(parent), 0x5678).unwrap();
        manager.destroy(parent).unwrap();
        assert_eq!(manager.get(child), None);
        assert_eq!(manager.get(parent), None);
    }

    #[test]
    fn destroying_a_window_cleans_its_queue_messages_and_timers() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0x1234).unwrap();
        manager.post_to_window(window, message(Some(window), WM_CLOSE)).unwrap();
        manager.post_to_window(window, message(Some(window), WM_PAINT)).unwrap();
        manager.set_timer(9, Some(window), 3, 10, 0xfeed, 100).unwrap();
        manager.destroy(window).unwrap();
        let filter = MessageFilter { hwnd: None, first: 0, last: u32::MAX };
        assert_eq!(manager.peek_for_thread(9, filter, false), None);
        assert_eq!(manager.expire_timers(u64::MAX), 0);
    }

    #[test]
    fn destroying_menu_owner_can_detach_its_window_association() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        assert_eq!(manager.set_menu(window, Some(4)), Ok(None));
        manager.clear_menu(4);
        assert_eq!(manager.get(window).unwrap().menu, None);
    }

    #[test]
    fn destruction_reservation_is_idempotent_and_cancelable() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0x1234).unwrap();
        assert_eq!(manager.begin_destroy(9, window), Ok(true));
        assert_eq!(manager.begin_destroy(9, window), Ok(false));
        manager.cancel_destroy(window);
        assert_eq!(manager.begin_destroy(9, window), Ok(true));
        manager.destroy(window).unwrap();
        assert_eq!(manager.begin_destroy(9, window), Err(WindowError::NoSuchWindow));
    }

    #[test]
    fn destruction_order_is_parent_first_and_children_before_parent_cleanup() {
        let mut manager = WindowManager::new();
        let parent = manager.create(9, None, 0x1).unwrap();
        let first = manager.create(9, Some(parent), 0x2).unwrap();
        let second = manager.create(9, Some(parent), 0x3).unwrap();
        let grandchild = manager.create(9, Some(first), 0x4).unwrap();
        assert_eq!(manager.destruction_order(parent), Some(vec![parent, first, grandchild, second]));
    }

    #[test]
    fn subtree_reservation_rejects_reentry_for_every_descendant_and_rolls_back() {
        let mut manager = WindowManager::new();
        let parent = manager.create(9, None, 0x1).unwrap();
        let child = manager.create(9, Some(parent), 0x2).unwrap();
        let sibling = manager.create(9, Some(parent), 0x3).unwrap();
        assert_eq!(manager.begin_destroy(9, parent), Ok(true));
        assert_eq!(manager.begin_destroy(9, child), Ok(false));
        assert_eq!(manager.begin_destroy(9, sibling), Ok(false));
        manager.cancel_destroy(parent);
        assert_eq!(manager.begin_destroy(9, child), Ok(true));
        manager.cancel_destroy(child);
        assert_eq!(manager.begin_destroy(9, parent), Ok(true));
    }

    #[test]
    fn destruction_reservation_rejects_a_non_owner_without_mutating_the_window() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0x1234).unwrap();
        assert_eq!(manager.begin_destroy(8, window), Err(WindowError::WrongThread));
        assert_eq!(manager.get(window).unwrap().owner_tid, 9);
        assert_eq!(manager.begin_destroy(9, window), Ok(true));
    }

    #[test]
    fn focus_returns_previous_window_and_routes_key_transitions() {
        let mut manager = WindowManager::new();
        let first = manager.create(9, None, 0).unwrap();
        let second = manager.create(9, None, 0).unwrap();
        assert_eq!(manager.set_focus(9, Some(first)), Ok(None));
        assert_eq!(manager.set_focus(9, Some(second)), Ok(Some(first)));
        assert_eq!(manager.focused(), Some(second));
        manager.post_key(9, 0x41, true, false).unwrap();
        let filter = MessageFilter { hwnd: Some(second), first: WM_KEYDOWN, last: WM_KEYDOWN };
        assert_eq!(manager.peek_for_thread(9, filter, true), Some(WinMessage { hwnd: Some(second), message: WM_KEYDOWN, wparam: 0x41, lparam: 1 }));
    }

    #[test]
    fn focus_transition_notifies_old_and_new_windows_in_order() {
        let mut manager = WindowManager::new();
        let old = manager.create(9, None, 0).unwrap();
        let new = manager.create(9, None, 0).unwrap();
        assert_eq!(manager.set_focus(9, Some(old)), Ok(None));
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(old), first: WM_SETFOCUS, last: WM_SETFOCUS }, true), Some(WinMessage { hwnd: Some(old), message: WM_SETFOCUS, wparam: 0, lparam: 0 }));
        assert_eq!(manager.set_focus(9, Some(new)), Ok(Some(old)));
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(old), first: WM_KILLFOCUS, last: WM_KILLFOCUS }, true), Some(WinMessage { hwnd: Some(old), message: WM_KILLFOCUS, wparam: new.raw() as u64, lparam: 0 }));
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(new), first: WM_SETFOCUS, last: WM_SETFOCUS }, true), Some(WinMessage { hwnd: Some(new), message: WM_SETFOCUS, wparam: old.raw() as u64, lparam: 0 }));
        assert_eq!(manager.set_focus(9, None), Ok(Some(new)));
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(new), first: WM_KILLFOCUS, last: WM_KILLFOCUS }, true), Some(WinMessage { hwnd: Some(new), message: WM_KILLFOCUS, wparam: 0, lparam: 0 }));
    }

    #[test]
    fn focus_rejects_other_threads_and_clears_on_destroy() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        assert_eq!(manager.set_focus(8, Some(window)), Err(WindowError::WrongThread));
        assert_eq!(manager.post_key(9, 0x41, true, false), Err(WindowError::NoFocus));
        manager.set_focus(9, Some(window)).unwrap();
        assert_eq!(manager.set_focus(9, None), Ok(Some(window)));
        assert_eq!(manager.focused(), None);
        manager.set_focus(9, Some(window)).unwrap();
        manager.destroy(window).unwrap();
        assert_eq!(manager.focused(), None);
        assert_eq!(manager.post_key(9, 0x41, true, false), Err(WindowError::NoFocus));
    }
