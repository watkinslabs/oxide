use super::*;
use super::tests::message;
    #[test]
    fn empty_paint_rect_admits_and_releases_a_real_transaction() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0x1234).unwrap();
        let empty = WindowRect { left: 0, top: 0, right: 0, bottom: 0 };
        assert_eq!(manager.begin_paint_rect(window), Ok(empty));
        assert_eq!(manager.paint_rect(window), Ok(empty));
        assert_eq!(manager.begin_paint_rect(window), Err(WindowError::PaintActive));
        assert_eq!(manager.end_paint(window), Ok(()));
        assert_eq!(manager.paint_rect(window), Err(WindowError::PaintNotActive));
        assert_eq!(manager.begin_paint_rect(window), Ok(empty));
        manager.destroy(window).unwrap();
        assert_eq!(manager.paint_rect(window), Err(WindowError::PaintNotActive));
    }
    #[test]
    fn key_lparam_encodes_transition_and_repeat_state() {
        assert_eq!(key_lparam(true, false), 1);
        assert_eq!(key_lparam(true, true), 0x4000_0002);
        assert_eq!(key_lparam(false, false), 0xc000_0001);
        assert_eq!(key_lparam(false, true), 0xc000_0002);
    }

    #[test]
    fn geometry_is_created_and_destroyed_with_the_window() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0x1234).unwrap();
        assert_eq!(manager.rect(window), Some(WindowRect { left: 0, top: 0, right: 0, bottom: 0 }));
        let rect = WindowRect { left: 10, top: 20, right: 410, bottom: 320 };
        manager.set_rect(window, rect).unwrap();
        assert_eq!(manager.rect(window), Some(rect));
        manager.destroy(window).unwrap();
        assert_eq!(manager.rect(window), None);
    }

    #[test]
    fn text_parent_and_visibility_follow_window_lifetime() {
        let mut manager = WindowManager::new();
        let parent = manager.create(9, None, 0).unwrap();
        let child = manager.create(9, Some(parent), 0).unwrap();
        manager.set_text(child, &[b'c' as u16, b't' as u16]).unwrap();
        assert_eq!(manager.text(child), Some(&[b'c' as u16, b't' as u16][..]));
        assert_eq!(manager.get(child).unwrap().parent, Some(parent));
        assert_eq!(manager.show(9, child, true), Ok(false));
        assert_eq!(manager.show(8, child, false), Err(WindowError::WrongThread));
        assert!(manager.get(child).unwrap().visible);
        manager.destroy(child).unwrap();
        assert_eq!(manager.text(child), None);
    }

    #[test]
    fn classes_are_case_insensitive_and_supply_the_window_procedure() {
        let mut manager = WindowManager::new();
        let atom = manager.register_class(&[b'N' as u16, b'o' as u16, b't' as u16], 0x1400).unwrap();
        assert_eq!(atom, 1);
        assert_eq!(manager.class_wndproc(&[b'n' as u16, b'O' as u16, b'T' as u16]), Some(0x1400));
        assert_eq!(manager.class_wndproc_by_atom(atom), Some(0x1400));
        assert_eq!(manager.class_info(&[b'n' as u16, b'O' as u16, b'T' as u16]).map(|value| (value.0, value.1)), Some((atom, 0x1400)));
        assert_eq!(manager.class_info_by_atom(atom).map(|value| value.2), Some(&[b'N' as u16, b'o' as u16, b't' as u16][..]));
        assert_eq!(manager.class_wndproc_by_atom(atom + 1), None);
        assert_eq!(manager.register_class(&[b'n' as u16, b'o' as u16, b't' as u16], 0x1500), Err(WindowError::InvalidParent));
    }

    #[test]
    fn class_unregister_waits_for_all_canonical_windows() {
        let mut manager = WindowManager::new();
        let name = [b'E' as u16, b'd' as u16, b'i' as u16, b't' as u16];
        let atom = manager.register_class(&name, 0x1400).unwrap();
        let window = manager.create_class_atom(9, None, atom).unwrap();
        assert_eq!(manager.unregister_class(&name), Err(WindowError::ClassInUse));
        manager.destroy(window).unwrap();
        assert_eq!(manager.unregister_class(&name), Ok(()));
        assert_eq!(manager.class_wndproc_by_atom(atom), None);
    }

    #[test]
    fn top_level_class_window_owns_visibility_and_message_delivery() {
        let mut manager = WindowManager::new();
        let atom = manager.register_class(&[b'N' as u16, b'o' as u16, b't' as u16], 0x1400).unwrap();
        let window = manager.create_class_atom(9, None, atom).unwrap();
        assert_eq!(manager.get(window).unwrap().wndproc, 0x1400);
        assert_eq!(manager.show(9, window, true), Ok(false));
        assert!(manager.get(window).unwrap().visible);
        let message = WinMessage { hwnd: Some(window), message: WM_CLOSE, wparam: 7, lparam: -9 };
        manager.post_to_window(window, message).unwrap();
        assert_eq!(manager.take_for_thread(9, MessageFilter { hwnd: Some(window), first: WM_CLOSE, last: WM_CLOSE }), QueueResult::Message(message));
        manager.destroy(window).unwrap();
        assert_eq!(manager.post_to_window(window, message), Err(WindowError::NoSuchWindow));
    }

    #[test]
    fn showing_sized_window_admits_one_full_paint_and_hide_does_not_repaint() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        let rect = WindowRect { left: 80, top: 60, right: 720, bottom: 540 };
        manager.set_rect(window, rect).unwrap();
        assert_eq!(manager.show(9, window, true), Ok(false));
        let filter = MessageFilter { hwnd: Some(window), first: WM_PAINT, last: WM_PAINT };
        assert_eq!(manager.peek_for_thread(9, filter, true).map(|message| message.message), Some(WM_PAINT));
        assert_eq!(manager.peek_for_thread(9, filter, true).map(|message| message.message), Some(WM_PAINT));
        assert_eq!(manager.begin_paint(window), Ok(Some(WindowRect { left: 0, top: 0, right: 640, bottom: 480 })));
        assert_eq!(manager.end_paint(window), Ok(()));
        assert_eq!(manager.begin_paint(window), Ok(None));
        assert_eq!(manager.peek_for_thread(9, filter, true), None);
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(window), first: WM_PAINT, last: WM_PAINT }, true), None);
        assert_eq!(manager.show(9, window, false), Ok(true));
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(window), first: WM_PAINT, last: WM_PAINT }, true), None);
    }

    #[test]
    fn invalidation_coalesces_and_begin_paint_consumes_one_dirty_region() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        manager.set_rect(window, WindowRect { left: 10, top: 20, right: 110, bottom: 120 }).unwrap();
        manager.set_visible(window, true).unwrap();
        let first = WindowRect { left: 2, top: 3, right: 20, bottom: 30 };
        manager.invalidate(window, Some(first)).unwrap();
        manager.invalidate(window, Some(WindowRect { left: 10, top: 1, right: 40, bottom: 50 })).unwrap();
        assert!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(window), first: WM_PAINT, last: WM_PAINT }, true).is_some());
        assert_eq!(manager.begin_paint(window), Ok(Some(WindowRect { left: 2, top: 1, right: 40, bottom: 50 })));
        assert!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(window), first: WM_PAINT, last: WM_PAINT }, true).is_none());
    }

    #[test]
    fn paint_transaction_requires_begin_before_end_and_closes_once() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        assert_eq!(manager.end_paint(window), Err(WindowError::PaintNotActive));
        assert_eq!(manager.begin_paint(window), Ok(None));
        assert_eq!(manager.begin_paint(window), Err(WindowError::PaintActive));
        assert_eq!(manager.end_paint(window), Ok(()));
        assert_eq!(manager.end_paint(window), Err(WindowError::PaintNotActive));
    }

    #[test]
    fn visible_paint_exposes_one_canonical_compositor_record() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        let bounds = WindowRect { left: 80, top: 60, right: 720, bottom: 540 };
        manager.set_rect(window, bounds).unwrap();
        manager.show(9, window, true).unwrap();
        manager.begin_paint(window).unwrap();
        manager.end_paint(window).unwrap();
        let damage = WindowRect { left: 12, top: 8, right: 40, bottom: 24 };
        manager.invalidate(window, Some(damage)).unwrap();
        manager.begin_paint(window).unwrap();
        assert_eq!(manager.present_record(window), Ok(WindowPresentRecord { window, bounds, damage: Some(damage) }));
        manager.end_paint(window).unwrap();
        assert_eq!(manager.present_record(window), Err(WindowError::PaintNotActive));
    }

    #[test]
    fn compositor_record_rejects_hidden_windows_and_clips_damage() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        manager.set_rect(window, WindowRect { left: 0, top: 0, right: 20, bottom: 20 }).unwrap();
        manager.invalidate(window, Some(WindowRect { left: -4, top: 2, right: 30, bottom: 40 })).unwrap();
        assert_eq!(manager.begin_paint(window), Ok(Some(WindowRect { left: 0, top: 2, right: 20, bottom: 20 })));
        assert_eq!(manager.present_record(window), Err(WindowError::NotVisible));
        manager.end_paint(window).unwrap();
        manager.show(9, window, true).unwrap();
        assert_eq!(manager.begin_paint(window), Ok(Some(WindowRect { left: 0, top: 0, right: 20, bottom: 20 })));
    }

    #[test]
    fn destroying_window_closes_an_open_paint_transaction() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        manager.begin_paint(window).unwrap();
        manager.destroy(window).unwrap();
        assert_eq!(manager.end_paint(window), Err(WindowError::PaintNotActive));
    }

    #[test]
    fn queue_rejects_messages_after_its_bounded_capacity() {
        let mut queue = MessageQueue::default();
        for _ in 0..MESSAGE_QUEUE_LIMIT { queue.post(message(None, 1)).unwrap(); }
        assert_eq!(queue.post(message(None, 2)), Err(QueueError::Full));
        assert_eq!(queue.len(), MESSAGE_QUEUE_LIMIT);
    }

    #[test]
    fn focused_relative_motion_posts_bounded_client_coordinates() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        manager.set_rect(window, WindowRect { left: 40, top: 50, right: 140, bottom: 130 }).unwrap();
        manager.set_focus(9, Some(window)).unwrap();
        manager.post_focused_mouse(0, 120).unwrap();
        manager.post_focused_mouse(1, 90).unwrap();
        let filter = MessageFilter { hwnd: Some(window), first: WM_MOUSEMOVE, last: WM_MOUSEMOVE };
        assert_eq!(manager.take_for_thread(9, filter), QueueResult::Message(WinMessage { hwnd: Some(window), message: WM_MOUSEMOVE, wparam: 0, lparam: mouse_lparam(99, 0) }));
        assert_eq!(manager.take_for_thread(9, filter), QueueResult::Message(WinMessage { hwnd: Some(window), message: WM_MOUSEMOVE, wparam: 0, lparam: mouse_lparam(99, 79) }));
    }

    #[test]
    fn captured_pointer_routes_buttons_and_signed_wheel_to_capture_owner() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        manager.set_rect(window, WindowRect { left: 40, top: 50, right: 140, bottom: 130 }).unwrap();
        manager.show(9, window, true).unwrap();
        manager.set_capture(9, window).unwrap();
        manager.post_hardware_mouse(EV_REL, REL_X, 200).unwrap();
        manager.post_hardware_mouse(EV_REL, REL_WHEEL, -1).unwrap();
        manager.post_hardware_mouse(EV_KEY, BTN_LEFT, 1).unwrap();
        manager.post_hardware_mouse(EV_KEY, BTN_LEFT, 0).unwrap();
        let any = MessageFilter { hwnd: Some(window), first: WM_MOUSEMOVE, last: WM_MOUSEWHEEL };
        assert_eq!(manager.take_for_thread(9, any), QueueResult::Message(WinMessage { hwnd: Some(window), message: WM_MOUSEMOVE, wparam: 0, lparam: mouse_lparam(160, -50) }));
        assert_eq!(manager.take_for_thread(9, any), QueueResult::Message(WinMessage { hwnd: Some(window), message: WM_MOUSEWHEEL, wparam: ((-120i16 as u16) as u64) << 16, lparam: mouse_lparam(200, 0) }));
        assert_eq!(manager.take_for_thread(9, any), QueueResult::Message(WinMessage { hwnd: Some(window), message: WM_LBUTTONDOWN, wparam: MK_LBUTTON as u64, lparam: mouse_lparam(160, -50) }));
        assert_eq!(manager.take_for_thread(9, any), QueueResult::Message(WinMessage { hwnd: Some(window), message: WM_LBUTTONUP, wparam: 0, lparam: mouse_lparam(160, -50) }));
    }

    #[test]
    fn pointer_capture_is_thread_owned_and_destroy_releases_it() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        assert_eq!(manager.set_capture(8, window), Err(WindowError::WrongThread));
        manager.set_capture(9, window).unwrap();
        assert_eq!(manager.captured(), Some(window));
        manager.destroy(window).unwrap();
        assert_eq!(manager.captured(), None);
    }

    #[test]
    fn filtered_peek_can_remove_only_the_matching_message() {
        let mut queue = MessageQueue::default();
        queue.post(message(None, 10)).unwrap();
        queue.post(message(None, 20)).unwrap();
        assert_eq!(queue.peek(MessageFilter { hwnd: None, first: 15, last: 25 }, true), Some(message(None, 20)));
        assert_eq!(queue.peek(MessageFilter { hwnd: None, first: 0, last: 100 }, true), Some(message(None, 10)));
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn clipboard_open_is_shared_by_window_and_close_is_thread_owned() {
        let mut clipboard = ClipboardManager::new();
        let window = WindowId::from_raw(7);
        assert!(clipboard.open(11, window));
        assert!(clipboard.is_open());
        assert!(clipboard.open(22, window));
        assert!(!clipboard.close(11));
        assert!(clipboard.close(22));
        assert!(!clipboard.is_open());
    }

    #[test]
    fn clipboard_rejects_a_different_window_until_the_owner_closes() {
        let mut clipboard = ClipboardManager::new();
        assert!(clipboard.open(11, WindowId::from_raw(7)));
        assert!(!clipboard.open(11, WindowId::from_raw(8)));
        assert!(!clipboard.open(22, None));
        assert!(clipboard.close(11));
        assert!(clipboard.open(22, None));
    }
