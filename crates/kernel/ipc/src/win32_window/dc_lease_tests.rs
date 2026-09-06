use super::*;
use crate::win32_gdi::{DCX_CLIPCHILDREN, DCX_CLIPSIBLINGS, DCX_WINDOW};

fn rect(left: i32, top: i32, right: i32, bottom: i32) -> WindowRect { WindowRect { left, top, right, bottom } }

#[test]
fn client_context_reports_backing_origin_dimensions_and_exact_region() {
    let mut manager = WindowManager::new();
    let parent = manager.create(1, None, 0).unwrap();
    let child = manager.create(1, Some(parent), 0).unwrap();
    manager.set_window_styles(parent, 0x1000_0000, 0).unwrap();
    manager.set_window_styles(child, 0x1000_0000, 0).unwrap();
    manager.set_rect(parent, rect(10, 20, 110, 120)).unwrap();
    manager.set_rect(child, rect(5, 6, 45, 36)).unwrap();
    manager.show(1, parent, true).unwrap();
    manager.show(1, child, true).unwrap();
    manager.windows.iter_mut().find(|(id, _)| *id == parent).unwrap().1.record.client_rect = Some(rect(10, 20, 100, 120));
    manager.windows.iter_mut().find(|(id, _)| *id == child).unwrap().1.record.client_rect = Some(rect(7, 9, 43, 33));
    let context = manager.dc_lease_context(child, 0).unwrap();
    assert_eq!(context.backing_hwnd, child.raw());
    assert_eq!(context.screen_origin, (17, 29));
    assert_eq!((context.logical_width, context.logical_height), (36, 24));
    assert_eq!(context.origin, (2, 3));
    assert_eq!(context.visible, PaintRegion::from_rect(rect(0, 0, 36, 24)).unwrap());
}

#[test]
fn default_lease_is_cached_and_class_style_selects_own_or_class_owner() {
    let mut manager = WindowManager::new();
    let cached = manager.create(1, None, 0).unwrap();
    manager.set_window_styles(cached, 0x1000_0000, 0).unwrap();
    assert_eq!(manager.dc_lease_context(cached, 0).unwrap().owner, crate::win32_gdi::LeaseOwner::Cached);
    let own_atom = manager.register_class_with_style(&[1], 0, 0, true, 0x20).unwrap();
    let class_atom = manager.register_class_with_style(&[2], 0, 0, true, 0x40).unwrap();
    let window = manager.create(1, None, 0).unwrap();
    manager.windows.iter_mut().find(|(id, _)| *id == window).unwrap().1.record.class_atom = Some(own_atom);
    manager.set_window_styles(window, 0x1000_0000, 0).unwrap();
    assert_eq!(manager.dc_lease_context(window, 0).unwrap().owner, crate::win32_gdi::LeaseOwner::Window(window.raw()));
    manager.windows.iter_mut().find(|(id, _)| *id == window).unwrap().1.record.class_atom = Some(class_atom);
    assert_eq!(manager.dc_lease_context(window, 0).unwrap().owner, crate::win32_gdi::LeaseOwner::Class(class_atom));
}

#[test]
fn window_lease_clips_visible_children_and_later_siblings_exactly() {
    let mut manager = WindowManager::new();
    let parent = manager.create(1, None, 0).unwrap();
    let target = manager.create(1, Some(parent), 0).unwrap();
    let child = manager.create(1, Some(target), 0).unwrap();
    let sibling = manager.create(1, Some(parent), 0).unwrap();
    manager.set_window_styles(parent, 0x1000_0000, 0).unwrap();
    manager.set_window_styles(target, 0x1400_0000, 0).unwrap();
    manager.set_window_styles(child, 0x1000_0000, 0).unwrap();
    manager.set_window_styles(sibling, 0x1000_0000, 0).unwrap();
    manager.set_rect(parent, rect(0, 0, 100, 100)).unwrap();
    manager.set_rect(target, rect(10, 10, 90, 90)).unwrap();
    manager.set_rect(child, rect(20, 20, 40, 40)).unwrap();
    manager.set_rect(sibling, rect(60, 0, 100, 100)).unwrap();
    for id in [parent, target, child, sibling] { manager.show(1, id, true).unwrap(); }
    let window_context = manager.dc_lease_context(target, DCX_WINDOW | DCX_CLIPCHILDREN | DCX_CLIPSIBLINGS).unwrap();
    assert!(window_context.visible.rects().iter().any(|r| r.left <= 25 && r.right > 25 && r.top <= 25 && r.bottom > 25));
    assert!(!window_context.visible.rects().iter().any(|r| r.left < 50 && r.right > 50));
    let client_context = manager.dc_lease_context(target, DCX_CLIPCHILDREN).unwrap();
    assert!(!client_context.visible.rects().iter().any(|r| r.left < 30 && r.right > 30 && r.top < 30 && r.bottom > 30));
    assert!(!client_context.visible.rects().iter().any(|r| r.left >= 50));
}
