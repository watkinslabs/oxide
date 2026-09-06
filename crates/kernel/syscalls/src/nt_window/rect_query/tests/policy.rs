use super::*;

#[test]
fn committed_client_origin_is_not_added_to_window_origin_twice() {
    use ipc::win32_window::{WindowManager, WindowRect, WindowPosition};
    const NOACTIVATE: u32 = 0x10;
    let mut state = WindowManager::new();
    let parent = state.create(7, None, 0).unwrap();
    let child = state.create(7, Some(parent), 0).unwrap();
    state.apply_position(7, WindowPosition { window: parent,
        rect: WindowRect { left: 100, top: 40, right: 500, bottom: 340 },
        client: Some(WindowRect { left: 105, top: 50, right: 495, bottom: 335 }),
        order: None, visible: None, flags: NOACTIVATE, notify_geometry: false }).unwrap();
    state.set_rect(child, WindowRect { left: 12, top: 18, right: 212, bottom: 118 }).unwrap();
    assert_eq!(query_state(&state, child, RectKind::Window, 96, 96),
        Some(WindowRect { left: 117, top: 68, right: 317, bottom: 168 }));
}

#[test]
fn child_window_rect_walks_parent_window_and_client_origins() {
    let mut state = ipc::win32_window::WindowManager::new();
    let parent = state.create(7, None, 0).unwrap();
    let child = state.create(7, Some(parent), 0).unwrap();
    state.set_rect(parent, ipc::win32_window::WindowRect { left: 100, top: 40, right: 500, bottom: 340 }).unwrap();
    state.set_rect(child, ipc::win32_window::WindowRect { left: 12, top: 18, right: 212, bottom: 118 }).unwrap();
    assert_eq!(query_state(&state, child, RectKind::Window, 96, 96),
        Some(ipc::win32_window::WindowRect { left: 112, top: 58, right: 312, bottom: 158 }));
}

#[test]
fn client_is_local_and_dpi_maps_with_wine_muldiv_rounding() {
    let mut state = ipc::win32_window::WindowManager::new();
    let window = state.create(7, None, 0).unwrap();
    state.set_rect(window, ipc::win32_window::WindowRect { left: 100, top: 40, right: 300, bottom: 140 }).unwrap();
    assert_eq!(query_state(&state, window, RectKind::Window, 192, 96),
        Some(ipc::win32_window::WindowRect { left: 200, top: 80, right: 600, bottom: 280 }));
    assert_eq!(query_state(&state, window, RectKind::Client, 96, 96),
        Some(ipc::win32_window::WindowRect { left: 0, top: 0, right: 200, bottom: 100 }));
}

#[test]
fn zero_requested_dpi_preserves_canonical_scale() {
    let rect = ipc::win32_window::WindowRect { left: 3, top: 4, right: 13, bottom: 24 };
    assert_eq!(map_rect(rect, 120, 0), rect);
}
