//! Point-to-window search in client and screen coordinates.
use super::*;
use crate::win32_window::LayeredAttributes;

struct Scene { windows: WindowManager }

impl Scene {
    fn new() -> Self { Self { windows: WindowManager::new() } }
    fn add(&mut self, parent: Option<WindowId>, style: u32, rect: (i32, i32, i32, i32)) -> WindowId {
        let id = self.windows.create(1, parent, 0).unwrap();
        self.windows.set_style_bits(id, style | WS_VISIBLE, 0).unwrap();
        self.windows.set_rect(id, WindowRect { left: rect.0, top: rect.1, right: rect.2, bottom: rect.3 }).unwrap();
        id
    }
}

#[test]
fn a_rectangle_test_excludes_its_right_and_bottom_edges() {
    let rect = WindowRect { left: 0, top: 0, right: 10, bottom: 10 };
    assert!(point_in_rect(rect, 0, 0));
    assert!(point_in_rect(rect, 9, 9));
    assert!(!point_in_rect(rect, 10, 9));
    assert!(!point_in_rect(rect, 9, 10));
    assert!(!point_in_rect(rect, -1, 0));
}

#[test]
fn a_point_outside_the_parents_client_area_answers_nothing() {
    let mut scene = Scene::new();
    let parent = scene.add(None, 0, (0, 0, 100, 100));
    assert_eq!(scene.windows.child_from_point(parent, 200, 200, CWP_ALL), None);
    assert_eq!(scene.windows.child_from_point(parent, 50, 50, CWP_ALL), Some(parent));
}

#[test]
fn the_topmost_child_covering_the_point_wins_and_the_filters_skip_the_rest() {
    let mut scene = Scene::new();
    let parent = scene.add(None, 0, (0, 0, 100, 100));
    let lower = scene.add(Some(parent), WS_CHILD, (0, 0, 60, 60));
    let upper = scene.add(Some(parent), WS_CHILD, (0, 0, 60, 60));
    assert_eq!(scene.windows.child_from_point(parent, 10, 10, CWP_ALL), Some(upper));

    scene.windows.set_style_bits(upper, 0, WS_VISIBLE).unwrap();
    assert_eq!(scene.windows.child_from_point(parent, 10, 10, CWP_SKIPINVISIBLE), Some(lower));
    assert_eq!(scene.windows.child_from_point(parent, 10, 10, CWP_ALL), Some(upper));

    scene.windows.set_style_bits(upper, WS_VISIBLE | WS_DISABLED, 0).unwrap();
    assert_eq!(scene.windows.child_from_point(parent, 10, 10, CWP_SKIPDISABLED), Some(lower));

    scene.windows.set_style_bits(upper, 0, WS_DISABLED).unwrap();
    scene.windows.set_ex_style_bits(upper, WS_EX_TRANSPARENT, 0).unwrap();
    assert_eq!(scene.windows.child_from_point(parent, 10, 10, CWP_SKIPTRANSPARENT), Some(lower));
}

#[test]
fn a_child_rectangle_is_read_in_its_parents_coordinates() {
    let mut scene = Scene::new();
    let parent = scene.add(None, 0, (100, 100, 300, 300));
    let child = scene.add(Some(parent), WS_CHILD, (50, 50, 100, 100));
    assert_eq!(scene.windows.rect_in_parent(child), Some(WindowRect { left: 50, top: 50, right: 100, bottom: 100 }));
    assert_eq!(scene.windows.child_from_point(parent, 60, 60, CWP_ALL), Some(child));
    assert_eq!(scene.windows.child_from_point(parent, 10, 10, CWP_ALL), Some(parent));
}

#[test]
fn the_screen_search_answers_the_innermost_window_under_the_point() {
    let mut scene = Scene::new();
    let top = scene.add(None, 0, (0, 0, 200, 200));
    let child = scene.add(Some(top), WS_CHILD, (10, 10, 100, 100));
    let grandchild = scene.add(Some(child), WS_CHILD, (20, 20, 50, 50));
    assert_eq!(scene.windows.window_from_point(None, 30, 30), (Some(grandchild), HTCLIENT));
    assert_eq!(scene.windows.window_from_point(None, 60, 60), (Some(child), HTCLIENT));
    assert_eq!(scene.windows.window_from_point(None, 150, 150), (Some(top), HTCLIENT));
    assert_eq!(scene.windows.window_from_point(None, 500, 500), (None, HTNOWHERE));
}

#[test]
fn a_hidden_window_and_a_layered_transparent_one_are_invisible_to_the_search() {
    let mut scene = Scene::new();
    let below = scene.add(None, 0, (0, 0, 200, 200));
    let above = scene.add(None, 0, (0, 0, 200, 200));
    assert_eq!(scene.windows.window_from_point(None, 10, 10).0, Some(above));
    scene.windows.set_style_bits(above, 0, WS_VISIBLE).unwrap();
    assert_eq!(scene.windows.window_from_point(None, 10, 10).0, Some(below));
    scene.windows.set_style_bits(above, WS_VISIBLE, 0).unwrap();
    scene.windows.set_layered_attributes(above, LayeredAttributes::default()).unwrap();
    scene.windows.set_ex_style_bits(above, WS_EX_TRANSPARENT, 0).unwrap();
    assert_eq!(scene.windows.window_from_point(None, 10, 10).0, Some(below));
}

#[test]
fn a_disabled_child_is_skipped_but_a_disabled_top_level_window_ends_the_search() {
    let mut scene = Scene::new();
    let top = scene.add(None, 0, (0, 0, 200, 200));
    let child = scene.add(Some(top), WS_CHILD, (0, 0, 100, 100));
    scene.windows.set_style_bits(child, WS_DISABLED, 0).unwrap();
    assert_eq!(scene.windows.window_from_point(None, 10, 10), (Some(top), HTCLIENT));
    scene.windows.set_style_bits(top, WS_DISABLED, 0).unwrap();
    assert_eq!(scene.windows.window_from_point(None, 10, 10), (Some(top), HTERROR));
}

#[test]
fn a_minimized_window_hides_its_children_from_the_search() {
    let mut scene = Scene::new();
    let top = scene.add(None, 0, (0, 0, 200, 200));
    let child = scene.add(Some(top), WS_CHILD, (0, 0, 100, 100));
    assert_eq!(scene.windows.window_from_point(None, 10, 10).0, Some(child));
    scene.windows.set_style_bits(top, WS_MINIMIZE, 0).unwrap();
    assert_eq!(scene.windows.window_from_point(None, 10, 10).0, Some(top));
}

#[test]
fn displaced_dialog_candidates_use_each_ancestors_client_origin() {
    let mut scene = Scene::new();
    let dialog = scene.add(None, 0, (280, 200, 740, 540));
    scene.windows.set_client_rect(dialog, WindowRect { left: 284, top: 224, right: 736, bottom: 536 }).unwrap();
    let panel = scene.add(Some(dialog), WS_CHILD, (20, 30, 300, 230));
    scene.windows.set_client_rect(panel, WindowRect { left: 23, top: 40, right: 297, bottom: 227 }).unwrap();
    let button = scene.add(Some(panel), WS_CHILD, (30, 40, 130, 68));
    assert_eq!(scene.windows.windows_from_point(None, 350, 315), [button, panel, dialog]);
    assert_eq!(scene.windows.windows_from_point(Some(dialog), 350, 315), [button, panel]);
    assert_eq!(scene.windows.windows_from_point(None, 437, 315), [panel, dialog]);
    assert_eq!(scene.windows.windows_from_point(None, 350, 332), [panel, dialog]);
    assert_eq!(scene.windows.child_from_point(panel, 40, 50, CWP_ALL), Some(button));
}

#[test]
fn children_cannot_receive_points_in_the_parents_nonclient_band() {
    let mut scene = Scene::new();
    let dialog = scene.add(None, 0, (200, 100, 500, 400));
    scene.windows.set_client_rect(dialog, WindowRect { left: 204, top: 128, right: 496, bottom: 396 }).unwrap();
    scene.add(Some(dialog), WS_CHILD, (-20, -40, 100, 100));
    assert_eq!(scene.windows.windows_from_point(None, 220, 110), [dialog]);
}

#[test]
fn window_region_holes_exclude_the_window_and_its_descendants() {
    let mut scene = Scene::new();
    let lower = scene.add(None, 0, (200, 100, 400, 300));
    let upper = scene.add(None, 0, (200, 100, 400, 300));
    let child = scene.add(Some(upper), WS_CHILD, (0, 0, 200, 200));
    let region = [WindowRect { left: 0, top: 0, right: 20, bottom: 200 },
        WindowRect { left: 180, top: 0, right: 200, bottom: 200 }];
    scene.windows.set_window_region(upper, Some(&region)).unwrap();
    assert_eq!(scene.windows.windows_from_point(None, 210, 150), [child, upper, lower]);
    assert_eq!(scene.windows.windows_from_point(None, 300, 150), [lower]);
    scene.windows.set_window_region(upper, Some(&[])).unwrap();
    assert_eq!(scene.windows.windows_from_point(None, 210, 150), [lower]);
    scene.windows.set_window_region(upper, None).unwrap();
    assert_eq!(scene.windows.windows_from_point(None, 300, 150), [child, upper, lower]);
}
