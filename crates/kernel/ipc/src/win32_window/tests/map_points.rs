//! Offsets between window client spaces, the point translation built on them,
//! and the right-to-left mirror both carry.
use super::*;
use crate::win32_window::WindowRect;
use crate::win32_window::styles::{WS_CHILD, WS_EX_LAYOUTRTL};

struct Tree { windows: WindowManager }

impl Tree {
    fn new() -> Self { Self { windows: WindowManager::new() } }
    /// A window whose window rectangle and client rectangle are both placed;
    /// the client inset is what a nonclient frame would leave.
    fn add(&mut self, parent: Option<WindowId>, style: u32, rect: (i32, i32, i32, i32), inset: (i32, i32)) -> WindowId {
        let id = self.windows.create(1, parent, 0).unwrap();
        self.windows.set_style_bits(id, style, !style).unwrap();
        let window = WindowRect { left: rect.0, top: rect.1, right: rect.2, bottom: rect.3 };
        self.windows.set_rect(id, window).unwrap();
        self.windows.set_client_rect(id, WindowRect { left: window.left + inset.0, top: window.top + inset.1,
            right: window.right, bottom: window.bottom }).unwrap();
        id
    }
    fn set_ex_style(&mut self, id: WindowId, ex: u32) {
        let (style, _) = self.windows.window_styles(id).unwrap();
        self.windows.set_window_styles(id, style, ex).unwrap();
    }
}

#[test]
fn a_top_level_windows_client_origin_is_its_client_rectangle_origin() {
    let mut tree = Tree::new();
    let top = tree.add(None, 0, (100, 50, 400, 300), (4, 24));
    assert_eq!(tree.windows.client_origin_screen(top), Some((104, 74, false)));
}

#[test]
fn a_childs_client_origin_accumulates_every_ancestor_client_origin() {
    let mut tree = Tree::new();
    let top = tree.add(None, 0, (100, 50, 400, 300), (4, 24));
    // A child's own rectangle is parent-client relative.
    let child = tree.add(Some(top), WS_CHILD, (10, 20, 110, 60), (0, 0));
    assert_eq!(tree.windows.client_origin_screen(child), Some((114, 94, false)));
    let grandchild = tree.add(Some(child), WS_CHILD, (5, 5, 50, 30), (0, 0));
    assert_eq!(tree.windows.client_origin_screen(grandchild), Some((119, 99, false)));
}

#[test]
fn client_to_screen_and_back_are_inverses() {
    let mut tree = Tree::new();
    let top = tree.add(None, 0, (100, 50, 400, 300), (4, 24));
    let child = tree.add(Some(top), WS_CHILD, (10, 20, 110, 60), (0, 0));
    let mut point = [(7, 9)];
    tree.windows.map_points(Some(child), None, &mut point).unwrap();
    assert_eq!(point, [(121, 103)]);
    tree.windows.map_points(None, Some(child), &mut point).unwrap();
    assert_eq!(point, [(7, 9)]);
}

#[test]
fn mapping_between_two_children_of_one_parent_is_their_origin_difference() {
    let mut tree = Tree::new();
    let top = tree.add(None, 0, (100, 50, 400, 300), (4, 24));
    let left = tree.add(Some(top), WS_CHILD, (10, 20, 110, 60), (0, 0));
    let right = tree.add(Some(top), WS_CHILD, (200, 25, 300, 65), (0, 0));
    let mut point = [(0, 0)];
    tree.windows.map_points(Some(left), Some(right), &mut point).unwrap();
    assert_eq!(point, [(10 - 200, 20 - 25)]);
}

#[test]
fn the_result_packs_the_two_offsets_low_words_with_y_above_x() {
    let mut tree = Tree::new();
    let top = tree.add(None, 0, (100, 50, 400, 300), (4, 24));
    let child = tree.add(Some(top), WS_CHILD, (10, 20, 110, 60), (0, 0));
    let mut point = [(0, 0)];
    let packed = tree.windows.map_points(Some(child), None, &mut point).unwrap();
    assert_eq!(packed, ((94u32 & 0xffff) << 16) | (114u32 & 0xffff));
    assert_eq!(pack_offset(-1, -2), 0xfffe_ffff);
}

#[test]
fn a_right_to_left_source_mirrors_the_x_axis_about_its_client_width() {
    let mut tree = Tree::new();
    let top = tree.add(None, 0, (0, 0, 200, 100), (0, 0));
    tree.set_ex_style(top, WS_EX_LAYOUTRTL);
    let offset = tree.windows.windows_offset(Some(top), None).unwrap();
    assert!(offset.mirrored);
    // The client origin term carries the client width, and the whole offset
    // is negated because the source mirrors.
    assert_eq!(offset.dx, -200);
    let mut point = [(30, 40)];
    tree.windows.map_points(Some(top), None, &mut point).unwrap();
    assert_eq!(point, [(170, 40)]);
}

#[test]
fn two_right_to_left_windows_do_not_mirror_relative_to_each_other() {
    let mut tree = Tree::new();
    let top = tree.add(None, 0, (0, 0, 200, 100), (0, 0));
    let child = tree.add(Some(top), WS_CHILD, (0, 0, 200, 100), (0, 0));
    tree.set_ex_style(top, WS_EX_LAYOUTRTL);
    tree.set_ex_style(child, WS_EX_LAYOUTRTL);
    assert!(!tree.windows.windows_offset(Some(child), Some(top)).unwrap().mirrored);
}

#[test]
fn a_mirrored_mapping_of_exactly_two_points_swaps_their_x_coordinates() {
    let mut tree = Tree::new();
    let top = tree.add(None, 0, (0, 0, 200, 100), (0, 0));
    tree.set_ex_style(top, WS_EX_LAYOUTRTL);
    let mut corners = [(10, 10), (60, 40)];
    tree.windows.map_points(Some(top), None, &mut corners).unwrap();
    assert_eq!(corners, [(140, 10), (190, 40)]);
    // Three points are not a rectangle, so no swap runs.
    let mut points = [(10, 0), (60, 0), (70, 0)];
    tree.windows.map_points(Some(top), None, &mut points).unwrap();
    assert_eq!(points, [(190, 0), (140, 0), (130, 0)]);
}

#[test]
fn a_window_that_does_not_exist_answers_nothing() {
    let tree = Tree::new();
    let missing = WindowId::from_raw(0x4242).unwrap();
    assert_eq!(tree.windows.client_origin_screen(missing), None);
    assert_eq!(tree.windows.windows_offset(Some(missing), None), None);
    let mut point = [(0, 0)];
    assert_eq!(tree.windows.map_points(Some(missing), None, &mut point), None);
    // The desktop on both sides is the identity mapping.
    assert_eq!(tree.windows.windows_offset(None, None), Some(WindowsOffset::default()));
}
