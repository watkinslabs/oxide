//! Handle-list building, class/title search and reparenting.
use super::*;

struct Scene { windows: WindowManager }

impl Scene {
    fn new() -> Self { Self { windows: WindowManager::new() } }
    fn add(&mut self, tid: u64, parent: Option<WindowId>, style: u32) -> WindowId {
        let id = self.windows.create(tid, parent, 0).unwrap();
        self.windows.set_style_bits(id, style, 0).unwrap();
        id
    }
}

fn filter(window: Option<WindowId>, children: bool, thread: u64) -> HwndListFilter {
    HwndListFilter { window, children, thread }
}

#[test]
fn the_top_level_list_runs_from_the_top_of_the_z_order_down() {
    let mut scene = Scene::new();
    let first = scene.add(1, None, 0);
    let second = scene.add(1, None, 0);
    scene.add(1, Some(first), WS_CHILD);
    assert_eq!(scene.windows.hwnd_list(filter(None, false, 0)), alloc::vec![second, first]);
}

#[test]
fn a_thread_filter_admits_only_that_threads_windows() {
    let mut scene = Scene::new();
    let mine = scene.add(1, None, 0);
    scene.add(2, None, 0);
    assert_eq!(scene.windows.hwnd_list(filter(None, false, 1)), alloc::vec![mine]);
    assert_eq!(scene.windows.hwnd_list(filter(None, false, 3)), alloc::vec![]);
}

#[test]
fn the_recursive_form_lists_descendants_and_the_sibling_form_starts_at_the_window() {
    let mut scene = Scene::new();
    let top = scene.add(1, None, 0);
    let child = scene.add(1, Some(top), WS_CHILD);
    let grandchild = scene.add(1, Some(child), WS_CHILD);
    assert_eq!(scene.windows.hwnd_list(filter(Some(top), true, 0)), alloc::vec![child, grandchild]);
    let second = scene.add(1, None, 0);
    assert_eq!(scene.windows.hwnd_list(filter(Some(second), false, 0)), alloc::vec![second, top]);
    assert_eq!(scene.windows.hwnd_list(filter(Some(top), false, 0)), alloc::vec![top]);
    assert_eq!(scene.windows.hwnd_list(filter(Some(grandchild), true, 0)), alloc::vec![]);
}

#[test]
fn dialog_control_lookup_from_first_child_reaches_every_identifier() {
    let mut scene = Scene::new();
    let dialog = scene.add(1, None, 0);
    let other = scene.add(1, None, 0);
    let mut controls = alloc::vec![];
    for identifier in [0x470, 0x471, 0x440, 1, 2] {
        let child = scene.add(1, Some(dialog), WS_CHILD);
        scene.windows.set_control_id(child, identifier).unwrap();
        controls.push((identifier, child));
    }
    let unrelated = scene.add(1, Some(other), WS_CHILD);
    scene.windows.set_control_id(unrelated, 0x471).unwrap();
    for (identifier, expected) in controls {
        let first = scene.windows.window_relative(dialog, GW_CHILD).unwrap();
        let found = scene.windows.hwnd_list(filter(Some(first), false, 0)).into_iter()
            .find(|window| scene.windows.control_id(*window) == Some(identifier));
        assert_eq!(found, Some(expected), "dialog control {identifier:#x}");
    }
}

#[test]
fn a_search_matches_a_class_atom_a_title_or_both() {
    let mut scene = Scene::new();
    let first = scene.add(1, None, 0);
    let second = scene.add(1, None, 0);
    scene.windows.set_text(first, &[b'a' as u16]).unwrap();
    scene.windows.set_text(second, &[b'b' as u16]).unwrap();
    assert_eq!(scene.windows.find_child(None, None, 0, None), Some(second));
    assert_eq!(scene.windows.find_child(None, None, 0, Some(&[b'a' as u16])), Some(first));
    assert_eq!(scene.windows.find_child(None, None, 0, Some(&[b'z' as u16])), None);
    assert_eq!(scene.windows.find_child(None, None, 0, Some(&[])), None);
}

#[test]
fn a_search_resumes_after_a_named_sibling_and_refuses_one_of_another_parent() {
    let mut scene = Scene::new();
    let first = scene.add(1, None, 0);
    let second = scene.add(1, None, 0);
    let child = scene.add(1, Some(first), WS_CHILD);
    assert_eq!(scene.windows.find_child(None, Some(second), 0, None), Some(first));
    assert_eq!(scene.windows.find_child(None, Some(first), 0, None), None);
    assert_eq!(scene.windows.find_child(None, Some(child), 0, None), None);
}

#[test]
fn reparenting_answers_the_old_parent_and_places_the_window_on_top_of_its_new_siblings() {
    let mut scene = Scene::new();
    let first = scene.add(1, None, 0);
    let second = scene.add(1, None, 0);
    let child = scene.add(1, Some(first), WS_CHILD);
    assert_eq!(scene.windows.set_parent(1, child, Some(second)), Ok(Some(first)));
    assert_eq!(scene.windows.get(child).unwrap().parent, Some(second));
    assert_eq!(scene.windows.hwnd_list(filter(Some(second), true, 0)), alloc::vec![child]);
    assert_eq!(scene.windows.set_parent(1, child, Some(second)), Ok(Some(second)));
}

#[test]
fn a_window_cannot_become_a_descendant_of_itself_and_only_its_own_thread_moves_it() {
    let mut scene = Scene::new();
    let top = scene.add(1, None, 0);
    let child = scene.add(1, Some(top), WS_CHILD);
    let grandchild = scene.add(1, Some(child), WS_CHILD);
    assert_eq!(scene.windows.set_parent(1, child, Some(grandchild)), Err(WindowError::InvalidParent));
    assert_eq!(scene.windows.set_parent(1, child, Some(child)), Err(WindowError::InvalidParent));
    assert_eq!(scene.windows.set_parent(2, child, None), Err(WindowError::WrongThread));
    assert_eq!(scene.windows.set_parent(1, child, None), Ok(Some(top)));
}
