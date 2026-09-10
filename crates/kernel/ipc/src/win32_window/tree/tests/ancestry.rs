//! Ancestry walks, relationship queries and the descendant test.
use super::*;

pub(super) struct Tree { pub windows: WindowManager }

impl Tree {
    pub(super) fn new() -> Self { Self { windows: WindowManager::new() } }
    pub(super) fn add(&mut self, parent: Option<WindowId>, style: u32) -> WindowId {
        let id = self.windows.create(1, parent, 0).unwrap();
        self.set_style(id, style);
        id
    }
    pub(super) fn set_style(&mut self, id: WindowId, style: u32) {
        self.windows.set_style_bits(id, style, !style).unwrap();
    }
    pub(super) fn set_owner(&mut self, id: WindowId, owner: Option<WindowId>) {
        self.windows.set_popup_owner(id, owner).unwrap();
    }
}

#[test]
fn the_root_walk_ends_at_the_window_with_no_parent() {
    let mut tree = Tree::new();
    let top = tree.add(None, 0);
    let child = tree.add(Some(top), WS_CHILD);
    let grandchild = tree.add(Some(child), WS_CHILD);
    assert_eq!(tree.windows.ancestor(grandchild, GA_ROOT), Some(top));
    assert_eq!(tree.windows.ancestor(top, GA_ROOT), Some(top));
    assert_eq!(tree.windows.ancestor(grandchild, GA_PARENT), Some(child));
    assert_eq!(tree.windows.ancestor(top, GA_PARENT), None);
}

#[test]
fn the_root_owner_walk_follows_a_popups_owner_but_the_root_walk_does_not() {
    let mut tree = Tree::new();
    let owner = tree.add(None, 0);
    let popup = tree.add(None, WS_POPUP);
    tree.set_owner(popup, Some(owner));
    let child = tree.add(Some(popup), WS_CHILD);
    assert_eq!(tree.windows.ancestor(child, GA_ROOT), Some(popup));
    assert_eq!(tree.windows.ancestor(child, GA_ROOTOWNER), Some(owner));
    assert_eq!(tree.windows.ancestor(popup, GA_ROOTOWNER), Some(owner));
}

#[test]
fn an_unknown_relationship_and_an_unknown_window_both_answer_nothing() {
    let mut tree = Tree::new();
    let top = tree.add(None, 0);
    assert_eq!(tree.windows.ancestor(top, 0), None);
    assert_eq!(tree.windows.ancestor(top, 4), None);
}

#[test]
fn the_parent_query_answers_the_parent_of_a_child_and_the_owner_of_a_popup() {
    let mut tree = Tree::new();
    let top = tree.add(None, 0);
    let child = tree.add(Some(top), WS_CHILD);
    let popup = tree.add(None, WS_POPUP);
    tree.set_owner(popup, Some(top));
    assert_eq!(tree.windows.relative_parent(child), Some(top));
    assert_eq!(tree.windows.relative_parent(popup), Some(top));
    assert_eq!(tree.windows.relative_parent(top), None);
}

#[test]
fn the_descendant_test_follows_only_child_windows() {
    let mut tree = Tree::new();
    let top = tree.add(None, 0);
    let child = tree.add(Some(top), WS_CHILD);
    let grandchild = tree.add(Some(child), WS_CHILD);
    assert!(tree.windows.is_child(top, grandchild));
    assert!(!tree.windows.is_child(grandchild, top));
    assert!(!tree.windows.is_child(top, top));
    // A window parented under `top` without WS_CHILD is not inside it.
    let popup = tree.add(Some(top), WS_POPUP);
    assert!(!tree.windows.is_child(top, popup));
}

#[test]
fn sibling_relationships_run_from_the_top_of_the_z_order_downward() {
    let mut tree = Tree::new();
    let parent = tree.add(None, 0);
    let bottom = tree.add(Some(parent), WS_CHILD);
    let middle = tree.add(Some(parent), WS_CHILD);
    let top = tree.add(Some(parent), WS_CHILD);
    assert_eq!(tree.windows.window_relative(parent, GW_CHILD), Some(top));
    assert_eq!(tree.windows.window_relative(middle, GW_HWNDNEXT), Some(bottom));
    assert_eq!(tree.windows.window_relative(top, GW_HWNDPREV), None);
    assert_eq!(tree.windows.window_relative(bottom, GW_HWNDNEXT), None);
    assert_eq!(tree.windows.window_relative(middle, GW_HWNDFIRST), Some(top));
    assert_eq!(tree.windows.window_relative(middle, GW_HWNDLAST), Some(bottom));
    for (endpoint, step, expected) in [
        (GW_HWNDFIRST, GW_HWNDNEXT, [top, middle, bottom]),
        (GW_HWNDLAST, GW_HWNDPREV, [bottom, middle, top]),
    ] {
        let mut current = tree.windows.window_relative(middle, endpoint);
        for sibling in expected {
            assert_eq!(current, Some(sibling));
            current = tree.windows.window_relative(sibling, step);
        }
        assert_eq!(current, None);
    }
}

#[test]
fn the_enabled_popup_query_answers_only_a_visible_enabled_owned_popup() {
    let mut tree = Tree::new();
    let owner = tree.add(None, 0);
    let popup = tree.add(None, WS_POPUP);
    tree.set_owner(popup, Some(owner));
    assert_eq!(tree.windows.window_relative(owner, GW_ENABLEDPOPUP), None);
    tree.windows.show(1, popup, true).unwrap();
    assert_eq!(tree.windows.window_relative(owner, GW_ENABLEDPOPUP), Some(popup));
    tree.set_style(popup, WS_POPUP | WS_VISIBLE | WS_DISABLED);
    assert_eq!(tree.windows.window_relative(owner, GW_ENABLEDPOPUP), None);
}
