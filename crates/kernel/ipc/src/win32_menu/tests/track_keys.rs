use crate::win32_menu::popup::TPM_NONOTIFY;
use crate::win32_menu::track::{TrackEffect, WM_COMMAND};
use crate::win32_menu::track_loop::{LoopStep, RetrievedMessage, TrackLoop, VK_ESCAPE, VK_LEFT, VK_RETURN, VK_RIGHT, WM_KEYDOWN};
use crate::win32_menu::{MenuId, MenuItem, MenuManager};
use alloc::vec;
use alloc::vec::Vec;

const OWNER: u32 = 7;
const FILE_NEW: u32 = 100;

fn text(value: &str) -> Vec<u16> { value.encode_utf16().collect() }

/// A bar carrying File and Edit, each with a popup of its own.
fn bar_chain() -> (MenuManager, u32, u32, u32) {
    let mut menus = MenuManager::new();
    let bar = menus.create().unwrap();
    let file = menus.create_popup().unwrap();
    let edit = menus.create_popup().unwrap();
    menus.insert(bar, 0, MenuItem { id: 0, state: 0, text: text("&File"), submenu: Some(file.raw()) }).unwrap();
    menus.insert(bar, 1, MenuItem { id: 0, state: 0, text: text("&Edit"), submenu: Some(edit.raw()) }).unwrap();
    menus.insert(file, 0, MenuItem { id: FILE_NEW, state: 0, text: text("&New"), submenu: None }).unwrap();
    menus.insert(edit, 0, MenuItem { id: 200, state: 0, text: text("&Copy"), submenu: None }).unwrap();
    (menus, bar.raw(), file.raw(), edit.raw())
}

/// A bar-tracking loop already past its entry notifications.
fn tracking(bar: u32) -> TrackLoop { TrackLoop::new(TPM_NONOTIFY, OWNER, bar, (0, 0)) }

fn focus(menus: &mut MenuManager, menu: u32, position: u32) {
    menus.set_focused_item(MenuId::from_raw(menu).unwrap(), position).unwrap();
}

fn focused(menus: &MenuManager, menu: u32) -> u32 { menus.focused_item(MenuId::from_raw(menu).unwrap()) }

/// Feed one key and collect every step it queues.
fn key(state: &mut TrackLoop, menus: &mut MenuManager, vk: u32) -> Vec<LoopStep> {
    state.message(menus, RetrievedMessage { hwnd: OWNER as u64, message: WM_KEYDOWN, wparam: vk as u64, lparam: 0 }, None);
    let mut steps = Vec::new();
    loop {
        let step = state.next(menus);
        let done = matches!(step, LoopStep::NextMessage | LoopStep::Done(_));
        steps.push(step);
        if done { return steps; }
    }
}

fn effects(steps: &[LoopStep]) -> Vec<TrackEffect> {
    steps.iter().filter_map(|step| match step { LoopStep::Effect(effect) => Some(effect.clone()), _ => None }).collect()
}

#[test]
fn return_on_a_bar_item_opens_its_popup() {
    let (mut menus, bar, _, _) = bar_chain();
    let mut state = tracking(bar);
    state.set_current(bar, 0);
    focus(&mut menus, bar, 0);
    let steps = key(&mut state, &mut menus, VK_RETURN);
    assert!(effects(&steps).contains(&TrackEffect::ShowSubPopup { menu: bar, select_first: true }));
    // Opening a popup is not the end of tracking.
    assert_eq!(*steps.last().unwrap(), LoopStep::NextMessage);
}

#[test]
fn return_on_a_popup_item_executes_it() {
    let (mut menus, bar, file, _) = bar_chain();
    let mut state = tracking(bar);
    state.set_current(file, 9);
    focus(&mut menus, file, 0);
    let steps = key(&mut state, &mut menus, VK_RETURN);
    assert!(effects(&steps).contains(&TrackEffect::Post { message: WM_COMMAND, wparam: FILE_NEW as u64, lparam: 0 }));
    assert!(matches!(steps.last().unwrap(), LoopStep::Done(_)));
}

#[test]
fn right_on_the_bar_with_a_popup_open_closes_it_moves_and_opens_the_next() {
    let (mut menus, bar, file, _) = bar_chain();
    let mut state = tracking(bar);
    state.set_current(file, 9);
    focus(&mut menus, bar, 0);
    let steps = key(&mut state, &mut menus, VK_RIGHT);
    assert_eq!(effects(&steps), vec![TrackEffect::HideSubPopups { menu: bar },
        TrackEffect::Repaint { menu: bar }, TrackEffect::ShowSubPopup { menu: bar, select_first: true }]);
    assert_eq!(focused(&menus, bar), 1);
    assert_eq!(state.current(), bar);
}

#[test]
fn right_on_the_bar_with_nothing_open_only_moves_the_highlight() {
    let (mut menus, bar, _, _) = bar_chain();
    let mut state = tracking(bar);
    state.set_current(bar, 0);
    focus(&mut menus, bar, 0);
    let steps = key(&mut state, &mut menus, VK_RIGHT);
    assert_eq!(effects(&steps), vec![TrackEffect::Repaint { menu: bar }]);
    assert_eq!(focused(&menus, bar), 1);
}

#[test]
fn left_on_the_bar_closes_the_popup_and_opens_the_item_before_it() {
    let (mut menus, bar, _, edit) = bar_chain();
    let mut state = tracking(bar);
    state.set_current(edit, 9);
    focus(&mut menus, bar, 1);
    let steps = key(&mut state, &mut menus, VK_LEFT);
    assert_eq!(effects(&steps), vec![TrackEffect::HideSubPopups { menu: bar },
        TrackEffect::Repaint { menu: bar }, TrackEffect::ShowSubPopup { menu: bar, select_first: true }]);
    assert_eq!(focused(&menus, bar), 0);
}

#[test]
fn right_inside_a_popup_opens_the_submenu_of_the_highlighted_item() {
    let (mut menus, bar, file, _) = bar_chain();
    let deep = menus.create_popup().unwrap();
    menus.insert(deep, 0, MenuItem { id: 300, state: 0, text: text("&Deep"), submenu: None }).unwrap();
    menus.set_item(MenuId::from_raw(file).unwrap(), 0, None, None, None, Some(Some(deep.raw()))).unwrap();
    let mut state = tracking(bar);
    state.set_current(file, 9);
    focus(&mut menus, file, 0);
    let steps = key(&mut state, &mut menus, VK_RIGHT);
    assert_eq!(effects(&steps), vec![TrackEffect::ShowSubPopup { menu: file, select_first: true }]);
}

#[test]
fn escape_closes_the_open_popup_and_keeps_tracking() {
    let (mut menus, bar, file, _) = bar_chain();
    let mut state = tracking(bar);
    state.set_current(file, 9);
    let steps = key(&mut state, &mut menus, VK_ESCAPE);
    assert_eq!(effects(&steps), vec![TrackEffect::HideSubPopups { menu: bar }]);
    assert_eq!(state.current(), bar);
    assert_eq!(*steps.last().unwrap(), LoopStep::NextMessage);
}

#[test]
fn escape_on_the_bar_itself_ends_tracking() {
    let (mut menus, bar, _, _) = bar_chain();
    let mut state = tracking(bar);
    state.set_current(bar, 0);
    let steps = key(&mut state, &mut menus, VK_ESCAPE);
    assert!(matches!(steps.last().unwrap(), LoopStep::Done(_)));
}
