//! Painting the items of one popup-menu window: the class background is only
//! the ground the plan is drawn over.
use super::entry::with_entry;
use super::popup_window::{layout_of, POPUP_MENU_EXTRA_OFFSET};
use ipc::win32_menu::MenuId;
use ipc::win32_window::WindowId;

/// Draw the menu one popup window carries into the device context of the
/// paint that is still open on it. A window of any other class draws nothing.
/// # C: O(N_items + pixels)
pub(crate) fn paint_popup_menu_window(hwnd: u64, dc: u64) {
    let Some(window) = u32::try_from(hwnd).ok().and_then(WindowId::from_raw) else { return; };
    let Some(menu) = with_entry(|entry| {
        let name = entry.state.class_name(window)?;
        if name != super::popup_window::POPUP_MENU_CLASS { return None; }
        let raw = entry.state.get_window_long_ptr(window, POPUP_MENU_EXTRA_OFFSET).ok()?;
        MenuId::from_raw(u32::try_from(raw).ok()?)
    }).flatten() else { return; };
    let Some(layout) = layout_of(menu.raw()) else { return; };
    let Some(plan) = with_entry(|entry| entry.menus.popup_draw_plan(menu, &layout).ok()).flatten() else { return; };
    crate::nt_window::menu_draw::run(dc, menu, &plan, (0, 0));
}
