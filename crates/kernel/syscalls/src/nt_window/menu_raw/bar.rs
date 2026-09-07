//! The menu bar of one window: the height it claims from the client area, the
//! drawing of the bar into the window's nonclient band, and the two entries
//! that carry a press or an Alt/F10 key into the tracking loop.
use super::entry::with_entry;
use super::popup_window::work_area;
use super::track_live::track_bar_menu;
use ipc::win32_menu::{MenuId, MenuRect};
use ipc::win32_window::nonclient_menu::{MenuCommand, HTSYSMENU};
use ipc::win32_window::WindowId;

/// Tracking a bar starts left-aligned on the left button, with the button
/// already down when a press opened it.
const TPM_LEFTALIGN_LEFTBUTTON: u32 = 0;
use ipc::win32_menu::popup::{TF_ENDMENU, TPM_BUTTONDOWN};

/// Cell metrics one bar is measured and drawn with: the profile's menu font,
/// which the drawing selects into its device context. # C: O(1)
fn metrics() -> (i32, i32, i32) {
    let metrics = ipc::win32_gdi::menu_bar_metrics();
    (metrics.char_width, metrics.char_height, metrics.bar_height)
}

/// The menu one window shows on its bar, and the window's own rectangle.
/// # C: O(N_windows)
#[inline(never)]
fn bar_of(hwnd: u64) -> Option<(MenuId, MenuRect)> {
    let window = WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
    with_entry(|entry| {
        let record = entry.state.get(window)?;
        let style = record.style;
        let ex_style = record.ex_style;
        let menu = entry.state.menu(window);
        if !ipc::win32_window::nonclient_menu::window_has_menu_bar(style, ex_style, menu) { return None; }
        let menu = MenuId::from_raw(menu?)?;
        let rect = entry.state.rect(window)?;
        Some((menu, MenuRect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }))
    }).flatten()
}

/// The height one window's menu bar takes off the top of its client area, for
/// the nonclient size calculation. Zero when the window shows no bar.
/// # C: O(N_items)
#[inline(never)]
pub(crate) fn height_for_current(hwnd: u64, width: i32) -> i32 {
    let Some((menu, rect)) = bar_of(hwnd) else { return 0; };
    let (char_width, char_height, bar_height) = metrics();
    let origin = MenuRect { left: 0, top: 0, right: width, bottom: rect.bottom - rect.top };
    with_entry(|entry| entry.menus.bar_rect(menu, origin, char_width, char_height, bar_height).map(|bar| bar.bottom - bar.top).unwrap_or(0)).unwrap_or(0)
}

/// Draw one window's menu bar into `dc`, whose origin is `origin` in the
/// window's own coordinates. Reports the height the bar drew and the redirect
/// status of the run that entered the font backend. # C: O(N_items + pixels)
#[inline(never)]
pub(crate) fn draw_into(hwnd: u64, dc: u64, origin: MenuRect) -> (i32, Option<u64>) {
    let Some((menu, _)) = bar_of(hwnd) else { return (0, None); };
    let (char_width, char_height, bar_height) = metrics();
    let Some(plan) = with_entry(|entry| entry.menus.bar_draw_plan(menu, origin, char_width, char_height, bar_height).ok()).flatten() else { return (0, None); };
    let Some(bar) = with_entry(|entry| entry.menus.bar_rect(menu, origin, char_width, char_height, bar_height).ok()).flatten() else { return (0, None); };
    let launched = crate::nt_window::menu_draw::run(dc, menu, &plan, (0, 0));
    (bar.bottom - bar.top, launched)
}

/// Paint the bar of one window into its own window-wide device context, the
/// way the nonclient painter draws it after the frame and caption. `Some` is
/// the redirect status the nonclient message must return, so the font backend
/// enters its callback with the payload the launch placed.
/// # C: O(N_items + pixels)
#[inline(never)]
pub(crate) fn nc_paint_for_current(hwnd: u64) -> Option<u64> {
    let (_, rect) = bar_of(hwnd)?;
    let window = u32::try_from(hwnd).ok()?;
    let (width, height) = (rect.right - rect.left, rect.bottom - rect.top);
    if width <= 0 || height <= 0 { return None; }
    let dc = crate::nt_gdi::acquire_window_dc_for_current(window, width, height);
    let handle = u32::try_from(dc).ok()?;
    if handle == 0 { return None; }
    let origin = MenuRect { left: 0, top: 0, right: width, bottom: height };
    let (_, launched) = draw_into(hwnd, dc, origin);
    // Item text does not rasterize inside this pass: it enters the font
    // backend after the syscall returns. Releasing the device context here
    // would put the band on the screen before its labels reached it, and take
    // the surface the pending upload names out from under it.
    crate::nt_text_order::end_paint_for_current(hwnd, dc, release_band_dc);
    launched
}

/// Release the window-wide device context the bar drew into, once every text
/// run the same pass issued has rasterized into it. # C: O(pixels)
fn release_band_dc(hwnd: u64, dc: u64) {
    let (Ok(window), Ok(handle)) = (u32::try_from(hwnd), u32::try_from(dc)) else { return; };
    let _ = crate::nt_gdi::release_window_dc_for_current(window, handle);
}

/// One stage of the entry into menu tracking. The route is the
/// non-allocating one: a stage that reports while the GUI owner is locked
/// must not enter a console sink that allocates. # C: O(1)
pub(crate) fn trace(stage: &'static [u8]) {
    klog::write_primary_raw(b"[MENU-ENTRY] ");
    klog::write_primary_raw(stage);
    klog::write_primary_raw(b"\n");
}

/// Enter menu tracking for one window's bar. A press names the point it began
/// at; a key names no point and lets the loop select the first item.
/// # C: O(N_messages * N_items); # Sleeps: yes
#[inline(never)]
pub(crate) fn track_for_current(hwnd: u64, command: MenuCommand, point: (i32, i32)) -> Option<u64> {
    trace(b"track-entered");
    let menu = match command {
        MenuCommand::Mouse { hit } if hit == HTSYSMENU => system_menu_of(hwnd),
        MenuCommand::Mouse { .. } => bar_of(hwnd).map(|(menu, _)| menu.raw()),
        MenuCommand::Keyboard { character } => keyboard_menu(hwnd, character),
    };
    let Some(menu) = menu else { trace(b"no-menu"); return None; };
    trace(b"menu-resolved");
    let mut flags = TPM_LEFTALIGN_LEFTBUTTON;
    if matches!(command, MenuCommand::Mouse { .. }) { flags |= TPM_BUTTONDOWN; }
    if let MenuCommand::Keyboard { character } = command {
        match keyboard_item(menu, character) {
            // A character naming no item ends tracking as soon as it begins.
            KeyboardEntry::NoItem => flags |= TF_ENDMENU,
            // The named item opens as though it had been chosen.
            KeyboardEntry::Named(position) => { select(menu, position); post_open(hwnd); }
            KeyboardEntry::First(position) => select(menu, position),
        }
    }
    let already = with_entry(|entry| entry.menu_tracking.is_some()).unwrap_or(true);
    if already { trace(b"already-tracking"); return None; }
    let _ = with_entry(|entry| entry.menu_tracking = Some(super::session::MenuCancel { owner: hwnd, exit: false }));
    trace(b"claimed");
    let _ = work_area();
    trace(b"work-area");
    // The loop suspends in every window procedure it enters and reports from
    // the callback return that finishes it.
    Some(track_bar_menu(hwnd, menu, flags, point))
}

/// What a keyboard-opened bar selects before its loop begins.
enum KeyboardEntry { NoItem, Named(u32), First(u32) }

/// The item a typed character names, or the first item a bare Alt or F10
/// selects. # C: O(N_items)
#[inline(never)]
fn keyboard_item(menu: u32, character: u32) -> KeyboardEntry {
    let Some(id) = MenuId::from_raw(menu) else { return KeyboardEntry::NoItem; };
    if character != 0 {
        let named = with_entry(|entry| entry.menus.item_by_key(id, character as u16)).flatten();
        return named.map_or(KeyboardEntry::NoItem, KeyboardEntry::Named);
    }
    let first = with_entry(|entry| {
        let count = entry.menus.count(id).unwrap_or(0);
        (0..count).find(|position| entry.menus.item(id, *position as u32, ipc::win32_menu::MF_BYPOSITION)
            .is_ok_and(|item| item.state & ipc::win32_menu::MF_SEPARATOR == 0))
    }).flatten();
    first.map_or(KeyboardEntry::NoItem, |position| KeyboardEntry::First(position as u32))
}

/// Highlight one bar item before tracking begins. # C: O(N_items)
fn select(menu: u32, position: u32) {
    let Some(id) = MenuId::from_raw(menu) else { return; };
    with_entry(|entry| {
        let _ = entry.menus.set_focused_item(id, position);
        let _ = entry.menus.hilite(id, position as usize, true);
    });
}

/// Ask the loop to open the selected item, the way the reference posts the
/// key that chooses it. # C: O(1)
fn post_open(hwnd: u64) {
    const WM_KEYDOWN: u64 = 0x0100;
    const VK_RETURN: u64 = 0x0d;
    let _ = crate::nt_window::dispatch(syscall::nt::NtCall { service: syscall::nt::NtService::PostMessage,
        args: syscall::SyscallArgs { a0: hwnd, a1: WM_KEYDOWN, a2: VK_RETURN, a3: 0, a4: 0, a5: 0 } });
}

/// The window menu one press on the window-menu icon opens. # C: O(N_windows)
#[inline(never)]
fn system_menu_of(hwnd: u64) -> Option<u32> {
    let window = WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
    with_entry(|entry| entry.state.get(window).and_then(|record| record.sys_menu)).flatten()
}

/// Which menu an Alt-key request opens: the window menu when the character is
/// a space or the window carries no bar, otherwise the bar. # C: O(N_windows)
#[inline(never)]
fn keyboard_menu(hwnd: u64, character: u32) -> Option<u32> {
    const SPACE: u32 = b' ' as u32;
    if character == SPACE { return system_menu_of(hwnd); }
    bar_of(hwnd).map(|(menu, _)| menu.raw()).or_else(|| system_menu_of(hwnd))
}

/// The `WM_NCCALCSIZE` parameter block begins with the rectangle the client
/// area is being computed into.
const NCCALCSIZE_CLIENT_RECT: usize = 16;
/// The Alt flag one key message carries in the high word of its lParam.
const KEYDATA_ALT: u64 = 0x2000_0000;

/// Answer the nonclient messages a menu bar owns, ahead of the rest of the
/// default window procedure. Absent means the message is not the bar's.
/// # C: O(N_items + pixels); # Sleeps: yes
#[inline(never)]
pub(crate) fn default_proc_for_current(hwnd: u64, message: u32, wparam: u64, lparam: i64) -> Option<u64> {
    use ipc::win32_window::nonclient_menu as nc;
    match message {
        nc::WM_NCLBUTTONDOWN => {
            trace(b"nc-button-down");
            let command = nc::nc_button_sys_command(wparam as u16 as i16)?;
            trace(b"nc-button-command");
            let _ = crate::nt_window::send::send_for_current(hwnd, nc::WM_SYSCOMMAND, command as u64, lparam as u64);
            Some(0)
        }
        nc::WM_SYSCOMMAND => {
            trace(b"syscommand");
            let command = nc::menu_sys_command(wparam as u32, lparam as u32)?;
            trace(b"syscommand-decoded");
            let point = ((lparam as u64 as u16 as i16) as i32, (((lparam as u64) >> 16) as u16 as i16) as i32);
            Some(track_for_current(hwnd, command, point).unwrap_or(0))
        }
        nc::WM_KEYDOWN | nc::WM_KEYUP | nc::WM_SYSKEYDOWN | nc::WM_SYSKEYUP | nc::WM_SYSCHAR => {
            let alt = lparam as u64 & KEYDATA_ALT != 0;
            let shift = crate::nt_window::keyboard::get_key_state_current(nc::VK_SHIFT as u64) & 0x8000 != 0;
            let character = if message == nc::WM_SYSCHAR { wparam as u32 } else { 0 };
            let vk = if message == nc::WM_SYSCHAR { 0 } else { wparam as u32 };
            let action = with_entry(|entry| entry.key_menu.key(message, vk, character, shift, alt)).flatten()?;
            match action {
                nc::KeyMenuAction::SysCommand { command, character } => {
                    let _ = crate::nt_window::send::send_for_current(hwnd, nc::WM_SYSCOMMAND, command as u64, character as u64);
                }
                nc::KeyMenuAction::ContextMenu => {
                    const WM_CONTEXTMENU: u32 = 0x007b;
                    let _ = crate::nt_window::send::send_for_current(hwnd, WM_CONTEXTMENU, hwnd, u64::MAX);
                }
                nc::KeyMenuAction::Beep => beep(),
            }
            Some(0)
        }
        _ => None,
    }
}

/// The warning a key that names no menu makes. # C: O(1)
fn beep() {
    const BEEP_HZ: u32 = 750;
    const BEEP_MS: u32 = 125;
    if crate::nt_window::USER_SETTINGS.lock().beep_enabled() { let _ = sound::beep::beep(BEEP_HZ, BEEP_MS); }
}

/// The hit-test code a point over one window's menu bar takes, ahead of the
/// window's own client hit test. # C: O(N_windows)
#[inline(never)]
pub(crate) fn hit_test_for_current(hwnd: u64, lparam: i64) -> Option<i16> {
    let window = WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
    // The point a nonclient hit test carries and the rectangles it is compared
    // against are in the same space the window rectangle is kept in, so the
    // client rectangle here is the unnormalised one: its top is where the
    // bar's band ends, and normalising that to zero leaves no band at all.
    let (client, has_menu) = with_entry(|entry| {
        let record = entry.state.get(window)?;
        let has_menu = ipc::win32_window::nonclient_menu::window_has_menu_bar(record.style, record.ex_style, entry.state.menu(window));
        Some((entry.state.client_rect_raw(window)?, has_menu))
    }).flatten()?;
    let x = (lparam as u64 as u16 as i16) as i32;
    let y = (((lparam as u64) >> 16) as u16 as i16) as i32;
    ipc::win32_window::nonclient_menu::menu_bar_hit_test(client.left, client.top, client.right, has_menu, x, y)
}

/// Take the menu bar's height off the top of the client rectangle one
/// `WM_NCCALCSIZE` is computing. # C: O(N_items)
#[inline(never)]
pub(crate) fn nc_calc_size_for_current(hwnd: u64, lparam: u64) -> Option<u64> {
    if lparam == 0 { return None; }
    let mut bytes = [0u8; NCCALCSIZE_CLIENT_RECT];
    if uaccess::copy_from_user(&mut bytes, lparam).is_err() { return None; }
    let value = |index: usize| i32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
    let (left, top, right) = (value(0), value(1), value(2));
    let height = height_for_current(hwnd, right - left);
    if height <= 0 { return None; }
    let top = top.checked_add(height)?;
    if uaccess::copy_to_user(lparam + 4, &top.to_le_bytes()).is_err() { return None; }
    Some(0)
}
