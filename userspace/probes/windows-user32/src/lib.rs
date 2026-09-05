//! Native userspace user32 façade over the tagged NT window ABI.

use std::io;
use std::collections::BTreeMap;
use syscall::nt::{NtService, NtWindowMessage, NtWindowRect};
use windows_gdi::{Gdi, GdiError, RasterError, RasterFont, RasterSurface, Rect as GdiRect};

pub mod input;
pub use input::{HostInput, InputError, InputRoute, InputTranslator, MouseButton};

const STATUS_NO_MORE_ENTRIES: u64 = 0x8000_001a;
const STATUS_FAILURE_MASK: u64 = 0x8000_0000;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_TIMER: u32 = 0x0113;
pub const WM_QUIT: u32 = 0x0012;
pub const VK_BACK: u16 = 0x08;
pub const VK_TAB: u16 = 0x09;
pub const VK_RETURN: u16 = 0x0d;
pub const VK_SPACE: u16 = 0x20;
const WINE_DISPATCH_MESSAGE: u64 = 0x138b;
const WINE_CREATE_MENU: u64 = 0x1366;
const WINE_CREATE_POPUP_MENU: u64 = 0x1368;
const WINE_SET_MENU: u64 = 0x1569;
const WINE_DESTROY_MENU: u64 = 0x1382;
const WINE_DRAW_MENU_BAR: u64 = 0x139b;
const WINE_CALL_ONE_PARAM: u64 = 0x133d;
const WINE_GET_DC: u64 = 0x13eb;
const WINE_GET_DC_EX: u64 = 0x13ec;
const WINE_RELEASE_DC: u64 = 0x1509;
const WINE_THUNKED_MENU_ITEM_INFO: u64 = 0x15d0;
const CALL_ONE_PARAM_GET_MENU_ITEM_COUNT: u64 = 4;
const MENUITEMINFO_BYTES: usize = 80;
const MENUITEMINFO_INSERT: u64 = 1;
pub const MF_BYPOSITION: u32 = 0x0000_0400;
pub const MF_POPUP: u32 = 0x0000_0010;
pub const MIIM_STATE: u32 = 0x0000_0001;
pub const MIIM_ID: u32 = 0x0000_0002;
pub const MIIM_SUBMENU: u32 = 0x0000_0004;
pub const MIIM_STRING: u32 = 0x0000_0040;

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MenuItemInfoW {
    pub cb_size: u32,
    pub f_mask: u32,
    pub f_type: u32,
    pub f_state: u32,
    pub w_id: u32,
    pub h_sub_menu: u64,
    pub hbmp_checked: u64,
    pub hbmp_unchecked: u64,
    pub dw_item_data: u64,
    pub dw_type_data: u64,
    pub cch: u32,
    pub hbmp_item: u64,
}

#[derive(Debug)]
pub enum WindowError { Status(u64), Host(io::Error) }

/// Result of one blocking GetMessageW operation. # C: O(1)
#[derive(Debug, Eq, PartialEq)]
pub enum GetMessageResult {
    Message(NtWindowMessage),
    Quit(NtWindowMessage),
}

#[derive(Debug)]
pub enum MenuRenderError { Window(WindowError), Gdi(GdiError), Raster(RasterError) }

/// User32-shaped client whose state remains owned by the native NT window service.
pub struct User32;

#[derive(Debug)]
pub enum ClassError { EmptyName, UnterminatedName, DuplicateName, UnknownClass, Service(WindowError) }

/// Userspace class metadata; HWND and message queues remain native-service state.
pub struct ClassRegistry { next_atom: u16, classes: BTreeMap<Vec<u16>, RegisteredClass> }

struct RegisteredClass { atom: u16, wndproc: u64 }

impl ClassRegistry {
    /// Construct an empty process-local class registry. # C: O(1)
    pub fn new() -> Self { Self { next_atom: 1, classes: BTreeMap::new() } }

    /// Register one UTF-16 window class and return its atom. # C: O(log N_classes)
    pub fn register_class_ex_w(&mut self, name: &[u16], wndproc: u64) -> Result<u16, ClassError> {
        let name = class_key(name)?;
        if self.classes.contains_key(&name) { return Err(ClassError::DuplicateName); }
        let atom = self.next_atom;
        self.next_atom = self.next_atom.checked_add(1).ok_or(ClassError::DuplicateName)?;
        self.classes.insert(name, RegisteredClass { atom, wndproc });
        Ok(atom)
    }

    /// Remove one class by its UTF-16 name. # C: O(log N_classes)
    pub fn unregister_class_w(&mut self, name: &[u16]) -> Result<(), ClassError> {
        let name = class_key(name)?;
        if self.classes.remove(&name).is_some() { Ok(()) } else { Err(ClassError::UnknownClass) }
    }

    /// Create a native window using the registered class procedure. # C: O(log N_classes) plus kernel service
    pub fn create_window_ex_w(&self, user32: &User32, name: &[u16], parent: u64) -> Result<u64, ClassError> {
        let name = class_key(name)?;
        let class = self.classes.get(&name).ok_or(ClassError::UnknownClass)?;
        user32.create_window(parent, class.wndproc).map_err(ClassError::Service)
    }

    /// Return the stable atom assigned to a registered class. # C: O(log N_classes)
    pub fn atom(&self, name: &[u16]) -> Result<u16, ClassError> {
        let name = class_key(name)?;
        self.classes.get(&name).map(|class| class.atom).ok_or(ClassError::UnknownClass)
    }
}

impl User32 {
    /// Construct a stateless façade over the current NT process. # C: O(1)
    pub const fn new() -> Self { Self }

    /// Allocate a process-owned regular menu. # C: O(1) plus kernel service
    pub fn create_menu(&self) -> Result<u64, WindowError> { invoke(NtService::WineSyscall, [WINE_CREATE_MENU, 0, 0, 0, 0, 0]) }

    /// Allocate a process-owned popup menu. # C: O(1) plus kernel service
    pub fn create_popup_menu(&self) -> Result<u64, WindowError> { invoke(NtService::WineSyscall, [WINE_CREATE_POPUP_MENU, 0, 0, 0, 0, 0]) }

    /// Attach a menu to a native HWND through the canonical window owner. # C: O(N_windows) plus kernel service
    pub fn set_menu(&self, hwnd: u64, menu: Option<u64>) -> Result<(), WindowError> { invoke(NtService::WineSyscall, [WINE_SET_MENU, hwnd, menu.unwrap_or(0), 0, 0, 0]).map(|_| ()) }

    /// Release a process-owned menu and its attached submenu tree. # C: O(N_menus + N_items) plus kernel service
    pub fn destroy_menu(&self, menu: u64) -> Result<(), WindowError> { invoke(NtService::WineSyscall, [WINE_DESTROY_MENU, menu, 0, 0, 0, 0]).map(|_| ()) }

    /// Invalidate the native frame after changing a window menu. # C: O(1) plus kernel service
    pub fn draw_menu_bar(&self, hwnd: u64) -> Result<(), WindowError> { invoke(NtService::WineSyscall, [WINE_DRAW_MENU_BAR, hwnd, 0, 0, 0, 0]).map(|_| ()) }

    /// Append one UTF-16 menu item using Wine's native MENUITEMINFO transaction. # C: O(N_items) plus usercopy
    pub fn append_menu_w(&self, menu: u64, flags: u32, id: u32, text: &[u16], submenu: Option<u64>) -> Result<(), WindowError> {
        let mut value = text.iter().copied().take_while(|unit| *unit != 0).collect::<Vec<_>>();
        value.push(0);
        let mut info = [0u8; MENUITEMINFO_BYTES];
        info[0..4].copy_from_slice(&(MENUITEMINFO_BYTES as u32).to_le_bytes());
        let mut mask = MIIM_ID | MIIM_STRING;
        if submenu.is_some() { mask |= MIIM_SUBMENU; }
        info[4..8].copy_from_slice(&mask.to_le_bytes());
        info[16..20].copy_from_slice(&id.to_le_bytes());
        info[24..32].copy_from_slice(&submenu.unwrap_or(0).to_le_bytes());
        info[56..64].copy_from_slice(&(value.as_ptr() as u64).to_le_bytes());
        info[64..68].copy_from_slice(&(value.len() as u32).to_le_bytes());
        invoke(NtService::WineSyscall, [WINE_THUNKED_MENU_ITEM_INFO, menu, u32::MAX as u64, (flags | MF_BYPOSITION) as u64, MENUITEMINFO_INSERT, info.as_mut_ptr() as u64]).map(|_| ())
    }

    /// Return the canonical number of items in one menu. # C: O(N_items) plus kernel service
    pub fn get_menu_item_count(&self, menu: u64) -> Result<usize, WindowError> { invoke(NtService::WineSyscall, [WINE_CALL_ONE_PARAM, menu, CALL_ONE_PARAM_GET_MENU_ITEM_COUNT, 0, 0, 0]).map(|value| value as usize) }

    /// Query one wide menu item through the native MENUITEMINFO transaction. # C: O(N_items) plus usercopy
    pub fn get_menu_item_info_w(&self, menu: u64, item: u32, by_position: bool, info: &mut MenuItemInfoW) -> Result<(), WindowError> {
        info.cb_size = MENUITEMINFO_BYTES as u32;
        invoke(NtService::WineSyscall, [WINE_THUNKED_MENU_ITEM_INFO, menu, item as u64, if by_position { MF_BYPOSITION as u64 } else { 0 }, 6, info as *mut MenuItemInfoW as u64]).map(|_| ())
    }

    /// Render a menu bar through the userspace raster owner and native GDI surface. # C: O(N_items * (N_text + pixels)) plus kernel services
    pub fn draw_menu_bar_temp(&self, gdi: &Gdi, font: &RasterFont, dc: u64, menu: u64, rect: &mut NtWindowRect, foreground: u32, background: u32) -> Result<i32, MenuRenderError> {
        let count = self.get_menu_item_count(menu).map_err(MenuRenderError::Window)?;
        let mut rendered: Vec<(RasterSurface, i32)> = Vec::new();
        let mut height = 19i32;
        for position in 0..count {
            let mut text = vec![0u16; 512];
            let mut info = MenuItemInfoW { cb_size: MENUITEMINFO_BYTES as u32, f_mask: MIIM_STRING, f_type: 0, f_state: 0, w_id: 0, h_sub_menu: 0, hbmp_checked: 0, hbmp_unchecked: 0, dw_item_data: 0, dw_type_data: text.as_mut_ptr() as u64, cch: text.len() as u32, hbmp_item: 0 };
            self.get_menu_item_info_w(menu, position as u32, true, &mut info).map_err(MenuRenderError::Window)?;
            let length = (info.cch as usize).min(text.len());
            let surface = font.rasterize(&text[..length], foreground, background).map_err(MenuRenderError::Raster)?;
            height = height.max(surface.height as i32 + 2);
            rendered.push((surface, 16));
        }
        rect.bottom = rect.top.saturating_add(height);
        gdi.fill_rect(dc, GdiRect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }, background).map_err(MenuRenderError::Gdi)?;
        let mut left = rect.left.saturating_add(1);
        for (surface, padding) in rendered {
            let top = rect.top.saturating_add((height.saturating_sub(surface.height as i32)) / 2);
            gdi.draw_raster(dc, left.saturating_add(padding / 2), top, &surface).map_err(MenuRenderError::Gdi)?;
            left = left.saturating_add(surface.width as i32).saturating_add(padding);
        }
        gdi.fill_rect(dc, GdiRect { left: rect.left, top: rect.bottom.saturating_sub(1), right: rect.right, bottom: rect.bottom }, 0x00c0_c0c0).map_err(MenuRenderError::Gdi)?;
        Ok(height)
    }

    /// Create one window and return its native identifier. # C: O(1) plus kernel service
    pub fn create_window(&self, parent: u64, wndproc: u64) -> Result<u64, WindowError> {
        invoke(NtService::CreateWindow, [parent, wndproc, 0, 0, 0, 0])
    }

    /// Destroy a window owned by the current NT process. # C: O(1) plus kernel service
    pub fn destroy_window(&self, hwnd: u64) -> Result<(), WindowError> {
        invoke(NtService::DestroyWindow, [hwnd, 0, 0, 0, 0, 0]).map(|_| ())
    }

    /// Post one message to a native window queue. # C: O(1) plus kernel service
    pub fn post_message(&self, hwnd: u64, message: u32, wparam: u64, lparam: i64) -> Result<(), WindowError> {
        invoke(NtService::PostMessage, [hwnd, message as u64, wparam, lparam as u64, 0, 0]).map(|_| ())
    }

    /// End the current thread's GetMessage loop with the supplied exit code. # C: O(1) plus kernel service
    pub fn post_quit_message(&self, exit_code: i32) -> Result<(), WindowError> {
        invoke(NtService::PostQuitMessage, [exit_code as u64, 0, 0, 0, 0, 0]).map(|_| ())
    }

    /// Arm or replace a window/thread timer owned by the native window manager. # C: O(N_timers) plus kernel service
    pub fn set_timer(&self, hwnd: Option<u64>, id: u64, timeout_ms: u32, proc: u64) -> Result<u64, WindowError> {
        invoke(NtService::SetWindowTimer, timer_args(hwnd, id, timeout_ms as u64, proc))
    }

    /// Cancel the exact window/thread timer identity in the native window manager. # C: O(N_timers) plus kernel service
    pub fn kill_timer(&self, hwnd: Option<u64>, id: u64) -> Result<bool, WindowError> {
        invoke(NtService::KillWindowTimer, timer_args(hwnd, id, 0, 0)).map(|value| value != 0)
    }

    /// Set the current thread's focus window and return the previous HWND. # C: O(1) plus kernel service
    pub fn set_focus(&self, hwnd: u64) -> Result<u64, WindowError> {
        invoke(NtService::SetFocusWindow, [hwnd, 0, 0, 0, 0, 0])
    }

    /// Inject one native key transition into the focused window's queue. # C: O(1) plus kernel service
    pub fn inject_key(&self, key: u16, pressed: bool, repeat: bool) -> Result<(), WindowError> {
        invoke(NtService::InjectKey, [key as u64, pressed as u64, repeat as u64, 0, 0, 0]).map(|_| ())
    }

    /// Convert a key-down message into the corresponding Unicode character message. # C: O(1) plus kernel service
    pub fn translate_message(&self, message: &NtWindowMessage, shift: bool, caps_lock: bool) -> Result<bool, WindowError> {
        if message.message != WM_KEYDOWN { return Ok(false); }
        let Some(character) = translate_virtual_key(message.wparam as u16, shift, caps_lock) else { return Ok(false); };
        self.post_message(message.hwnd, WM_CHAR, character as u64, message.lparam)?;
        Ok(true)
    }

    /// Inspect one queued message, optionally removing it. # C: O(1) plus usercopy
    pub fn peek_message(&self, hwnd: u64, first: u32, last: u32, remove: bool) -> Result<Option<NtWindowMessage>, WindowError> {
        let mut message = NtWindowMessage { hwnd: 0, message: 0, padding: 0, wparam: 0, lparam: 0 };
        let result = invoke(NtService::PeekMessage, [(&mut message as *mut NtWindowMessage) as u64, hwnd, first as u64, last as u64, remove as u64, 0]);
        match result { Ok(_) => Ok(Some(message)), Err(WindowError::Status(STATUS_NO_MORE_ENTRIES)) => Ok(None), Err(error) => Err(error) }
    }

    /// Remove and return the next matching message, preserving GetMessageW's quit result. # C: O(1) plus scheduler wait
    pub fn get_message(&self, hwnd: u64, first: u32, last: u32) -> Result<GetMessageResult, WindowError> {
        let mut message = NtWindowMessage { hwnd: 0, message: 0, padding: 0, wparam: 0, lparam: 0 };
        invoke(NtService::GetMessage, [(&mut message as *mut NtWindowMessage) as u64, hwnd, first as u64, last as u64, 0, 0])?;
        Ok(classify_get_message(message))
    }

    /// Dispatch one message through its canonical native window procedure. # C: O(1) plus one callback transition
    pub fn dispatch_message(&self, message: &NtWindowMessage) -> Result<i64, WindowError> {
        let mut args = [0u64; 17];
        args[0] = message as *const NtWindowMessage as u64;
        let result = invoke(NtService::WineSyscall, [WINE_DISPATCH_MESSAGE, args.as_ptr() as u64, 0, 0, 0, 0])?;
        Ok(result as i64)
    }

    /// Invoke the native default window procedure. # C: O(1) plus kernel service
    pub fn default_window_proc(&self, hwnd: u64, message: u32, wparam: u64, lparam: i64) -> Result<u64, WindowError> {
        invoke(NtService::DefaultWindowProc, [hwnd, message as u64, wparam, lparam as u64, 0, 0])
    }

    /// Read the native rectangle for one window. # C: O(N_windows) plus usercopy
    pub fn get_window_rect(&self, hwnd: u64) -> Result<NtWindowRect, WindowError> {
        let mut rect = NtWindowRect { left: 0, top: 0, right: 0, bottom: 0 };
        invoke(NtService::GetWindowRect, [hwnd, (&mut rect as *mut NtWindowRect) as u64, 0, 0, 0, 0]).map(|_| rect)
    }

    /// Set the native rectangle for one window. # C: O(N_windows) plus usercopy
    pub fn set_window_rect(&self, hwnd: u64, rect: &NtWindowRect) -> Result<(), WindowError> {
        invoke(NtService::SetWindowRect, [hwnd, (rect as *const NtWindowRect) as u64, 0, 0, 0, 0]).map(|_| ())
    }

    /// Read one window's UTF-16 title/control text. # C: O(N_text) plus usercopy
    pub fn get_window_text(&self, hwnd: u64, text: &mut [u16]) -> Result<usize, WindowError> {
        if text_copy_capacity(text.len()) == 0 && text.is_empty() { return Ok(0); }
        invoke(NtService::GetWindowText, [hwnd, text.as_mut_ptr() as u64, text.len() as u64, 0, 0, 0]).map(|length| length as usize)
    }

    /// Replace one window's UTF-16 title/control text. # C: O(N_text) plus usercopy
    pub fn set_window_text(&self, hwnd: u64, text: &[u16]) -> Result<(), WindowError> {
        let mut value = text.iter().copied().take_while(|unit| *unit != 0).collect::<Vec<_>>();
        value.push(0);
        invoke(NtService::SetWindowText, [hwnd, value.as_ptr() as u64, 0, 0, 0, 0]).map(|_| ())
    }

    /// Read the client rectangle in client coordinates. # C: O(N_windows) plus usercopy
    pub fn get_client_rect(&self, hwnd: u64) -> Result<NtWindowRect, WindowError> {
        let mut rect = NtWindowRect { left: 0, top: 0, right: 0, bottom: 0 };
        invoke(NtService::GetClientRect, [hwnd, (&mut rect as *mut NtWindowRect) as u64, 0, 0, 0, 0]).map(|_| rect)
    }

    /// Return the native parent HWND, or zero for a top-level window. # C: O(N_windows)
    pub fn get_parent(&self, hwnd: u64) -> Result<u64, WindowError> {
        invoke(NtService::GetParent, [hwnd, 0, 0, 0, 0, 0])
    }

    /// Apply a Win32 show command and return the previous visibility state. # C: O(N_windows)
    pub fn show_window(&self, hwnd: u64, command: u32) -> Result<bool, WindowError> {
        invoke(NtService::ShowWindow, [hwnd, command as u64, 0, 0, 0, 0]).map(|previous| previous != 0)
    }

    /// Mark a client region dirty, or the whole client when absent. # C: O(N_windows + N_dirty) plus kernel service
    pub fn invalidate_rect(&self, hwnd: u64, rect: Option<&NtWindowRect>) -> Result<(), WindowError> {
        invoke(NtService::InvalidateWindow, [hwnd, rect.map(|value| value as *const NtWindowRect as u64).unwrap_or(0), 0, 0, 0, 0]).map(|_| ())
    }

    /// Consume and return the current dirty client region. # C: O(N_dirty) plus usercopy
    pub fn begin_paint(&self, hwnd: u64) -> Result<NtWindowRect, WindowError> {
        let mut rect = NtWindowRect { left: 0, top: 0, right: 0, bottom: 0 };
        invoke(NtService::BeginWindowPaint, [hwnd, (&mut rect as *mut NtWindowRect) as u64, 0, 0, 0, 0]).map(|_| rect)
    }

    /// Finish one native paint transaction. # C: O(N_windows) plus kernel service
    pub fn end_paint(&self, hwnd: u64) -> Result<(), WindowError> {
        invoke(NtService::EndWindowPaint, [hwnd, 0, 0, 0, 0, 0]).map(|_| ())
    }

    /// Acquire the canonical display DC for a window, retained across leases. # C: O(N_windows + N_gdi)
    pub fn get_dc(&self, hwnd: u64) -> Result<u64, WindowError> {
        invoke(NtService::WineSyscall, [WINE_GET_DC, hwnd, 0, 0, 0, 0])
    }

    /// Acquire a window DC with the supported Wine clip flags. # C: O(N_windows + N_gdi)
    pub fn get_dc_ex(&self, hwnd: u64, clip_region: u64, flags: u32) -> Result<u64, WindowError> {
        invoke(NtService::WineSyscall, [WINE_GET_DC_EX, hwnd, clip_region, flags as u64, 0, 0])
    }

    /// Release one GetDC lease without deleting the canonical DC object. # C: O(N_windows + N_gdi)
    pub fn release_dc(&self, hwnd: u64, dc: u64) -> Result<(), WindowError> {
        invoke(NtService::WineSyscall, [WINE_RELEASE_DC, hwnd, dc, 0, 0, 0]).map(|_| ())
    }
}

fn translate_virtual_key(key: u16, shift: bool, caps_lock: bool) -> Option<u16> {
    let character = match key {
        VK_BACK | VK_TAB | VK_RETURN | VK_SPACE => Some(key),
        0x30..=0x39 => if shift { Some(match key { 0x30 => b')', 0x31 => b'!', 0x32 => b'@', 0x33 => b'#', 0x34 => b'$', 0x35 => b'%', 0x36 => b'^', 0x37 => b'&', 0x38 => b'*', 0x39 => b'(', _ => unreachable!() } as u16) } else { Some(key) },
        0x41..=0x5a => {
            let upper = shift ^ caps_lock;
            if upper { Some(key) } else { Some(key + (b'a' as u16 - b'A' as u16)) }
        }
        _ => None,
    };
    character
}

fn classify_get_message(message: NtWindowMessage) -> GetMessageResult {
    if message.message == WM_QUIT { GetMessageResult::Quit(message) } else { GetMessageResult::Message(message) }
}

fn text_copy_capacity(buffer_len: usize) -> usize { buffer_len.saturating_sub(1) }

fn timer_args(hwnd: Option<u64>, id: u64, timeout_ms: u64, proc: u64) -> [u64; 6] {
    [hwnd.unwrap_or(0), id, timeout_ms, proc, 0, 0]
}

fn invoke(service: NtService, args: [u64; 6]) -> Result<u64, WindowError> {
    let result = unsafe { libc::syscall(service.entry() as libc::c_long, args[0], args[1], args[2], args[3], args[4], args[5]) };
    if result == -1 { return Err(WindowError::Host(io::Error::last_os_error())); }
    let result = result as u64;
    if result & STATUS_FAILURE_MASK != 0 { Err(WindowError::Status(result)) } else { Ok(result) }
}

fn class_key(name: &[u16]) -> Result<Vec<u16>, ClassError> {
    let end = name.iter().position(|unit| *unit == 0).ok_or(ClassError::UnterminatedName)?;
    if end == 0 || name[end + 1..].iter().any(|unit| *unit != 0) { return Err(ClassError::EmptyName); }
    Ok(name[..end].iter().map(|unit| {
        if (b'A' as u16..=b'Z' as u16).contains(unit) { *unit + (b'a' as u16 - b'A' as u16) } else { *unit }
    }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_message_layout_is_fixed_64_bit_abi() {
        assert_eq!(std::mem::size_of::<NtWindowMessage>(), 32);
        assert_eq!(std::mem::align_of::<NtWindowMessage>(), 8);
        assert_eq!(std::mem::size_of::<NtWindowRect>(), 16);
        assert_eq!(std::mem::size_of::<MenuItemInfoW>(), 80);
        assert_eq!(std::mem::offset_of!(MenuItemInfoW, h_sub_menu), 24);
        assert_eq!(std::mem::offset_of!(MenuItemInfoW, dw_type_data), 56);
        assert_eq!(std::mem::offset_of!(MenuItemInfoW, hbmp_item), 72);
    }

    #[test]
    fn selectors_remain_outside_linux_syscall_namespace() {
        assert_eq!(NtService::CreateWindow.entry(), 0x4e54_0000_0000_001b);
        assert_eq!(NtService::GetMessage.entry(), 0x4e54_0000_0000_001f);
        assert_eq!(NtService::PostQuitMessage.entry(), 0x4e54_0000_0000_0213);
        assert_eq!(NtService::SetFocusWindow.entry(), 0x4e54_0000_0000_0214);
        assert_eq!(NtService::InjectKey.entry(), 0x4e54_0000_0000_0215);
        assert_eq!(NtService::SetWindowTimer.entry(), 0x4e54_0000_0000_021b);
        assert_eq!(NtService::KillWindowTimer.entry(), 0x4e54_0000_0000_021c);
    }

    #[test]
    fn no_message_status_is_not_a_transport_failure() {
        assert_eq!(STATUS_NO_MORE_ENTRIES & STATUS_FAILURE_MASK, STATUS_FAILURE_MASK);
        assert!(matches!(WindowError::Status(STATUS_NO_MORE_ENTRIES), WindowError::Status(value) if value == STATUS_NO_MORE_ENTRIES));
    }

    #[test]
    fn get_message_preserves_wm_quit_loop_termination() {
        let ordinary = NtWindowMessage { hwnd: 7, message: WM_KEYDOWN, padding: 0, wparam: 0x41, lparam: 0 };
        let quit = NtWindowMessage { hwnd: 0, message: WM_QUIT, padding: 0, wparam: 9, lparam: 0 };
        assert_eq!(classify_get_message(ordinary), GetMessageResult::Message(ordinary));
        assert_eq!(classify_get_message(quit), GetMessageResult::Quit(quit));
    }

    #[test]
    fn virtual_key_translation_obeys_shift_and_caps_state() {
        assert_eq!(translate_virtual_key(0x41, false, false), Some(b'a' as u16));
        assert_eq!(translate_virtual_key(0x41, true, false), Some(b'A' as u16));
        assert_eq!(translate_virtual_key(0x41, false, true), Some(b'A' as u16));
        assert_eq!(translate_virtual_key(VK_RETURN, false, false), Some(VK_RETURN));
        assert_eq!(translate_virtual_key(0x70, false, false), None);
    }

    #[test]
    fn geometry_selectors_are_stable_tagged_entries() {
        assert_eq!(NtService::GetWindowRect.entry(), 0x4e54_0000_0000_01ff);
        assert_eq!(NtService::SetWindowRect.entry(), 0x4e54_0000_0000_0200);
        assert_eq!(NtService::GetWindowText.entry(), 0x4e54_0000_0000_0207);
        assert_eq!(NtService::ShowWindow.entry(), 0x4e54_0000_0000_020b);
        assert_eq!(NtService::InvalidateWindow.entry(), 0x4e54_0000_0000_020c);
        assert_eq!(NtService::EndWindowPaint.entry(), 0x4e54_0000_0000_020e);
    }

    #[test]
    fn classes_bind_procedures_without_duplicating_native_windows() {
        let mut classes = ClassRegistry::new();
        let name: Vec<u16> = "Notepad".encode_utf16().chain([0]).collect();
        let atom = classes.register_class_ex_w(&name, 0x1400).unwrap();
        let mixed_case: Vec<u16> = "NOTEPAD".encode_utf16().chain([0]).collect();
        assert!(matches!(classes.atom(&mixed_case), Ok(value) if value == atom));
        assert!(matches!(classes.register_class_ex_w(&mixed_case, 0x1500), Err(ClassError::DuplicateName)));
        assert!(classes.unregister_class_w(&mixed_case).is_ok());
        assert!(matches!(classes.atom(&name), Err(ClassError::UnknownClass)));
    }

    #[test]
    fn class_lookup_rejects_non_case_name_changes_and_malformed_termination() {
        let mut classes = ClassRegistry::new();
        let name: Vec<u16> = "Notepad".encode_utf16().chain([0]).collect();
        let different: Vec<u16> = "NotepadEdit".encode_utf16().chain([0]).collect();
        let unterminated: Vec<u16> = "Notepad".encode_utf16().collect();
        classes.register_class_ex_w(&name, 0x1400).unwrap();
        assert!(matches!(classes.atom(&different), Err(ClassError::UnknownClass)));
        assert!(matches!(classes.atom(&unterminated), Err(ClassError::UnterminatedName)));
    }

    #[test]
    fn zero_text_buffer_is_a_noop_and_nonzero_buffer_reserves_a_terminator() {
        assert_eq!(text_copy_capacity(0), 0);
        assert_eq!(text_copy_capacity(1), 0);
        assert_eq!(text_copy_capacity(8), 7);
    }

    #[test]
    fn window_dc_client_uses_the_wine_getdc_lease_ordinals() {
        assert_eq!([(WINE_GET_DC, 0x13eb), (WINE_GET_DC_EX, 0x13ec), (WINE_RELEASE_DC, 0x1509)], [(0x13eb, 0x13eb), (0x13ec, 0x13ec), (0x1509, 0x1509)]);
    }

    #[test]
    fn window_timers_preserve_thread_target_and_callback_abi() {
        assert_eq!(timer_args(None, 7, 250, 0xfeed), [0, 7, 250, 0xfeed, 0, 0]);
        assert_eq!(timer_args(Some(41), 9, 0, 0), [41, 9, 0, 0, 0, 0]);
        assert_eq!(WM_TIMER, 0x0113);
    }
}
