//! Native userspace user32 façade over the tagged NT window ABI.

use std::io;
use std::collections::BTreeMap;
use syscall::nt::{NtService, NtWindowMessage, NtWindowRect};

const STATUS_NO_MORE_ENTRIES: u64 = 0x8000_001a;
const STATUS_FAILURE_MASK: u64 = 0x8000_0000;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_CHAR: u32 = 0x0102;
pub const VK_BACK: u16 = 0x08;
pub const VK_TAB: u16 = 0x09;
pub const VK_RETURN: u16 = 0x0d;
pub const VK_SPACE: u16 = 0x20;

#[derive(Debug)]
pub enum WindowError { Status(u64), Host(io::Error) }

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
        let name = class_name(name)?;
        if self.classes.contains_key(name) { return Err(ClassError::DuplicateName); }
        let atom = self.next_atom;
        self.next_atom = self.next_atom.checked_add(1).ok_or(ClassError::DuplicateName)?;
        self.classes.insert(name.to_vec(), RegisteredClass { atom, wndproc });
        Ok(atom)
    }

    /// Remove one class by its UTF-16 name. # C: O(log N_classes)
    pub fn unregister_class_w(&mut self, name: &[u16]) -> Result<(), ClassError> {
        let name = class_name(name)?;
        if self.classes.remove(name).is_some() { Ok(()) } else { Err(ClassError::UnknownClass) }
    }

    /// Create a native window using the registered class procedure. # C: O(log N_classes) plus kernel service
    pub fn create_window_ex_w(&self, user32: &User32, name: &[u16], parent: u64) -> Result<u64, ClassError> {
        let name = class_name(name)?;
        let class = self.classes.get(name).ok_or(ClassError::UnknownClass)?;
        user32.create_window(parent, class.wndproc).map_err(ClassError::Service)
    }

    /// Return the stable atom assigned to a registered class. # C: O(log N_classes)
    pub fn atom(&self, name: &[u16]) -> Result<u16, ClassError> {
        let name = class_name(name)?;
        self.classes.get(name).map(|class| class.atom).ok_or(ClassError::UnknownClass)
    }
}

impl User32 {
    /// Construct a stateless façade over the current NT process. # C: O(1)
    pub const fn new() -> Self { Self }

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

    /// Remove and return the next matching message, waiting in the native service if needed. # C: O(1) plus scheduler wait
    pub fn get_message(&self, hwnd: u64, first: u32, last: u32) -> Result<NtWindowMessage, WindowError> {
        let mut message = NtWindowMessage { hwnd: 0, message: 0, padding: 0, wparam: 0, lparam: 0 };
        invoke(NtService::GetMessage, [(&mut message as *mut NtWindowMessage) as u64, hwnd, first as u64, last as u64, 0, 0]).map(|_| message)
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

fn invoke(service: NtService, args: [u64; 6]) -> Result<u64, WindowError> {
    let result = unsafe { libc::syscall(service.entry() as libc::c_long, args[0], args[1], args[2], args[3], args[4], args[5]) };
    if result == -1 { return Err(WindowError::Host(io::Error::last_os_error())); }
    let result = result as u64;
    if result & STATUS_FAILURE_MASK != 0 { Err(WindowError::Status(result)) } else { Ok(result) }
}

fn class_name(name: &[u16]) -> Result<&[u16], ClassError> {
    let end = name.iter().position(|unit| *unit == 0).ok_or(ClassError::UnterminatedName)?;
    if end == 0 || name[end + 1..].iter().any(|unit| *unit != 0) { return Err(ClassError::EmptyName); }
    Ok(&name[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_message_layout_is_fixed_64_bit_abi() {
        assert_eq!(std::mem::size_of::<NtWindowMessage>(), 32);
        assert_eq!(std::mem::align_of::<NtWindowMessage>(), 8);
        assert_eq!(std::mem::size_of::<NtWindowRect>(), 16);
    }

    #[test]
    fn selectors_remain_outside_linux_syscall_namespace() {
        assert_eq!(NtService::CreateWindow.entry(), 0x4e54_0000_0000_001b);
        assert_eq!(NtService::GetMessage.entry(), 0x4e54_0000_0000_001f);
        assert_eq!(NtService::PostQuitMessage.entry(), 0x4e54_0000_0000_0213);
        assert_eq!(NtService::SetFocusWindow.entry(), 0x4e54_0000_0000_0214);
        assert_eq!(NtService::InjectKey.entry(), 0x4e54_0000_0000_0215);
    }

    #[test]
    fn no_message_status_is_not_a_transport_failure() {
        assert_eq!(STATUS_NO_MORE_ENTRIES & STATUS_FAILURE_MASK, STATUS_FAILURE_MASK);
        assert!(matches!(WindowError::Status(STATUS_NO_MORE_ENTRIES), WindowError::Status(value) if value == STATUS_NO_MORE_ENTRIES));
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
        assert!(matches!(classes.atom(&name), Ok(value) if value == atom));
        assert!(matches!(classes.register_class_ex_w(&name, 0x1500), Err(ClassError::DuplicateName)));
        assert!(classes.unregister_class_w(&name).is_ok());
        assert!(matches!(classes.atom(&name), Err(ClassError::UnknownClass)));
    }
}
