//! NT GUI adapter: process-scoped windows and thread message queues.

// Window callback completion is currently an x86-64 Windows-personality path;
// AArch64 is compile-only and retains the shared module without treating its
// intentionally undispatched callback helpers as missing implementation.
#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as GuiLockClass};
use syscall::nt::{self, NtCall, NtWindowCall, NtWindowMessage};
#[path = "nt_window/owner.rs"]
mod owner;
#[path = "nt_window/class_background.rs"]
mod class_background;
pub(crate) use class_background::{register_class_with_background_for_current, class_background_for_current};
#[path = "nt_window/erase_background.rs"]
mod erase_background;
#[cfg(target_os = "oxide-kernel")]
#[path = "nt_window/default_paint.rs"]
mod default_paint;
use owner::new_entry;
#[path = "nt_window/control.rs"]
mod control;
pub(crate) mod control_color;
pub(crate) mod paint;
pub(crate) mod paintlease;
pub(crate) mod property;
pub(crate) mod redraw;
pub(crate) mod caret;
pub(crate) mod settings;
pub(crate) mod paint_callbacks;
pub(crate) mod paint_prepare;
mod paint_cleanup;
pub(crate) mod scroll;
mod nonclient;
mod dc_lease;
pub(crate) use dc_lease::dc_lease_context_for_current;
pub(crate) use nonclient::nonclient_scroll_context_for_current;
pub(crate) use control::{set_control_id_for_current, control_id_for_current};
pub(crate) use control::{get_window_long_for_current, set_window_long_with_encoding_for_current};
#[path = "nt_window/teardown.rs"]
mod teardown;
pub(crate) use teardown::cleanup_thread_at_exit;
#[path = "nt_window/creation_metadata.rs"]
mod creation_metadata;
#[path = "nt_window/desktop.rs"]
pub(crate) mod desktop;
#[path = "nt_window/rect_query.rs"]
pub(crate) mod rect_query;
pub(crate) use creation_metadata::{set_creation_metadata_current, window_call_context_current};
#[path = "nt_window/retrieval.rs"]
mod retrieval;
pub(crate) use retrieval::{resume_position_message_current, retrieve_raw};
#[path = "nt_window/position.rs"]
pub(crate) mod position;
#[path = "nt_window/send.rs"]
pub(crate) mod send;
pub(crate) use position::{position_context_for_current, position_apply_for_current};

#[path = "nt_window/create_lifecycle.rs"]
mod create_lifecycle;
#[path = "nt_window/create.rs"]
mod create;
#[path = "nt_window/bridge.rs"]
mod bridge;
#[path = "nt_window/keyboard.rs"]
mod keyboard;
#[path = "nt_window/query.rs"]
mod query;
pub(crate) use query::hwnd_snapshot_for_current;
#[path = "nt_window/accel.rs"]
mod accel;
pub(crate) use accel::{accel_create_for_current, accel_copy_for_current, accel_destroy_for_current, accel_target_for_current};
pub(crate) use keyboard::{get_key_state_current, get_async_key_state_current,
    get_keyboard_state_current, set_keyboard_state_current};
pub(crate) use bridge::handle_event as compositor_event;
pub(crate) use create_lifecycle::{CreateReturnConvention, CreateStructArgs};
pub(crate) use create::begin_create_lifecycle_for_current;
#[cfg(target_arch = "x86_64")]
pub(crate) use create_lifecycle::{callback_layout, serialize_create_struct, CALLBACK_FRAME_BYTES};
#[cfg(target_arch = "x86_64")]
#[path = "nt_window/callbacks.rs"]
mod callbacks;
#[cfg(target_arch = "x86_64")]
pub(crate) use callbacks::complete_callback;

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_NO_MORE_ENTRIES: u64 = 0x8000_001a;
const STATUS_QUOTA_EXCEEDED: u64 = 0xc000_0044;
const STATUS_ALERTED: u64 = 0x0000_0101;
const STATUS_PENDING: u64 = 0x0000_0103;
const STATUS_NOT_SUPPORTED: u64 = 0xc000_00bb;
const WM_DESTROY: u64 = 0x0002;
const MENUITEMINFO_MASK_STATE: u32 = 0x0000_0001;
const MENUITEMINFO_MASK_ID: u32 = 0x0000_0002;
const MENUITEMINFO_MASK_SUBMENU: u32 = 0x0000_0004;
const MENUITEMINFO_MASK_STRING: u32 = 0x0000_0040;

pub(crate) const CALLBACK_DESTROY: u64 = 1;
pub(crate) const CALLBACK_NCDESTROY: u64 = 2;
pub(crate) const CALLBACK_CREATE_NCCREATE: u64 = 3;
pub(crate) const CALLBACK_CREATE: u64 = 4;

fn callback_argument(root: u64, index: usize) -> u64 { (root << 32) | index as u64 }
fn callback_root(argument: u64) -> u64 { argument >> 32 }
fn callback_index(argument: u64) -> usize { argument as u32 as usize }

#[derive(Clone, Copy)]
struct PendingCreate { token: u64, hwnd: u64, wndproc: u64, params: CreateStructArgs, convention: CreateReturnConvention }
struct GuiEntry { group: Weak<sched::thread_group::ThreadGroup>, state: ipc::win32_window::WindowManager, menus: ipc::win32_menu::MenuManager, accelerators: ipc::win32_accel::AcceleratorTables, wait: Arc<sched::live::WaitList>, foreground: bool, next_create: u64, pending_creates: Vec<PendingCreate>, pending_positions: Vec<position::PendingPosition>, remote_positions: Vec<position::RemotePosition>, retrievals: Vec<retrieval::Retrieval>, sent: send::Queue, redraw: redraw::Queue, scroll_pending: scroll::pending::Queue, paint_callbacks: paint_callbacks::Queue }
static GUI: Spinlock<Vec<GuiEntry>, GuiLockClass> = Spinlock::new(Vec::new());
#[cfg(target_os = "oxide-kernel")]
static USER_ATOMS: Spinlock<ipc::win32_window::UserAtomTable, GuiLockClass> = Spinlock::new(ipc::win32_window::UserAtomTable::new());
static USER_SETTINGS: Spinlock<ipc::win32_window::UserSettings, GuiLockClass> = Spinlock::new(ipc::win32_window::UserSettings::new());
#[cfg(target_os = "oxide-kernel")]
static CLIPBOARD: Spinlock<ipc::win32_window::ClipboardManager, GuiLockClass> = Spinlock::new(ipc::win32_window::ClipboardManager::new());

/// Register one system-wide message name in the canonical user atom table.
/// # C: O(N_user_atoms * N_name)
#[cfg(target_os = "oxide-kernel")]
pub fn register_window_message_for_current(name: &[u16]) -> Option<u16> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    USER_ATOMS.lock().register(name)
}

/// Admit the raw Wine `OpenClipboard` operation against the shared
/// window-station owner. # C: O(N_process_gui_states + N_windows)
#[cfg(target_os = "oxide-kernel")]
pub fn open_clipboard_for_current(hwnd: u64) -> bool {
    let Some(cur) = sched::live::current() else { return false; };
    if !cur.is_nt_personality() || hwnd > u32::MAX as u64 { return false; }
    let window = if hwnd == 0 { None } else {
        let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return false; };
        let mut entries = GUI.lock();
        entries.retain(|entry| entry.group.upgrade().is_some());
        if !entries.iter().any(|entry| entry.state.get(window).is_some()) { return false; }
        Some(window)
    };
    CLIPBOARD.lock().open(cur.tid as u64, window)
}

/// Release the shared clipboard lock from its opening thread. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn close_clipboard_for_current() -> bool {
    let Some(cur) = sched::live::current() else { return false; };
    if !cur.is_nt_personality() { return false; }
    CLIPBOARD.lock().close(cur.tid as u64)
}

/// Resolve a visible window rectangle from the current NT process's canonical HWND state. # C: O(N_process_gui_states + N_windows)
pub fn window_rect_for_current(hwnd: u32) -> Option<(ipc::win32_window::WindowRect, bool)> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let group = Arc::clone(&cur.thread_group);
    let window = ipc::win32_window::WindowId::from_raw(hwnd)?;
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    let state = &entries[index].state;
    let record = state.get(window)?;
    Some((state.rect(window)?, record.visible))
}

/// Placement reads only the canonical record and rectangle. # C: O(processes + windows)
pub(crate) fn placement_context_for_current(hwnd: u64) -> Option<crate::nt_wine_window::placement::Context> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let id = ipc::win32_window::WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
    let entries = GUI.lock();
    let entry = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    let record = entry.state.get(id)?;
    Some(crate::nt_wine_window::placement::Context {
        rect: entry.state.rect(id)?, style: record.style, ex_style: record.ex_style,
    })
}

// Never hold the GUI lock while consulting the independent transport owner.
// GNOME-bound processes receive translated desktop events instead of stealing
// the underlying physical events from Mutter's input path.
fn desktop_owns_physical_input() -> bool {
    let group = {
        let entries = GUI.lock();
        entries.iter().find(|entry| entry.foreground).and_then(|entry| entry.group.upgrade())
    };
    group.is_some_and(|group| crate::nt_compositor::monitors(&group).is_some())
}

/// Route one accepted physical key transition to the desktop foreground NT window. # C: O(N_nt_processes + N_windows)
pub fn route_hardware_key(key: u16, pressed: bool, repeat: bool) -> bool {
    if desktop_owns_physical_input() { return false; }
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(entry) = entries.iter_mut().find(|entry| entry.foreground) else { return false; };
    match entry.state.post_focused_key(key, pressed, repeat) {
        Ok(()) => { entry.wait.wake_all(); true }
        Err(ipc::win32_window::WindowError::QueueFull) => {
            klog::kwarn!("nt input: foreground window queue full");
            true
        }
        Err(_) => false,
    }
}

/// Route one accepted relative pointer transition to the desktop foreground
/// window through its canonical message queue. # C: O(N_nt_processes + N_windows)
pub fn route_hardware_rel(code: u16, value: i32) -> bool {
    if desktop_owns_physical_input() { return false; }
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(entry) = entries.iter_mut().find(|entry| entry.foreground) else { return false; };
    match entry.state.post_focused_mouse(code, value) {
        Ok(()) => { entry.wait.wake_all(); true }
        Err(ipc::win32_window::WindowError::QueueFull) => {
            klog::kwarn!("nt input: foreground window queue full");
            true
        }
        Err(_) => false,
    }
}

/// Route one accepted physical pointer transition through the canonical GUI owner. # C: O(N_nt_processes + N_windows)
pub fn route_hardware_mouse(ev_type: u16, code: u16, value: i32) -> bool {
    if desktop_owns_physical_input() { return false; }
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(entry) = entries.iter_mut().find(|entry| entry.foreground) else { return false; };
    match entry.state.post_hardware_mouse(ev_type, code, value) {
        Ok(()) => { entry.wait.wake_all(); true }
        Err(ipc::win32_window::WindowError::QueueFull) => {
            klog::kwarn!("nt input: foreground window queue full");
            true
        }
        Err(_) => false,
    }
}

// Module manifest: dispatch routes canonical GUI operations; menu owns menu adapters.
#[path = "nt_window/dispatch.rs"]
mod dispatch;
pub use dispatch::dispatch;

#[cfg(target_os = "oxide-kernel")]
fn destroy_window_for_current(hwnd: u64) {
    let Some(cur) = sched::live::current() else { return; };
    if !cur.is_nt_personality() || hwnd > u32::MAX as u64 { return; }
    let group = Arc::clone(&cur.thread_group);
    let (cleanup, atoms, paint_dcs) = {
        let mut entries = GUI.lock();
        entries.retain(|entry| entry.group.upgrade().is_some());
        let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return; };
        let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return; };
        let windows = entries[index].state.destruction_order(window).unwrap_or_default();
        let paint_dcs = windows.iter().filter_map(|window| entries[index].state.paint_session(*window).ok().map(|session| session.dc).filter(|dc| *dc != 0 && !entries[index].paint_callbacks.holds_dc(*dc))).collect::<Vec<_>>();
        let Ok((_, atoms)) = entries[index].state.destroy_with_property_atoms(window) else { return; };
        for window in &windows { entries[index].paint_callbacks.cancel_window(window.raw() as u64); }
        for window in &windows { entries[index].redraw.cancel_window(*window); }
        for window in &windows { entries[index].scroll_pending.cancel_root(window.raw() as u64); }
        (windows.into_iter().map(|window| window.raw()).collect::<Vec<_>>(), atoms, paint_dcs)
    };
    { let mut owner = USER_ATOMS.lock(); for atom in atoms { owner.release_property_atom(atom); } }
    for dc in paint_dcs { let _ = crate::nt_gdi::delete_paint_dc_current(dc); }
    for hwnd in cleanup {
        paint_cleanup::window_for_current(hwnd as u64);
        send::cancel_window(&group, hwnd as u64);
        position::cancel_position_window(&group, hwnd as u64);
        let _ = bridge::publish_destroy_current(hwnd as u64);
        crate::nt_gdi::destroy_window_dc_for_current(hwnd);
    }
}

#[cfg(target_os = "oxide-kernel")]
fn destruction_order_for_current(hwnd: u64) -> Option<alloc::vec::Vec<u64>> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() || hwnd > u32::MAX as u64 { return None; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    Some(entries[index].state.destruction_order(ipc::win32_window::WindowId::from_raw(hwnd as u32)?)?.into_iter().map(|window| window.raw() as u64).collect())
}

#[cfg(not(target_os = "oxide-kernel"))]
fn destruction_order_for_current(_: u64) -> Option<alloc::vec::Vec<u64>> { None }

#[cfg(not(target_os = "oxide-kernel"))]
fn destroy_window_for_current(_: u64) {}

fn copy_message(destination: syscall::UserPtr<NtWindowMessage>, message: ipc::win32_window::WinMessage) -> Result<(), syscall::Errno> {
    let mut bytes = [0u8; core::mem::size_of::<NtWindowMessage>()];
    bytes[0..8].copy_from_slice(&(message.hwnd.map(|hwnd| hwnd.raw() as u64).unwrap_or(0)).to_le_bytes());
    bytes[8..12].copy_from_slice(&message.message.to_le_bytes());
    bytes[16..24].copy_from_slice(&message.wparam.to_le_bytes());
    bytes[24..32].copy_from_slice(&(message.lparam as u64).to_le_bytes());
    uaccess::copy_to_user(destination.as_u64(), &bytes)
}

fn valid_window(hwnd: u64) -> Option<ipc::win32_window::WindowId> {
    (hwnd <= u32::MAX as u64).then(|| ipc::win32_window::WindowId::from_raw(hwnd as u32)).flatten()
}

fn message_filter(state: &ipc::win32_window::WindowManager, hwnd: u64, first: u32, last: u32) -> Option<ipc::win32_window::MessageFilter> {
    if hwnd > u32::MAX as u64 { return None; }
    let hwnd = ipc::win32_window::WindowId::from_raw(hwnd as u32);
    if state.validate_message_filter(hwnd).is_err() { return None; }
    Some(ipc::win32_window::MessageFilter { hwnd, first, last })
}

fn copy_rect(destination: syscall::UserPtr<syscall::nt::NtWindowRect>, value: ipc::win32_window::WindowRect) -> u64 {
    let fields = [value.left.to_le_bytes(), value.top.to_le_bytes(), value.right.to_le_bytes(), value.bottom.to_le_bytes()];
    let mut bytes = [0u8; 16];
    for (index, field) in fields.iter().enumerate() { bytes[index * 4..index * 4 + 4].copy_from_slice(field); }
    if uaccess::copy_to_user(destination.as_u64(), &bytes).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}

fn read_rect(source: syscall::UserPtr<syscall::nt::NtWindowRect>) -> Option<ipc::win32_window::WindowRect> {
    let mut bytes = [0u8; 16];
    uaccess::copy_from_user(&mut bytes, source.as_u64()).ok()?;
    let field = |index: usize| i32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
    Some(ipc::win32_window::WindowRect { left: field(0), top: field(1), right: field(2), bottom: field(3) })
}

/// Register one Wine class in the same process-scoped window owner used by
/// direct native window calls. # C: O(N_process_gui_states + N_classes)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn register_class_for_current(name: &[u16], wndproc: u64) -> Option<u64> {
    register_class_with_extra_for_current(name, wndproc, 0)
}

/// # C: O(processes + classes); canonical storage is initialized before callbacks.
pub(crate) fn register_class_with_extra_for_current(name: &[u16], wndproc: u64, extra: i32) -> Option<u64> {
    register_class_with_encoding_for_current(name, wndproc, extra, true)
}

/// # C: O(processes + classes); destination encoding follows the registered procedure.
pub(crate) fn register_class_with_encoding_for_current(name: &[u16], wndproc: u64, extra: i32, unicode: bool) -> Option<u64> {
    register_class_with_style_for_current(name, wndproc, extra, unicode, 0)
}

/// # C: O(processes + classes); raw class flags enter the canonical class owner.
pub(crate) fn register_class_with_style_for_current(name: &[u16], wndproc: u64, extra: i32, unicode: bool, style: u32) -> Option<u64> {
    register_class_with_background_for_current(name, wndproc, extra, unicode, style, 0)
}

/// Unregister one process-local Wine class through the canonical owner.
/// # C: O(N_process_gui_states + N_classes + N_windows)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn unregister_class_for_current(name: &[u16]) -> bool {
    let Some(cur) = sched::live::current() else { return false; };
    if !cur.is_nt_personality() { return false; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return false; };
    entries[index].state.unregister_class(name).is_ok()
}

#[path = "nt_window/menu.rs"]
mod menu;
pub(crate) use menu::*;

/// Create a Wine window by resolving its registered class in the canonical
/// process window owner. # C: O(N_process_gui_states + N_classes + N_windows)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn create_class_window_for_current(name: &[u16], parent: u64) -> Option<u64> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() || parent > u32::MAX as u64 { return None; }
    let parent = if parent == 0 { None } else { Some(ipc::win32_window::WindowId::from_raw(parent as u32)?) };
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| {
            entries.push(new_entry(&group));
            entries.len() - 1
        });
    entries[index].state.create_class(cur.tid as u64, parent, name).ok().map(|window| window.raw() as u64)
}

/// Create a Wine window after resolving an integer-resource class atom in the
/// canonical process window owner. # C: O(N_process_gui_states + N_classes + N_windows)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn create_class_window_by_atom_for_current(atom: u16, parent: u64) -> Option<u64> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() || parent > u32::MAX as u64 { return None; }
    let parent = if parent == 0 { None } else { Some(ipc::win32_window::WindowId::from_raw(parent as u32)?) };
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| {
            entries.push(new_entry(&group));
            entries.len() - 1
        });
    entries[index].state.create_class_atom(cur.tid as u64, parent, atom).ok().map(|window| window.raw() as u64)
}

/// Read the registered class name associated with one canonical HWND.
/// # C: O(N_process_gui_states + N_windows + N_classes)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn window_class_name_for_current(hwnd: u64) -> Option<Vec<u16>> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() || hwnd > u32::MAX as u64 { return None; }
    let window = ipc::win32_window::WindowId::from_raw(hwnd as u32)?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    entries[index].state.class_name(window).map(|name| name.to_vec())
}

/// Resolve canonical class metadata for Wine's class-information query.
/// # C: O(N_process_gui_states + N_classes)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn class_info_for_current(name: &[u16]) -> Option<(u16, u64, Vec<u16>, u32)> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    let (atom, wndproc, class_name) = entries[index].state.class_info(name)?;
    Some((atom, wndproc, class_name.to_vec(), entries[index].state.class_extra_by_atom(atom)?))
}

/// Resolve canonical class metadata for an integer-resource class atom.
/// # C: O(N_process_gui_states + N_classes)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn class_info_by_atom_for_current(atom: u16) -> Option<(u16, u64, Vec<u16>, u32)> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    let (atom, wndproc, class_name) = entries[index].state.class_info_by_atom(atom)?;
    Some((atom, wndproc, class_name.to_vec(), entries[index].state.class_extra_by_atom(atom)?))
}

/// Replace text while keeping the mutation inside the canonical window owner.
/// # C: O(N_process_gui_states + N_windows + N_text)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn set_window_text_for_current(hwnd: u64, text: &[u16]) -> Result<(), ()> {
    let cur = sched::live::current().ok_or(())?;
    if !cur.is_nt_personality() || hwnd > u32::MAX as u64 { return Err(()); }
    let window = ipc::win32_window::WindowId::from_raw(hwnd as u32).ok_or(())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))).ok_or(())?;
    entries[index].state.set_text(window, text).map_err(|_| ())
}

/// Return the canonical UTF-16 text length for one HWND. # C: O(N_process_gui_states + N_windows)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn window_text_length_for_current(hwnd: u64) -> Option<u64> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() || hwnd > u32::MAX as u64 { return None; }
    let window = ipc::win32_window::WindowId::from_raw(hwnd as u32)?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    Some(entries[index].state.text(window)?.len() as u64)
}

/// Resolve the WndProc stored in the current process's canonical HWND state.
/// # C: O(N_process_gui_states + N_windows)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn window_wndproc_for_current(hwnd: u64) -> Option<u64> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() || hwnd > u32::MAX as u64 { return None; }
    let group = Arc::clone(&cur.thread_group);
    let window = ipc::win32_window::WindowId::from_raw(hwnd as u32)?;
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    entries[index].state.get(window).map(|record| record.wndproc)
}
