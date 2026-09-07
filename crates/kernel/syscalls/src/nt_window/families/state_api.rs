//! Window style, attribute, foreground and deferred-position access. The
//! window owner decides; this module resolves the caller.
use super::super::*;
use alloc::vec::Vec;
use ipc::win32_window::{DeferError, DeferredPosition, EnableOutcome, LayeredAttributes, WindowId, WindowRect};

fn id(hwnd: u64) -> Option<WindowId> { valid_window(hwnd) }

/// The one window holding the update lock, and the shell, program-manager and
/// task-manager windows the desktop names. Each is a single desktop-wide slot.
static UPDATE_LOCK: Spinlock<u32, GuiLockClass> = Spinlock::new(0);
static SHELL_WINDOWS: Spinlock<ShellWindows, GuiLockClass> = Spinlock::new(ShellWindows::new());

struct ShellWindows { shell: u32, list_view: u32, progman: u32, taskman: u32 }
impl ShellWindows { const fn new() -> Self { Self { shell: 0, list_view: 0, progman: 0, taskman: 0 } } }

/// AlterWindowStyle. # C: O(N_processes + N_windows)
pub(crate) fn alter_style_for_current(hwnd: u64, mask: u32, style: u32) -> bool {
    let Some(window) = id(hwnd) else { return false; };
    access::with_state_mut(|state| state.alter_style(window, mask, style)).unwrap_or(Ok(false)).unwrap_or(false)
}

/// EnableWindow. # C: O(N_processes + N_windows)
pub(crate) fn enable_window_for_current(hwnd: u64, enable: bool) -> Option<EnableOutcome> {
    let window = id(hwnd)?;
    access::with_state_mut(|state| state.enable_window(window, enable))?.ok()
}

/// Help context identifier. # C: O(N_processes + N_windows)
pub(crate) fn help_context_for_current(hwnd: u64) -> u32 {
    let Some(window) = id(hwnd) else { return 0; };
    access::with_state(|state| state.help_context(window)).unwrap_or(0)
}

/// Set the help context identifier. # C: O(N_processes + N_windows)
pub(crate) fn set_help_context_for_current(hwnd: u64, context: u32) -> bool {
    let Some(window) = id(hwnd) else { return false; };
    access::with_state_mut(|state| state.set_help_context(window, context)).is_some_and(|result| result.is_ok())
}

/// Layered appearance, present only once it has been set.
/// # C: O(N_processes + N_windows)
pub(crate) fn layered_attributes_for_current(hwnd: u64) -> Option<LayeredAttributes> {
    let window = id(hwnd)?;
    access::with_state(|state| state.layered_attributes(window))?
}

/// Set the layered appearance. # C: O(N_processes + N_windows)
pub(crate) fn set_layered_attributes_for_current(hwnd: u64, attributes: LayeredAttributes) -> bool {
    let Some(window) = id(hwnd) else { return false; };
    access::with_state_mut(|state| state.set_layered_attributes(window, attributes)).is_some_and(|result| result.is_ok())
}

/// Admit one per-pixel layered update. # C: O(N_processes + N_windows)
pub(crate) fn admit_layered_update_for_current(hwnd: u64, flags: u32, size: Option<(i32, i32)>) -> bool {
    let Some(window) = id(hwnd) else { return false; };
    access::with_state(|state| state.admit_layered_update(window, flags, size)).is_some_and(|result| result.is_ok())
}

/// Window region as a rectangle list. # C: O(N_processes + N_windows + N_rects)
pub(crate) fn window_region_for_current(hwnd: u64) -> Option<Vec<WindowRect>> {
    let window = id(hwnd)?;
    access::with_state(|state| state.window_region(window).map(|rects| rects.to_vec()))?
}

/// Install or clear the window region. # C: O(N_processes + N_windows + N_rects)
pub(crate) fn set_window_region_for_current(hwnd: u64, region: Option<&[WindowRect]>) -> bool {
    let Some(window) = id(hwnd) else { return false; };
    access::with_state_mut(|state| state.set_window_region(window, region)).is_some_and(|result| result.is_ok())
}

/// Whether the non-client area is drawn active, and the flip a flash applies.
/// # C: O(N_processes + N_windows)
pub(crate) fn nc_activated_for_current(hwnd: u64) -> bool {
    let Some(window) = id(hwnd) else { return false; };
    access::with_state(|state| state.nc_activated(window)).unwrap_or(false)
}

/// # C: O(N_processes + N_windows)
pub(crate) fn set_nc_activated_for_current(hwnd: u64, active: bool) -> bool {
    let Some(window) = id(hwnd) else { return false; };
    access::with_state_mut(|state| state.set_nc_activated(window, active)).is_some_and(|result| result.is_ok())
}

/// Display affinity; no window here is excluded from capture.
/// # C: O(N_processes + N_windows)
pub(crate) fn display_affinity_for_current(hwnd: u64) -> Option<u32> {
    let window = id(hwnd)?;
    access::with_state(|state| state.display_affinity(window))?.ok()
}

/// Title-bar element state derived from one window's styles.
/// # C: O(N_processes + N_windows + N_classes)
pub(crate) fn title_bar_state_for_current(hwnd: u64) -> Option<(WindowRect, [u32; ipc::win32_window::TITLE_BAR_ELEMENTS])> {
    let window = id(hwnd)?;
    access::with_state(|state| {
        let record = state.get(window)?;
        let class_style = state.position_class_style(window).unwrap_or(0);
        Some((state.rect(window)?, ipc::win32_window::title_bar_state(record.style, record.ex_style, class_style)))
    })?
}

/// Styles of one window, for the calls that report them. # C: O(N_processes + N_windows)
pub(crate) fn styles_for_current(hwnd: u64) -> Option<(u32, u32)> {
    let window = id(hwnd)?;
    access::with_state(|state| state.get(window).map(|record| (record.style, record.ex_style)))?
}

/// Foreground window of the desktop. # C: O(N_processes)
pub(crate) fn foreground_window() -> u64 {
    let entries = GUI.lock();
    entries.iter().find(|entry| entry.foreground)
        .and_then(|entry| entry.state.focused().or(entry.state.active_window()))
        .map_or(0, |window| window.raw() as u64)
}

/// Make one window's process the foreground one and activate the window.
/// # C: O(N_processes + N_windows)
pub(crate) fn set_foreground_window(hwnd: u64) -> bool {
    let Some(window) = id(hwnd) else { return false; };
    let tid = sched::live::current().map_or(0, |task| task.tid as u64);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(index) = entries.iter().position(|entry| entry.state.get(window).is_some()) else { return false; };
    for (position, entry) in entries.iter_mut().enumerate() { entry.foreground = position == index; }
    entries[index].state.set_focus(tid, Some(window)).is_ok()
}

/// The windows a thread-information query reports for the calling thread.
/// # C: O(N_processes + N_windows)
pub(crate) fn gui_thread_info() -> Option<(Option<WindowId>, Option<WindowId>, Option<WindowId>, Option<WindowId>, WindowRect)> {
    access::with_state(|state| {
        let caret = state.caret_placement();
        (state.active_window(), state.focused(), state.capture_window(), caret.map(|(hwnd, _)| hwnd),
            caret.map_or(WindowRect { left: 0, top: 0, right: 0, bottom: 0 }, |(_, rect)| rect))
    })
}

/// Take or release the single window-update lock, answering whether the
/// request was granted. Releasing always succeeds. # C: O(1)
pub(crate) fn lock_window_update(hwnd: u64) -> bool {
    let mut lock = UPDATE_LOCK.lock();
    if hwnd == 0 { *lock = 0; return true; }
    let Some(window) = id(hwnd) else { return false; };
    if *lock != 0 { return false; }
    *lock = window.raw();
    true
}

/// Install the shell window pair. It is refused once one is installed, and for
/// a topmost window. # C: O(N_processes + N_windows)
pub(crate) fn set_shell_window(shell: u64, list_view: u64) -> bool {
    let Some(shell_id) = id(shell) else { return false; };
    if SHELL_WINDOWS.lock().shell != 0 { return false; }
    let topmost = |hwnd: u64| styles_for_current(hwnd)
        .is_some_and(|(_, ex_style)| ex_style & ipc::win32_window::styles::WS_EX_TOPMOST != 0);
    if topmost(shell) { return false; }
    if list_view != shell && list_view != 0 && topmost(list_view) { return false; }
    let mut windows = SHELL_WINDOWS.lock();
    windows.shell = shell_id.raw();
    windows.list_view = id(list_view).map_or(0, |window| window.raw());
    true
}

/// Install the program-manager window, answering it back. # C: O(1)
pub(crate) fn set_progman_window(hwnd: u64) -> u64 {
    let Some(window) = id(hwnd) else { return 0; };
    SHELL_WINDOWS.lock().progman = window.raw();
    hwnd
}

/// Install the task-manager window, answering it back. # C: O(1)
pub(crate) fn set_taskman_window(hwnd: u64) -> u64 {
    let Some(window) = id(hwnd) else { return 0; };
    SHELL_WINDOWS.lock().taskman = window.raw();
    hwnd
}

/// Open one deferred-position batch. # C: O(N_processes)
pub(crate) fn begin_defer_for_current(count: i32) -> Result<u32, DeferError> {
    access::with_defer_mut(|batches| batches.begin(count)).unwrap_or(Err(DeferError::InvalidParameter))
}

/// Add one move to a batch. # C: O(N_processes + N_entries)
pub(crate) fn defer_for_current(handle: u32, position: DeferredPosition) -> Result<(), DeferError> {
    access::with_defer_mut(|batches| batches.defer(handle, position)).unwrap_or(Err(DeferError::InvalidHandle))
}

/// Close one batch and answer its moves. # C: O(N_processes)
pub(crate) fn end_defer_for_current(handle: u32) -> Result<Vec<DeferredPosition>, DeferError> {
    access::with_defer_mut(|batches| batches.end(handle)).unwrap_or(Err(DeferError::InvalidHandle))
}

/// Whether one window belongs to a live NT process. # C: O(N_processes + N_windows)
pub(crate) fn window_is_live(hwnd: u64) -> bool {
    id(hwnd).is_some_and(access::window_exists)
}

/// Report an error the caller reads back from its thread environment block.
/// # C: O(1)
pub(crate) fn report_last_error(error: u32) {
    let Some(task) = sched::live::current().filter(|task| task.is_nt_personality()) else { return; };
    let teb = task.nt_teb();
    if teb == 0 { return; }
    if let Some(address) = teb.checked_add(TEB_LAST_ERROR_OFFSET) { let _ = uaccess::put_user_u32(address, error); }
}

const TEB_LAST_ERROR_OFFSET: u64 = 0x68;
