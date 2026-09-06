use alloc::vec::Vec;
use ipc::win32_window::WindowRect;
use syscall::nt_compositor::Monitor;
use super::codec::*;

/// Adapter boundary; all persistent semantics belong to the canonical window owner.
pub(super) trait Owner {
    fn context(&mut self, hwnd: u64) -> Option<Context>;
    fn desktop(&mut self) -> Option<Vec<Monitor>>;
    fn startup_show(&mut self) -> Result<Option<u32>, ()>;
    fn set_rect(&mut self, hwnd: u64, rect: WindowRect) -> u64;
    fn show(&mut self, hwnd: u64, command: u32) -> u64;
    fn invalid_parameter(&mut self);
}

/// Bad pointers and truncated copies cannot reach window mutations. # C: O(1) + apply
pub(super) fn read_apply(owner: &mut impl Owner, hwnd: u64, pointer: u64,
    mut read: impl FnMut(&mut [u8], u64) -> bool) -> u64 {
    if pointer == 0 || pointer.checked_add(BYTES as u64).is_none() { return 0; }
    let mut bytes = [0; BYTES];
    if !read(&mut bytes, pointer) { return 0; }
    apply(owner, hwnd, &bytes)
}

/// Caller supplies length=44; no output is written for invalid length or HWND. # C: O(monitors)
pub(super) fn read_query(owner: &mut impl Owner, hwnd: u64, pointer: u64,
    mut read: impl FnMut(&mut [u8], u64) -> bool, mut write: impl FnMut(u64, &[u8]) -> bool) -> u64 {
    if pointer == 0 || pointer.checked_add(BYTES as u64).is_none() { return 0; }
    let mut length = [0; 4];
    if !read(&mut length, pointer) { return 0; }
    if u32::from_le_bytes(length) != BYTES as u32 { owner.invalid_parameter(); return 0; }
    let Some(bytes) = query(owner, hwnd) else { return 0; };
    u64::from(write(pointer, &bytes))
}

fn normal_state(context: Context) -> bool { context.style & (WS_MINIMIZE | WS_MAXIMIZE) == 0 }

/// Show's BOOL is previous visibility; NTSTATUS errors must never become TRUE. # C: O(1)
pub(super) fn show_result(result: u64) -> u64 { if result <= 1 { result } else { 0 } }

/// A default show resolves through startup parameters; maximize/minimize need canonical state. # C: O(1)
pub(super) fn normal_show(command: u32, startup: Option<u32>) -> Option<u32> {
    let command = if command == SW_SHOWDEFAULT { startup.unwrap_or(SW_SHOWNORMAL) } else { command };
    match command { SW_HIDE | SW_SHOWNORMAL | SW_SHOWNOACTIVATE | SW_SHOW | SW_SHOWNA | SW_RESTORE => Some(command), _ => None }
}

fn screen_rect(m: &Monitor) -> Option<WindowRect> {
    m.monitor.validate().ok()?; m.workarea.validate().ok()?;
    let r = m.workarea;
    Some(WindowRect { left: r.x, top: r.y, right: r.x.checked_add(r.width as i32)?, bottom: r.y.checked_add(r.height as i32)? })
}

fn select_monitor(rect: WindowRect, monitors: &[Monitor]) -> Option<&Monitor> {
    monitors.iter().filter(|m| screen_rect(m).is_some()).max_by_key(|m| {
        let r = m.monitor;
        let (left, top, right, bottom) = (r.x as i64, r.y as i64, r.x as i64+r.width as i64, r.y as i64+r.height as i64);
        let w = (right.min(rect.right as i64)-left.max(rect.left as i64)).max(0);
        let h = (bottom.min(rect.bottom as i64)-top.max(rect.top as i64)).max(0);
        let dx = (left-rect.right as i64).max(rect.left as i64-right).max(0) as i128;
        let dy = (top-rect.bottom as i64).max(rect.top as i64-bottom).max(0) as i128;
        (w*h, -(dx*dx+dy*dy))
    })
}

fn onscreen(mut rect: WindowRect, work: WindowRect) -> Option<WindowRect> {
    let width = rect.right.checked_sub(rect.left)?; let height = rect.bottom.checked_sub(rect.top)?;
    if rect.right <= work.left { rect.left = work.left; rect.right = work.left.checked_add(width)?; }
    else if rect.left >= work.right { rect.right = work.right; rect.left = work.right.checked_sub(width)?; }
    if rect.bottom <= work.top { rect.top = work.top; rect.bottom = work.top.checked_add(height)?; }
    else if rect.top >= work.bottom { rect.bottom = work.bottom; rect.top = work.bottom.checked_sub(height)?; }
    valid_rect(rect).then_some(rect)
}

/// All fallible decoding/context checks precede either canonical mutation. # C: O(monitors) + owner calls
pub(super) fn apply(owner: &mut impl Owner, hwnd: u64, bytes: &[u8]) -> u64 {
    let Some(placement) = Placement::decode(bytes) else { owner.invalid_parameter(); return 0; };
    let Some(context) = owner.context(hwnd) else { return 0; };
    if !normal_state(context) || placement.max != (-1, -1)
        || (placement.flags & WPF_SETMINPOSITION != 0 && placement.min != (-1, -1)) { return 0; }
    let startup = if placement.show == SW_SHOWDEFAULT { match owner.startup_show() { Ok(s) => s, Err(()) => return 0 } } else { None };
    let Some(show) = normal_show(placement.show, startup) else { return 0; };
    let Some(monitors) = owner.desktop() else { return 0; };
    let Some(monitor) = select_monitor(placement.normal, &monitors) else { return 0; };
    let Some(work) = screen_rect(monitor) else { return 0; };
    let Some(normal) = onscreen(placement.normal, work) else { return 0; };
    if owner.set_rect(hwnd, normal) != 0 { return 0; }
    u64::from(owner.show(hwnd, show) <= 1)
}

/// Get uses the canonical current normal rectangle, never a cached adapter placement. # C: O(monitors)
pub(super) fn query(owner: &mut impl Owner, hwnd: u64) -> Option<[u8; BYTES]> {
    let context = owner.context(hwnd)?;
    if !normal_state(context) || !valid_rect(context.rect) { return None; }
    let rect = context.rect;
    Some(Placement { flags: 0, show: SW_SHOWNORMAL, min: (-1,-1), max: (-1,-1), normal: rect }.encode())
}

/// Previous visibility remains FALSE for a successful first show. # C: O(1) + owner calls
pub(super) fn show(owner: &mut impl Owner, hwnd: u64, command: u32) -> u64 {
    let Some(context) = owner.context(hwnd) else { return 0; };
    if !normal_state(context) { return 0; }
    let startup = if command == SW_SHOWDEFAULT { match owner.startup_show() { Ok(s) => s, Err(()) => return 0 } } else { None };
    let Some(command) = normal_show(command, startup) else { return 0; };
    show_result(owner.show(hwnd, command))
}
