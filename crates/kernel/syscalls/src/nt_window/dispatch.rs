use super::*;
#[path="mouse_activate.rs"] mod mouse_activate;
#[path="set_cursor.rs"] mod set_cursor;
#[path="retrieval_status.rs"] mod retrieval_status;

const WM_NCPAINT: u32 = 0x0085;
const WM_NCCALCSIZE: u32 = 0x0083;

/// Dispatch one GUI call against the current NT process. `None` means this is
/// not a window service and lets the main NT dispatcher continue its ladder.
/// # C: O(N_process_gui_states + N_windows + N_wakeups)
pub fn dispatch(call: NtCall) -> Option<u64> {
    dispatch_mode(call, false)
}

pub(super) fn dispatch_mode(call: NtCall, raw: bool) -> Option<u64> {
    let operation = nt::decode_window(call).ok()?;
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    if let NtWindowCall::DefaultProc { hwnd, message, wparam, lparam } = operation {
        if message == ipc::win32_window::WM_SETCURSOR { return Some(set_cursor::for_current(hwnd, wparam, lparam)); }
        if message == ipc::win32_window::hardware::WM_MOUSEACTIVATE { return Some(mouse_activate::for_current(hwnd, wparam, lparam)); }
        if let Some(result) = control_color::for_current(message, wparam) { return Some(result); }
        if let Some(result) = erase_background::kernel::for_current(message, hwnd, wparam) { return Some(result); }
        if message == ipc::win32_window::WM_PAINT { return Some(default_paint::for_current(hwnd)); }
        // The menu bar owns its band of the nonclient area: its size, its
        // pixels, and the two entries into menu tracking.
        if message == WM_NCPAINT {
            // The frame the window draws for itself goes on before the bar:
            // the bar's band is inside it, and a bar drawn first is drawn
            // over by the frame that surrounds it.
            let _ = nonclient_frame::nc_paint_for_current(hwnd);
            // A launched run rewrote this thread's frame: the font backend
            // reads its payload out of the syscall return, so the redirect
            // status is what this nonclient message answers.
            if let Some(status) = menu_raw::bar::nc_paint_for_current(hwnd) { return Some(status); }
        }
        if message == WM_NCCALCSIZE {
            // The frame's own band comes off first and the menu bar's band
            // off what is left, which is the order the two are drawn in.
            let framed = nonclient_frame::nc_calc_size_for_current(hwnd, lparam as u64).is_some();
            if let Some(result) = menu_raw::bar::nc_calc_size_for_current(hwnd, lparam as u64) { return Some(result); }
            if framed { return Some(0); }
        }
        if message == ipc::win32_window::WM_NCHITTEST {
            if let Some(hit) = menu_raw::bar::hit_test_for_current(hwnd, lparam) { return Some(hit as i64 as u64); }
        }
        if let Some(result) = menu_raw::bar::default_proc_for_current(hwnd, message, wparam, lparam) { return Some(result); }
    }
    if let NtWindowCall::BeginPaint { hwnd, rect } = operation { return Some(paint::begin(hwnd, rect)); }
    if crate::nt_compositor::monitors_current().is_none() {
        input::set_native_key_hook(Some(route_hardware_key));
        input::set_native_rel_hook(Some(route_hardware_rel));
        input::set_native_mouse_hook(Some(route_hardware_mouse));
    }
    let group = Arc::clone(&cur.thread_group);
    loop {
        let mut scanned = 0;
        if matches!(operation, NtWindowCall::Peek { .. } | NtWindowCall::Get { .. }) {
            crate::nt_gdi::flush_pending_for_current(false);
            let _ = caret::blink::expire_for_current(timekeeper::monotonic_ns());
            if let Some(result) = retrieval::pump(call, raw) { return Some(result); }
            if let Some(result) = retrieval_status::acknowledge(&operation) { return Some(result); }
            // Activation, the cursor and the double click are decided here,
            // on the way out of the queue and inside the window procedure,
            // not by whatever posted the raw input.
            match hardware::process_for_current(call, raw, operation) {
                hardware::Stage::Pending(status) => return Some(status),
                hardware::Stage::Again | hardware::Stage::Next(_) => continue,
                hardware::Stage::Ready => {}
                hardware::Stage::Drained(mark) => scanned = mark,
                hardware::Stage::Prepared(selected) => {
                    let hardware::Selected { id, message } = *selected;
                    if let Some(status) = hardware::deliver_for_current(operation, id, message) { return Some(status); }
                    continue;
                }
            }
        }
        let (result, wake, sleep, cleanup, atoms, paint_dcs) = {
            let mut entries = GUI.lock();
            let index = owner::entry_index(&mut entries, &group);
            let wait = Arc::clone(&entries[index].wait);
            let state = &mut entries[index].state;
            let mut cleanup = Vec::new();
            let mut atoms = Vec::new();
            let mut paint_dcs = Vec::new();
            state.expire_timers(timekeeper::monotonic_ns());
            let outcome = match operation {
                NtWindowCall::DefaultProc { hwnd, message, wparam: _, lparam } => {
                    if hwnd > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
                    let result = match rect_query::default_proc_state(state, hwnd as u32, message, lparam) {
                        ipc::win32_window::DefaultWindowResult::Return(value) => value as u64,
                        // WM_PAINT is answered before this lock by the real
                        // BeginPaint/EndPaint sequence (default_paint).
                        ipc::win32_window::DefaultWindowResult::ValidatePaint => STATUS_SUCCESS,
                        ipc::win32_window::DefaultWindowResult::RequestDestroy => {
                            if hwnd != 0 {
                                let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return Some(STATUS_INVALID_HANDLE); };
                                let windows = state.destruction_order(window).unwrap_or_default();
                                paint_dcs.extend(windows.iter().filter_map(|window| state.paint_session(*window).ok().map(|session| session.dc).filter(|dc| *dc != 0)));
                                let Ok((_, released)) = state.destroy_with_property_atoms(window) else { return Some(STATUS_INVALID_HANDLE); };
                                atoms.extend(released);
                                cleanup.extend(windows.into_iter().rev().map(|window| window.raw()));
                            }
                            STATUS_SUCCESS
                        }
                    };
                    (Some(result), None, None)
                }
                NtWindowCall::Create { parent, wndproc } => {
                    if parent > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
                    // A top-level window names the desktop window as its
                    // parent, and the reference replaces that parent with
                    // none: the desktop belongs to no process, so a window
                    // parented to it is a window with no parent here.
                    let parent = if parent == 0 || ipc::win32_window::handle_space::is_server_handle(parent as u32) { None }
                        else { match ipc::win32_window::WindowId::from_raw(parent as u32) { Some(parent) => Some(parent), None => return Some(STATUS_INVALID_HANDLE) } };
                    let result = match state.create(cur.tid as u64, parent, wndproc) { Ok(window) => window.raw() as u64, Err(_) => STATUS_INVALID_PARAMETER };
                    state.note_queue_access(cur.tid as u64, timekeeper::monotonic_ns());
                    (Some(result), None, None)
                }
                NtWindowCall::Destroy { hwnd } => {
                    if hwnd > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
                    let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return Some(STATUS_INVALID_HANDLE); };
                    if let Some(record) = state.get(window) {
                        if record.wndproc != 0 {
                            let reserved = match state.begin_destroy(cur.tid as u64, window) {
                                Ok(value) => value,
                                Err(ipc::win32_window::WindowError::WrongThread) => return Some(STATUS_ACCESS_DENIED),
                                Err(_) => return Some(STATUS_INVALID_HANDLE),
                            };
                            if !reserved { return Some(STATUS_SUCCESS); }
                            let callback = crate::nt_rtl::begin_wndproc_callback_with_completion(hwnd, WM_DESTROY, 0, 0, record.wndproc, sched::nt_callback::Completion { kind: CALLBACK_DESTROY, argument: callback_argument(hwnd, 0) });
                            if callback == STATUS_PENDING { return Some(callback); }
                            state.cancel_destroy(window);
                            if callback != STATUS_NOT_SUPPORTED { return Some(STATUS_INVALID_HANDLE); }
                        }
                    }
                    let windows = state.destruction_order(window).unwrap_or_default();
                    paint_dcs.extend(windows.iter().filter_map(|window| state.paint_session(*window).ok().map(|session| session.dc).filter(|dc| *dc != 0)));
                    let result = match state.destroy_with_property_atoms(window) {
                        Ok((_, released)) => { atoms.extend(released); cleanup.extend(windows.into_iter().rev().map(|window| window.raw())); STATUS_SUCCESS },
                        Err(_) => STATUS_INVALID_HANDLE,
                    };
                    (Some(result), None, None)
                }
                NtWindowCall::Post { hwnd, message, wparam, lparam } => {
                    if hwnd > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
                    let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return Some(STATUS_INVALID_HANDLE); };
                    let result = match state.post_to_window(window, ipc::win32_window::WinMessage { hwnd: Some(window), message, wparam, lparam }) { Ok(()) => STATUS_SUCCESS, Err(ipc::win32_window::WindowError::QueueFull) => STATUS_QUOTA_EXCEEDED, Err(_) => STATUS_INVALID_HANDLE };
                    (Some(result), Some(wait), None)
                }
                NtWindowCall::Peek { message, hwnd, first, last, remove } => {
                    let Some(filter) = message_filter(state, hwnd, first, last) else { return Some(STATUS_INVALID_HANDLE); };
                    state.note_queue_access(cur.tid as u64, timekeeper::monotonic_ns());
                    if let Some(found) = state.peek_posted_for_thread(cur.tid as u64, filter, false) {
                        if copy_message(message, found).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                        if remove != 0 { let _ = state.peek_posted_for_thread(cur.tid as u64, filter, true); }
                        (Some(STATUS_SUCCESS), None, None)
                    } else { (Some(STATUS_NO_MORE_ENTRIES), None, None) }
                }
                NtWindowCall::Get { message, hwnd, first, last } => {
                    let Some(filter) = message_filter(state, hwnd, first, last) else { return Some(STATUS_INVALID_HANDLE); };
                    state.note_queue_access(cur.tid as u64, timekeeper::monotonic_ns());
                    match state.take_posted_for_thread(cur.tid as u64, filter) {
                        ipc::win32_window::QueueResult::Message(found) => {
                            // Which message a pump is handed decides everything
                            // downstream: an application that never receives
                            // WM_PAINT never calls BeginPaint and never draws,
                            // which is indistinguishable from one that received
                            // it and ignored it.
                            hardware::note_get(found);
                            if copy_message(message, found).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                            (Some(STATUS_SUCCESS), None, None)
                        }
                        ipc::win32_window::QueueResult::Quit(code) => {
                            if copy_message(message, ipc::win32_window::WinMessage { hwnd: None, message: ipc::win32_window::WM_QUIT, wparam: code as u64, lparam: 0 }).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                            (Some(0), None, None)
                        }
                        ipc::win32_window::QueueResult::Empty => {
                            // A drained queue that still owes a paint means the
                            // damage exists but the paint selection rejected it,
                            // which no other trace can tell from no damage at all.
                            trace_idle(state, cur.tid as u64);
                            (None, None, Some((wait, filter)))
                        }
                    }
                }
                NtWindowCall::PostQuit { code } => {
                    state.post_quit(cur.tid as u64, code);
                    (Some(STATUS_SUCCESS), Some(wait), None)
                }
                NtWindowCall::SetFocus { hwnd } => {
                    if hwnd > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
                    let window = if hwnd == 0 { None } else {
                        let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return Some(STATUS_INVALID_HANDLE); };
                        Some(window)
                    };
                    let result = match state.set_focus(cur.tid as u64, window) {
                        Ok(previous) => previous.map_or(0, |value| value.raw() as u64),
                        Err(ipc::win32_window::WindowError::WrongThread) => STATUS_INVALID_PARAMETER,
                        Err(_) => STATUS_INVALID_HANDLE,
                    };
                    if result != STATUS_INVALID_HANDLE && result != STATUS_INVALID_PARAMETER {
                        for (entry_index, entry) in entries.iter_mut().enumerate() { entry.foreground = entry_index == index && window.is_some(); }
                    }
                    (Some(result), None, None)
                }
                NtWindowCall::InjectKey { key, pressed, repeat } => {
                    if pressed > 1 || repeat > 1 { return Some(STATUS_INVALID_PARAMETER); }
                    let result = match state.post_key(cur.tid as u64, key, pressed != 0, repeat != 0) {
                        Ok(()) => STATUS_SUCCESS,
                        Err(ipc::win32_window::WindowError::NoFocus) => STATUS_INVALID_HANDLE,
                        Err(ipc::win32_window::WindowError::WrongThread) => STATUS_INVALID_PARAMETER,
                        Err(ipc::win32_window::WindowError::QueueFull) => STATUS_QUOTA_EXCEEDED,
                        Err(_) => STATUS_INVALID_HANDLE,
                    };
                    (Some(result), Some(wait), None)
                }
                NtWindowCall::SetTimer { hwnd, id, timeout_ms, proc } => {
                    if hwnd > u32::MAX as u64 || id == 0 { return Some(STATUS_INVALID_PARAMETER); }
                    let window = if hwnd == 0 { None } else { Some(match ipc::win32_window::WindowId::from_raw(hwnd as u32) { Some(window) => window, None => return Some(STATUS_INVALID_HANDLE) }) };
                    let result = match state.set_timer(cur.tid as u64, window, ipc::win32_window::WM_TIMER, id, timeout_ms, proc, timekeeper::monotonic_ns()) {
                        Ok(value) => value,
                        Err(_) => STATUS_INVALID_HANDLE,
                    };
                    (Some(result), None, None)
                }
                NtWindowCall::KillTimer { hwnd, id } => {
                    if hwnd > u32::MAX as u64 || id == 0 { return Some(STATUS_INVALID_PARAMETER); }
                    let window = if hwnd == 0 { None } else { Some(match ipc::win32_window::WindowId::from_raw(hwnd as u32) { Some(window) => window, None => return Some(STATUS_INVALID_HANDLE) }) };
                    (Some(state.kill_timer(window, ipc::win32_window::WM_TIMER, id) as u64), None, None)
                }
                NtWindowCall::GetRect { hwnd, rect } => {
                    let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return Some(STATUS_INVALID_HANDLE); };
                    let Some(value) = state.rect(window) else { return Some(STATUS_INVALID_HANDLE); };
                    let native = [value.left.to_le_bytes(), value.top.to_le_bytes(), value.right.to_le_bytes(), value.bottom.to_le_bytes()];
                    let mut bytes = [0u8; 16];
                    for (index, field) in native.iter().enumerate() { bytes[index * 4..index * 4 + 4].copy_from_slice(field); }
                    if uaccess::copy_to_user(rect.as_u64(), &bytes).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                    (Some(STATUS_SUCCESS), None, None)
                }
                NtWindowCall::SetRect { hwnd, rect } => {
                    let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return Some(STATUS_INVALID_HANDLE); };
                    let mut bytes = [0u8; 16];
                    if uaccess::copy_from_user(&mut bytes, rect.as_u64()).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                    let field = |index: usize| i32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
                    let value = ipc::win32_window::WindowRect { left: field(0), top: field(1), right: field(2), bottom: field(3) };
                    (Some(match state.set_rect(window, value) { Ok(()) => STATUS_SUCCESS, Err(_) => STATUS_INVALID_HANDLE }), None, None)
                }
                NtWindowCall::SetRectValues { hwnd, left, top, right, bottom } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    let value = ipc::win32_window::WindowRect { left, top, right, bottom };
                    (Some(match state.set_rect(window, value) { Ok(()) => STATUS_SUCCESS, Err(_) => STATUS_INVALID_HANDLE }), None, None)
                }
                NtWindowCall::GetText { hwnd, text, count } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    let Some(value) = state.text(window) else { return Some(STATUS_INVALID_HANDLE); };
                    let limit = count.saturating_sub(1) as usize;
                    let copied = value.len().min(limit);
                    for (index, unit) in value.iter().take(copied).enumerate() {
                        let bytes = unit.to_le_bytes();
                        let Some(address) = text.as_u64().checked_add(index as u64 * 2) else { return Some(STATUS_INVALID_PARAMETER); };
                        if uaccess::copy_to_user(address, &bytes).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                    }
                    if count != 0 {
                        let address = text.as_u64().checked_add(copied as u64 * 2).unwrap_or(0);
                        if address == 0 || uaccess::copy_to_user(address, &[0, 0]).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                    }
                    (Some(copied as u64), None, None)
                }
                NtWindowCall::SetText { hwnd, text } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    let mut value = alloc::vec::Vec::new();
                    let mut terminated = false;
                    for index in 0..=u16::MAX as usize {
                        let Some(address) = text.as_u64().checked_add(index as u64 * 2) else { return Some(STATUS_INVALID_PARAMETER); };
                        let mut bytes = [0u8; 2];
                        if uaccess::copy_from_user(&mut bytes, address).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                        let unit = u16::from_le_bytes(bytes);
                        if unit == 0 { terminated = true; break; }
                        value.push(unit);
                    }
                    if !terminated || state.set_text(window, &value).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                    (Some(STATUS_SUCCESS), None, None)
                }
                NtWindowCall::GetClientRect { hwnd, rect } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    let Some(value) = state.client_rect(window) else { return Some(STATUS_INVALID_HANDLE); };
                    (Some(copy_rect(rect, value)), None, None)
                }
                NtWindowCall::GetParent { hwnd } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    let Some(record) = state.get(window) else { return Some(STATUS_INVALID_HANDLE); };
                    (Some(record.parent.map(|parent| parent.raw() as u64).unwrap_or(0)), None, None)
                }
                NtWindowCall::Show { hwnd, command } => {
                    // An application that has created its windows and entered
                    // its message loop shows nothing until this runs, so
                    // whether it is reached at all is the first question when
                    // no window appears.
                    klog::write_raw(b"[WINDOWS-WINDOW-SHOW] hwnd=");
                    klog::write_hex_u64(hwnd);
                    klog::write_raw(b" command=");
                    klog::write_hex_u64(command as u64);
                    klog::write_raw(b"\n");
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    let Some(visible) = crate::nt_window_policy::show_command_visibility(command as u64) else { return Some(state.get(window).map(|record| record.visible as u64).unwrap_or(STATUS_INVALID_HANDLE)); };
                    let shown = state.show(cur.tid as u64, window, visible);
                    // Showing a window with real geometry must leave it needing
                    // paint; the hosted model does exactly that. Report what the
                    // live state actually holds, so a window that shows and
                    // never paints says whether it had geometry to damage.
                    klog::write_raw(b"[WINDOWS-WINDOW-SHOW] result-rect=");
                    match state.client_rect(window) {
                        Some(rect) => { klog::write_hex_u64(rect.right as u64); klog::write_raw(b"x"); klog::write_hex_u64(rect.bottom as u64); }
                        None => klog::write_raw(b"none"),
                    }
                    klog::write_raw(b" pending-paint=");
                    klog::write_hex_u64(matches!(state.next_pending_paint(window, None, ipc::win32_window::PaintChildren::All), Ok(Some(_))) as u64);
                    klog::write_raw(b"\n");
                    (Some(match shown {
                        Ok(previous) => {
                            if let Some(wparam) = crate::nt_window_policy::visibility_transition_message(previous, visible) {
                                match state.post_to_window(window, ipc::win32_window::WinMessage { hwnd: Some(window), message: crate::nt_window_policy::WM_SHOWWINDOW, wparam, lparam: 0 }) {
                                    Ok(()) => previous as u64,
                                    Err(ipc::win32_window::WindowError::QueueFull) => STATUS_QUOTA_EXCEEDED,
                                    Err(_) => STATUS_INVALID_HANDLE,
                                }
                            } else { previous as u64 }
                        }
                        Err(ipc::win32_window::WindowError::WrongThread) => STATUS_INVALID_PARAMETER,
                        Err(_) => STATUS_INVALID_HANDLE,
                    }), None, None)
                }
                NtWindowCall::Invalidate { hwnd, rect } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    let requested = rect.and_then(|pointer| read_rect(pointer));
                    if rect.is_some() && requested.is_none() { return Some(STATUS_INVALID_PARAMETER); }
                    (Some(match state.invalidate(window, requested) { Ok(()) => STATUS_SUCCESS, Err(_) => STATUS_INVALID_HANDLE }), None, None)
                }
                NtWindowCall::BeginPaint { hwnd, rect } => {
                    let _ = (hwnd, rect);
                    return Some(STATUS_INVALID_PARAMETER);
                }
                NtWindowCall::EndPaint { hwnd } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    (Some(match state.end_paint(window) { Ok(()) => STATUS_SUCCESS, Err(_) => STATUS_INVALID_HANDLE }), None, None)
                }
            };
            for hwnd in &cleanup { if let Some(window) = ipc::win32_window::WindowId::from_raw(*hwnd) { entries[index].redraw.cancel_window(window); } }
            for hwnd in &cleanup { entries[index].scroll_pending.cancel_root(*hwnd as u64); }
            for hwnd in &cleanup { entries[index].paint_callbacks.cancel_window(*hwnd as u64); }
            paint_dcs.retain(|dc| !entries[index].paint_callbacks.holds_dc(*dc));
            (outcome.0, outcome.1, outcome.2, cleanup, atoms, paint_dcs)
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
        if let (NtWindowCall::Create { parent, .. }, Some(&hwnd)) = (&operation, result.as_ref()) {
            if hwnd != STATUS_INVALID_PARAMETER && hwnd != STATUS_INVALID_HANDLE && hwnd != STATUS_PENDING {
                return Some(create::begin_create_lifecycle_for_current(hwnd, CreateStructArgs::empty(*parent), CreateReturnConvention::NativeStatus));
            }
        }
        if let Some(wait) = wake { wait.wake_all(); }
        if result.is_some_and(|status| status <= 1) {
            let published = match operation {
                // A show is not only a visibility change: the reference
                // finishes it by placing the window at the top of its band and
                // activating it, and `result` is the visibility it replaced.
                NtWindowCall::Show { hwnd, command } => show_order::publish_for_current(hwnd, command as u64, result == Some(1)),
                NtWindowCall::SetText { hwnd, .. } => bridge::publish_title_current(hwnd),
                NtWindowCall::SetRect { hwnd, .. } | NtWindowCall::SetRectValues { hwnd, .. } => bridge::publish_geometry_current(hwnd),
                _ => Ok(()),
            };
            if published.is_err() { return Some(STATUS_INVALID_PARAMETER); }
        }
        if matches!(operation, NtWindowCall::Peek { .. }) && result == Some(STATUS_NO_MORE_ENTRIES) {
            crate::nt_gdi::flush_pending_for_current(true);
        }
        if let Some(result) = result { return Some(result); }
        let Some((wait, filter)) = sleep else { return Some(STATUS_NO_MORE_ENTRIES); };
        crate::nt_gdi::flush_pending_for_current(true);
        let deadline = caret::blink::retrieval_deadline_for_current().unwrap_or(0);
        // SAFETY: GUI snapshots are released before dispatch parks on the owned process wait list.
        let outcome = unsafe { sched::live::wait_event_interruptible_until(&wait, deadline, timekeeper::monotonic_ns, || {
            let mut entries = GUI.lock();
            entries.retain(|entry| entry.group.upgrade().is_some());
            entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
                .is_some_and(|entry| {
                    entry.remote_positions.iter().any(|work| work.targets(cur.tid as u64))
                        || entry.sent.has_for_tid(cur.tid as u64)
                        || entry.state.has_message_since(cur.tid as u64, filter, Some(scanned))
                        || entry.state.quit_pending(cur.tid as u64)
                })
        }) };
        if outcome == sched::task::WaitOutcome::TimedOut { continue; }
        if outcome != sched::task::WaitOutcome::Ready { return Some(STATUS_ALERTED); }
    }
}

/// Damage still owed when a retrieval finds nothing to hand over, bounded so a
/// running system stays quiet. # C: O(N_dirty * N_windows)
fn trace_idle(state: &ipc::win32_window::WindowManager, tid: u64) {
    use core::sync::atomic::{AtomicU32, Ordering};
    static BUDGET: AtomicU32 = AtomicU32::new(0);
    let dirty = state.dirty_windows();
    if dirty.is_empty() || BUDGET.fetch_add(1, Ordering::Relaxed) >= 100 { return; }
    klog::write_raw(b"[WINDOWS-IDLE-DAMAGE] tid="); klog::write_hex_u64(tid);
    for window in dirty {
        klog::write_raw(b" hwnd="); klog::write_hex_u64(window.raw() as u64);
        klog::write_raw(b"/owner="); klog::write_hex_u64(state.get(window).map(|record| record.owner_tid).unwrap_or(0));
        klog::write_raw(b"/visible="); klog::write_hex_u64(state.get(window).is_some_and(|record| record.visible) as u64);
    }
    klog::write_raw(b"\n");
}
