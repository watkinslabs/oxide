use super::*;

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
    if let NtWindowCall::DefaultProc { message, wparam, .. } = operation {
        if let Some(result) = control_color::for_current(message, wparam) { return Some(result); }
    }
    if let NtWindowCall::BeginPaint { hwnd, rect } = operation { return Some(paint::begin(hwnd, rect)); }
    if crate::nt_compositor::monitors_current().is_none() {
        input::set_native_key_hook(Some(route_hardware_key));
        input::set_native_rel_hook(Some(route_hardware_rel));
        input::set_native_mouse_hook(Some(route_hardware_mouse));
    }
    let group = Arc::clone(&cur.thread_group);
    loop {
        if matches!(operation, NtWindowCall::Peek { .. } | NtWindowCall::Get { .. }) {
            crate::nt_gdi::flush_pending_for_current(false);
            let _ = caret::blink::expire_for_current(timekeeper::monotonic_ns());
            if let Some(result) = retrieval::pump(call, raw) { return Some(result); }
        }
        let (result, wake, sleep, cleanup, atoms, paint_dcs) = {
            let mut entries = GUI.lock();
            entries.retain(|entry| entry.group.upgrade().is_some());
            let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)));
            let index = index.unwrap_or_else(|| {
                entries.push(new_entry(&group));
                entries.len() - 1
            });
            let wait = Arc::clone(&entries[index].wait);
            let state = &mut entries[index].state;
            let mut cleanup = Vec::new();
            let mut atoms = Vec::new();
            let mut paint_dcs = Vec::new();
            state.expire_timers(timekeeper::monotonic_ns());
            let outcome = match operation {
                NtWindowCall::DefaultProc { hwnd, message, wparam: _, lparam } => {
                    if hwnd > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
                    let rect = ipc::win32_window::WindowId::from_raw(hwnd as u32).and_then(|window| state.rect(window));
                    let result = match rect.map_or_else(|| ipc::win32_window::default_window_proc(message), |rect| ipc::win32_window::default_window_proc_for_rect(message, rect, lparam)) {
                        ipc::win32_window::DefaultWindowResult::Return(value) => value as u64,
                        ipc::win32_window::DefaultWindowResult::RequestDestroy => {
                            if hwnd != 0 {
                                let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return Some(STATUS_INVALID_HANDLE); };
                                let windows = state.destruction_order(window).unwrap_or_default();
                                paint_dcs.extend(windows.iter().filter_map(|window| state.paint_session(*window).ok().map(|session| session.dc).filter(|dc| *dc != 0)));
                                let Ok((_, released)) = state.destroy_with_property_atoms(window) else { return Some(STATUS_INVALID_HANDLE); };
                                atoms.extend(released);
                                cleanup.extend(windows.into_iter().map(|window| window.raw()));
                            }
                            STATUS_SUCCESS
                        }
                    };
                    (Some(result), None, None)
                }
                NtWindowCall::Create { parent, wndproc } => {
                    if parent > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
                    let parent = if parent == 0 { None } else { match ipc::win32_window::WindowId::from_raw(parent as u32) { Some(parent) => Some(parent), None => return Some(STATUS_INVALID_HANDLE) } };
                    let result = match state.create(cur.tid as u64, parent, wndproc) { Ok(window) => window.raw() as u64, Err(_) => STATUS_INVALID_PARAMETER };
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
                        Ok((_, released)) => { atoms.extend(released); cleanup.extend(windows.into_iter().map(|window| window.raw())); STATUS_SUCCESS },
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
                    if let Some(found) = state.peek_for_thread(cur.tid as u64, filter, false) {
                        if copy_message(message, found).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                        if remove != 0 { let _ = state.peek_for_thread(cur.tid as u64, filter, true); }
                        (Some(STATUS_SUCCESS), None, None)
                    } else { (Some(STATUS_NO_MORE_ENTRIES), None, None) }
                }
                NtWindowCall::Get { message, hwnd, first, last } => {
                    let Some(filter) = message_filter(state, hwnd, first, last) else { return Some(STATUS_INVALID_HANDLE); };
                    match state.take_for_thread(cur.tid as u64, filter) {
                        ipc::win32_window::QueueResult::Message(found) => {
                            if copy_message(message, found).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                            (Some(STATUS_SUCCESS), None, None)
                        }
                        ipc::win32_window::QueueResult::Quit(code) => {
                            if copy_message(message, ipc::win32_window::WinMessage { hwnd: None, message: ipc::win32_window::WM_QUIT, wparam: code as u64, lparam: 0 }).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                            (Some(0), None, None)
                        }
                        ipc::win32_window::QueueResult::Empty => (None, None, Some((wait, filter))),
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
                    let result = match state.set_timer(cur.tid as u64, window, id, timeout_ms, proc, timekeeper::monotonic_ns()) {
                        Ok(value) => value,
                        Err(_) => STATUS_INVALID_HANDLE,
                    };
                    (Some(result), None, None)
                }
                NtWindowCall::KillTimer { hwnd, id } => {
                    if hwnd > u32::MAX as u64 || id == 0 { return Some(STATUS_INVALID_PARAMETER); }
                    let window = if hwnd == 0 { None } else { Some(match ipc::win32_window::WindowId::from_raw(hwnd as u32) { Some(window) => window, None => return Some(STATUS_INVALID_HANDLE) }) };
                    (Some(state.kill_timer(window, id) as u64), None, None)
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
                    (Some(match state.show(cur.tid as u64, window, visible) {
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
                NtWindowCall::Show { hwnd, .. } => bridge::publish_visibility_current(hwnd),
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
                        || entry.state.has_message_for_thread(cur.tid as u64, filter)
                        || entry.state.quit_pending(cur.tid as u64)
                })
        }) };
        if outcome == sched::task::WaitOutcome::TimedOut { continue; }
        if outcome != sched::task::WaitOutcome::Ready { return Some(STATUS_ALERTED); }
    }
}
