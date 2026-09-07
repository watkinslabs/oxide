//! Kernel binding for the input-context ordinals and `NtUserQueryWindow`:
//! the per-process input-context owner, the window record's association, and
//! the window/thread facts the query classes read.
use super::*;
use crate::nt_wine_window::query_window;
use ipc::win32_imc::{AssociateFacts, ImcId, InvalidHandle, associate};

fn with_entry<T>(f: impl FnOnce(&mut GuiEntry, u64) -> T) -> Option<T> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| { entries.push(new_entry(&group)); entries.len() - 1 });
    Some(f(&mut entries[index], cur.tid as u64))
}

/// Zero when the process owns no GUI state or the object cannot be allocated.
/// # C: O(processes)
pub(crate) fn create_input_context_for_current(client_ptr: u64) -> u64 {
    with_entry(|entry, tid| entry.contexts.create(tid, client_ptr).map_or(0, |id| u64::from(id.raw()))).unwrap_or(0)
}

/// # C: O(processes + contexts)
pub(crate) fn destroy_input_context_for_current(himc: ImcId) -> bool {
    with_entry(|entry, _| entry.contexts.destroy(himc)).unwrap_or(false)
}

/// # C: O(processes + contexts)
pub(crate) fn query_input_context_for_current(himc: ImcId, attr: u32) -> Result<u64, InvalidHandle> {
    with_entry(|entry, _| entry.contexts.query(himc, attr)).unwrap_or(Err(InvalidHandle))
}

/// # C: O(processes + contexts)
pub(crate) fn update_input_context_for_current(himc: ImcId, attr: u32, value: u64) -> Result<bool, InvalidHandle> {
    with_entry(|entry, _| entry.contexts.update(himc, attr, value)).unwrap_or(Err(InvalidHandle))
}

/// # C: O(processes + contexts)
pub(crate) fn build_himc_list_for_current(thread_id: u64, count: usize) -> Vec<u32> {
    with_entry(|entry, _| entry.contexts.list(thread_id, count).into_iter().map(|id| id.raw()).collect()).unwrap_or_default()
}

/// # C: O(processes + threads)
pub(crate) fn disable_thread_ime_for_current(thread_id: u64) -> bool {
    with_entry(|entry, tid| entry.contexts.disable_thread_ime(tid, thread_id)).unwrap_or(false)
}

/// The calling thread's default input context, created on first use. # C: O(processes + contexts)
pub(crate) fn default_input_context_for_current() -> u64 {
    with_entry(|entry, tid| entry.contexts.default_context(tid).map_or(0, |id| u64::from(id.raw()))).unwrap_or(0)
}

/// `NtUserAssociateInputContext` against the canonical window and context
/// owners; the association lands on the window record. # C: O(processes + windows + contexts)
pub(crate) fn associate_input_context_for_current(hwnd: u64, ctx: u64, flags: u32) -> u32 {
    let window = u32::try_from(hwnd).ok().and_then(ipc::win32_window::WindowId::from_raw);
    with_entry(|entry, tid| {
        let ctx = crate::nt_wine_window::input_context::handle_index(ctx).and_then(ImcId::from_raw);
        let default_ctx = if flags == ipc::win32_imc::IACE_DEFAULT { entry.contexts.default_context(tid) } else { None };
        let facts = AssociateFacts {
            flags, ctx, default_ctx, current_tid: tid,
            ctx_thread: ctx.and_then(|id| entry.contexts.get(id)).map(|context| context.thread_id),
            window: window.and_then(|id| entry.state.imc_window_facts(id)),
        };
        let outcome = associate(facts);
        if let (Some(assign), Some(id)) = (outcome.assign, window) { let _ = entry.state.set_window_imc(id, assign); }
        outcome.result
    }).unwrap_or(ipc::win32_imc::AICR_FAILED)
}

/// Facts for one window-info class. The default-input-context class reads the
/// calling thread alone, so it never resolves the named window.
/// # C: O(processes + windows + contexts)
pub(crate) fn query_window_facts(hwnd: u64, cls: u64, now_ns: u64) -> Option<query_window::Facts> {
    sched::live::current().filter(|task| task.is_nt_personality())?;
    if !query_window::needs_window(cls) {
        return Some(query_window::Facts { default_input_context: default_input_context_for_current(), ..Default::default() });
    }
    let id = ipc::win32_window::WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
    let entries = GUI.lock();
    let owner = entries.iter().find(|entry| entry.state.get(id).is_some())?;
    let record = owner.state.get(id)?;
    let pid = owner.group.upgrade().map_or(0, |group| u64::from(group.leader_pid().tid));
    let foreground_tid = entries.iter().find(|entry| entry.foreground)
        .and_then(|entry| entry.state.active_window().and_then(|window| entry.state.get(window)))
        .map(|top| top.owner_tid);
    Some(query_window::Facts {
        pid, thread_id: record.owner_tid,
        active: owner.state.active_window().map_or(0, |window| u64::from(window.raw())),
        focus: owner.state.focused().map_or(0, |window| u64::from(window.raw())),
        hung: owner.state.window_hung(id, now_ns),
        foreground_thread: foreground_tid == Some(record.owner_tid),
        // No thread owns a default IME window until window registration creates
        // one; the class then reports that window.
        default_ime_window: 0,
        default_input_context: 0,
    })
}
