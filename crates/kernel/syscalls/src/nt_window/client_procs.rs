//! The client procedure array user32 publishes, and the one-shot claim that
//! makes the builtin classes register exactly once per process.
use super::*;

fn with_entry<T>(f: impl FnOnce(&mut GuiEntry) -> T) -> Option<T> {
    let cur = sched::live::current().filter(|task| task.is_nt_personality())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| { entries.push(new_entry(&group)); entries.len() - 1 });
    Some(f(&mut entries[index]))
}

/// Retain the published W procedure array; the builtin classes are registered
/// from it later, when the desktop window comes up. # C: O(processes)
pub(crate) fn publish_client_procs_for_current(procs_w: u64) -> bool {
    with_entry(|entry| { entry.client_procs_w = procs_w; true }).unwrap_or(false)
}

/// Claim the one builtin-class registration of this process, answering the
/// published array exactly once. A process whose user32 published nothing has
/// nothing to register and never claims. # C: O(processes)
pub(crate) fn claim_builtin_registration_for_current() -> Option<u64> {
    with_entry(|entry| {
        if entry.builtins_registered || entry.client_procs_w == 0 { return None; }
        entry.builtins_registered = true;
        Some(entry.client_procs_w)
    }).flatten()
}

/// Claim the one client-side builtin-class initialisation callback. Only a
/// process whose classes are registered owes it, and it is owed once.
/// # C: O(processes)
pub(crate) fn claim_init_builtin_classes_callback_for_current() -> bool {
    with_entry(|entry| {
        if entry.init_callback_issued || !entry.builtins_registered { return false; }
        entry.init_callback_issued = true;
        true
    }).unwrap_or(false)
}

/// Install the builtin class procedures in the process window-procedure
/// table, so a builtin handle resolves before the client has allocated
/// anything of its own. Each table is `NB_BUILTIN_PROCS` procedure words.
/// # C: O(NB_BUILTIN_PROCS)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn publish_builtin_winprocs_for_current(procs_a: u64, procs_w: u64) -> bool {
    let Some(ansi) = read_proc_table(procs_a) else { return false; };
    let Some(unicode) = read_proc_table(procs_w) else { return false; };
    with_entry(|entry| { entry.state.publish_builtin_winprocs(&ansi, &unicode); true }).unwrap_or(false)
}

/// # C: O(NB_BUILTIN_PROCS)
#[cfg(target_os = "oxide-kernel")]
fn read_proc_table(base: u64) -> Option<[u64; ipc::win32_window::NB_BUILTIN_PROCS]> {
    let mut table = [0u64; ipc::win32_window::NB_BUILTIN_PROCS];
    for (index, slot) in table.iter_mut().enumerate() {
        *slot = uaccess::get_user_u64(base.checked_add((index * 8) as u64)?).ok()?;
    }
    Some(table)
}

/// `NtUserCallTwoParam_AllocWinProc`. The procedure is answered unchanged when
/// no slot is taken, so a caller never stores a null procedure.
/// # C: O(processes + N_winprocs)
pub(crate) fn alloc_winproc_for_current(func: u64, ansi: bool) -> u64 {
    with_entry(|entry| entry.state.alloc_winproc(func, ansi)).unwrap_or(func)
}

/// `NtUserCallTwoParam_GetDialogProc`. A word that is not a handle this
/// process issued is answered unchanged. # C: O(processes)
pub(crate) fn dialog_proc_for_current(proc: u64, ansi: bool) -> u64 {
    with_entry(|entry| entry.state.dialog_proc(proc, ansi)).unwrap_or(proc)
}
