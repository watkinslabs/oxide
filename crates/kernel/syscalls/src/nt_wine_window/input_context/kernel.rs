//! Kernel routing: the canonical per-process input-context owner answers each
//! ordinal, and the two handle-reading ordinals report invalid-handle.
use super::*;
use crate::nt_window::imc;
use ipc::win32_imc::ImcId;

fn context(himc: u64) -> Option<ImcId> { handle_index(himc).and_then(ImcId::from_raw) }

fn invalid_handle() -> u64 { crate::nt_rtl::set_last_win32_error(ERROR_INVALID_HANDLE); 0 }

/// Copy one thread's input-context handles into the client's buffer and report
/// how many landed. # C: O(contexts)
fn build_list(arg: impl Fn(usize) -> u64) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_UNSUCCESSFUL; };
    let Some((buffer, count)) = list_bounds(arg(2), arg(1)) else { return STATUS_UNSUCCESSFUL; };
    let handles = imc::build_himc_list_for_current(list_thread(arg(0), cur.tid as u64), count);
    for (index, handle) in handles.iter().enumerate() {
        let Some(slot) = buffer.checked_add(index as u64 * HIMC_BYTES) else { return STATUS_ACCESS_VIOLATION; };
        if uaccess::put_user_u64(slot, u64::from(*handle)).is_err() { return STATUS_ACCESS_VIOLATION; }
    }
    if uaccess::put_user_u32(arg(3), handles.len() as u32).is_err() { return STATUS_ACCESS_VIOLATION; }
    STATUS_SUCCESS
}

/// # C: O(1) dispatch plus the canonical owner's work
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    let arg = |index: usize| args.get(index).copied().unwrap_or(0);
    match ordinal {
        CREATE_ORDINAL => Some(imc::create_input_context_for_current(arg(0))),
        DESTROY_ORDINAL => Some(u64::from(context(arg(0)).is_some_and(imc::destroy_input_context_for_current))),
        QUERY_ORDINAL => Some(match context(arg(0)) {
            Some(himc) => imc::query_input_context_for_current(himc, arg(1) as u32).unwrap_or_else(|_| invalid_handle()),
            None => invalid_handle(),
        }),
        UPDATE_ORDINAL => Some(match context(arg(0)) {
            Some(himc) => imc::update_input_context_for_current(himc, arg(1) as u32, arg(2)).map_or_else(|_| invalid_handle(), u64::from),
            None => invalid_handle(),
        }),
        ASSOCIATE_ORDINAL => Some(u64::from(imc::associate_input_context_for_current(arg(0), arg(1), arg(2) as u32))),
        BUILD_HIMC_LIST_ORDINAL => Some(build_list(&arg)),
        DISABLE_THREAD_IME_ORDINAL => Some(u64::from(imc::disable_thread_ime_for_current(arg(0) as u32 as u64))),
        // The status notification is the IME driver's; the display personality
        // installs no IME driver, so nothing consumes it.
        NOTIFY_IME_STATUS_ORDINAL => Some(0),
        _ => None,
    }
}
