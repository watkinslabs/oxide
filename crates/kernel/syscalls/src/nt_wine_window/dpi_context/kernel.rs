//! Kernel binding: the context lives on the process GUI entry.
use super::*;

/// # C: O(processes)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    match ordinal {
        GET_ORDINAL => {
            let process = args.first().copied().unwrap_or(0);
            Some(u64::from(get(crate::nt_window::dpi_context_for_current().unwrap_or(0), process)))
        }
        SET_ORDINAL => {
            let ctx = args.first().copied().unwrap_or(0) as u32;
            let system_dpi = drm::primary_system_dpi();
            match crate::nt_window::set_dpi_context_for_current(ctx, system_dpi) {
                Ok(()) => Some(1),
                Err(error) => { crate::nt_rtl::set_last_win32_error(u64::from(error)); Some(0) }
            }
        }
        _ => None,
    }
}
