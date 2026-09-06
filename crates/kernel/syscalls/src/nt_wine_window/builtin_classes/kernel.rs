//! Kernel binding: procedures come from the published W array in user memory;
//! classes enter the canonical per-process class owner.
use super::*;
extern crate alloc;

/// # C: O(builtins) plus bounded usercopy
pub(crate) fn register_for_current(procs_w: u64) -> usize {
    register_all(
        |index| procs_w.checked_add(index as u64 * PROC_ENTRY_BYTES).and_then(|address| uaccess::get_user_u64(address).ok()),
        crate::nt_window::shared_oem_cursor_for_current,
        |builtin, wndproc, cursor| {
            let name: alloc::vec::Vec<u16> = builtin.name.encode_utf16().collect();
            crate::nt_window::register_class_desc_for_current(ipc::win32_window::ClassRegistration {
                cb_wnd_extra: builtin.extra, style: builtin.style, background: builtin.brush, cursor,
                ..ipc::win32_window::ClassRegistration::new(&name, wndproc) }).is_some()
        })
}
