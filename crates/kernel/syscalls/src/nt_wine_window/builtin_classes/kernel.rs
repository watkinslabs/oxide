//! Kernel binding: procedures come from the published W array in user memory;
//! classes enter the canonical per-process class owner.
use super::*;
extern crate alloc;

/// # C: O(builtins) plus bounded usercopy
pub(crate) fn register_for_current(procs_w: u64) -> usize {
    register_all(
        |index| procs_w.checked_add(index as u64 * PROC_ENTRY_BYTES).and_then(|address| uaccess::get_user_u64(address).ok()),
        |builtin, wndproc| {
            let name: alloc::vec::Vec<u16> = builtin.name.encode_utf16().collect();
            crate::nt_window::register_class_with_background_for_current(&name, wndproc, builtin.extra, true, builtin.style, builtin.brush).is_some()
        })
}
