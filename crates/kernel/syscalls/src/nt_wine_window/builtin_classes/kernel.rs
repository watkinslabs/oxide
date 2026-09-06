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

/// Register the builtin classes of this process if they are not registered
/// yet. The reference reaches this from every path that resolves the desktop
/// window, window creation included, so a process that never asks for the
/// desktop window by name still gets its controls.
/// # C: O(builtins) plus bounded usercopy
pub(crate) fn ensure_registered() {
    let Some(procs_w) = crate::nt_window::claim_builtin_registration_for_current() else { return; };
    let registered = register_for_current(procs_w);
    klog::write_raw(b"[WINDOWS-BUILTIN-CLASSES] registered=");
    klog::write_hex_u64(registered as u64);
    klog::write_raw(b"\n");
}

/// NtUserGetDesktopWindow. The reference registers the builtin classes here,
/// once per process, and then calls back into the client so it can finish its
/// own class-time initialisation; the answer is the desktop window either way.
/// # C: O(builtins) plus bounded usercopy
pub(crate) fn get_desktop_window() -> u64 {
    const STATUS_PENDING: u64 = 0x0000_0103;
    let desktop = crate::nt_window::desktop::window_for_current();
    ensure_registered();
    if !crate::nt_window::claim_init_builtin_classes_callback_for_current() { return desktop; }
    let status = crate::nt_rtl::begin_user_callback(crate::nt_user_callback::NT_USER_INIT_BUILTIN_CLASSES, 0, 0,
        sched::nt_callback::Completion { kind: crate::nt_window::CALLBACK_INIT_BUILTIN_CLASSES, argument: desktop });
    // A callback that could not be entered leaves the classes registered and
    // answers the desktop window directly; only an armed callback suspends.
    if status == STATUS_PENDING { status } else { desktop }
}
