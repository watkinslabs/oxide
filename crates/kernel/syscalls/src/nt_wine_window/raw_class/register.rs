//! The WNDCLASSEXW registration entry: the caller's whole structure enters the
//! canonical class owner, keyed by its name and the registering module.
use super::*;
// The canonical class owner this entry hands the registration to. Production
// reaches it at the crate root; the hosted contract that drives this file
// supplies its own recorder in its place.
#[cfg(not(test))] use crate::nt_window;
#[cfg(test)] use super::nt_window;

/// Register a raw Wine WNDCLASSEXW through the process-local canonical owner.
/// The whole structure enters the class record: style, both extra sizes, the
/// registering module, both icons, the cursor, the background brush and the
/// procedure. # C: O(N_process_gui_states + N_classes) plus bounded usercopy
pub(crate) fn register_class(args: SyscallArgs) -> u64 {
    use ipc::win32_window::class_info_abi;
    let mut raw = [0u8; class_info_abi::BYTES];
    if args.a0 == 0 || uaccess::copy_from_user(&mut raw, args.a0).is_err() {
        wine_window_diag! { klog::write_raw(b"[WINDOWS-PE-WINE-CLASS] reject-wndclass ptr="); klog::write_hex_u64(args.a0); klog::write_raw(b"\n"); }
        return 0;
    }
    let Some(fields) = class_info_abi::decode(&raw) else {
        wine_window_diag! { klog::write_raw(b"[WINDOWS-PE-WINE-CLASS] reject-cbsize ptr="); klog::write_hex_u64(args.a0); klog::write_raw(b"\n"); }
        return 0;
    };
    let Some(name) = read_unicode_string(args.a1) else {
        wine_window_diag! { klog::write_raw(b"[WINDOWS-PE-WINE-CLASS] reject-name ptr="); klog::write_hex_u64(args.a1); klog::write_raw(b"\n"); }
        return 0;
    };
    // The class menu name never travels inside WNDCLASSEXW across this
    // boundary: the caller hands over one opaque handle of its own — a client
    // pointer, or an integer resource id, which is a value below 0x10000 and
    // addresses nothing. It is kept verbatim and never dereferenced, and
    // window creation reads it back to load the class's menu.
    let menu_name = args.a3;
    let result = nt_window::register_class_desc_for_current(ipc::win32_window::ClassRegistration {
        cb_cls_extra: fields.cb_cls_extra, cb_wnd_extra: fields.cb_wnd_extra, unicode: args.a5 as u32 == 0,
        style: fields.style, background: fields.background, cursor: fields.cursor, icon: fields.icon,
        icon_sm: fields.icon_sm, module: fields.instance, menu_name, builtin: args.a4 != 0,
        ..ipc::win32_window::ClassRegistration::new(&name, fields.wndproc) }).unwrap_or(0);
    wine_window_diag! { klog::write_raw(b"[WINDOWS-PE-WINE-CLASS] result="); klog::write_hex_u64(result); klog::write_raw(b" wndproc="); klog::write_hex_u64(fields.wndproc);
        klog::write_raw(b" instance="); klog::write_hex_u64(fields.instance);
        klog::write_raw(b" menu-name="); klog::write_hex_u64(menu_name); klog::write_raw(b"\n"); }
    result
}
