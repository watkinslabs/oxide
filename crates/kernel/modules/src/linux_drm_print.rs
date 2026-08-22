//! DRM diagnostic entry points used by external drivers.

use super::*;
use core::ffi::VaList;

const DRM_MESSAGE_BYTES: usize = 1024;

pub(super) fn export_symbols() {
    crate::symtab::export("__drm_dev_dbg", drm_dev_dbg as *const () as usize, false);
    crate::symtab::export("__drm_err", drm_err as *const () as usize, false);
}

fn write_message(prefix: &[u8], format: *const u8, args: &mut VaList) {
    let mut message = [0u8; DRM_MESSAGE_BYTES];
    // SAFETY: the DRM caller supplies a NUL-terminated printf format and matching varargs.
    let len = unsafe { crate::linux_string::vscnprintf(message.as_mut_ptr(), message.len(), format, args) }.max(0) as usize;
    klog::write_raw(prefix);
    klog::write_raw(&message[..len.min(message.len() - 1)]);
}

/// Linux's debug gate is disabled by default; consume correctly-shaped calls until DRM debug categories are configurable. # C: O(1)
pub(super) unsafe extern "C" fn drm_dev_dbg(_desc: *mut c_void, _dev: *const c_void, _category: u32, _format: *const u8, mut _args: ...) {}

/// Emit an external DRM error through the kernel log. # C: O(format length)
pub(super) unsafe extern "C" fn drm_err(format: *const u8, mut args: ...) {
    write_message(b"[drm] *ERROR* ", format, &mut args);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_entry_points_are_module_exports() {
        let _modules = crate::test_serial::claim();
        export_symbols();
        assert!(crate::symtab::is_exported("__drm_dev_dbg"));
        assert!(crate::symtab::is_exported("__drm_err"));
    }
}
