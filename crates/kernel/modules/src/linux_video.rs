//! Video modeset admission ABI.

/// Register video modeset admission symbols. # C: O(1)
pub fn export_symbols() {
    crate::symtab::export("video_firmware_drivers_only", video_firmware_drivers_only as *const () as usize, false);
}

/// True only when the boot command line requests firmware-only graphics. # C: O(command-line length)
extern "C" fn video_firmware_drivers_only() -> bool { firmware_drivers_only(cmdline::get()) }

fn firmware_drivers_only(line: &[u8]) -> bool { cmdline::token::bare_flag(line, b"nomodeset") }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_bare_nomodeset_flag_disables_kernel_modesetting() {
        assert!(firmware_drivers_only(b"quiet nomodeset console=ttyS0"));
        assert!(!firmware_drivers_only(b"quiet nomodesetting nomodeset=0"));
    }

    #[test]
    fn exports_the_video_modeset_admission_symbol() {
        let _modules = crate::test_serial::claim();
        export_symbols();
        assert!(crate::symtab::is_exported("video_firmware_drivers_only"));
    }
}
