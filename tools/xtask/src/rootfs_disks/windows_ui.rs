//! Rootfs injection for the native Windows UI service smoke.

use std::path::Path;

use super::{dbg, probe_cargo_bin};

const DESTINATION: &str = "/usr/local/bin/windows-ui-smoke";

/// Inject the userspace Win32 window/message/GDI smoke for either 64-bit guest.
/// # C: O(cargo + debugfs writes)
pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    let probe = probe_cargo_bin(arch, "windows-user32", "windows-ui-smoke")?;
    let _ = dbg(root_img, &format!("rm {DESTINATION}"));
    dbg(root_img, &format!("write {} {DESTINATION}", probe.display()))?;
    dbg(root_img, &format!("sif {DESTINATION} mode 0100755"))?;
    eprintln!("xtask rootfs: injected native Windows UI smoke into {}", root_img.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn ui_smoke_destination_is_a_stable_rootfs_contract() {
        assert_eq!(super::DESTINATION, "/usr/local/bin/windows-ui-smoke");
    }
}
