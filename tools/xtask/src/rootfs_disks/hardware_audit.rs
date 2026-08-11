use std::path::{Path, PathBuf};

const AUDIT_NAME: &str = "oxide-hardware-audit";
const AUDIT_DESTINATION: &str = "/usr/local/bin/oxide-hardware-audit";
const AUDIT_MODE: &str = "0100755";

/// Inject the physical-machine inventory utility.  It is intentionally a
/// manual command: an early physical boot can have incomplete sysfs/devtmpfs,
/// and automatic execution would capture a misleading partial inventory.
/// # C: O(debugfs write)
pub(super) fn inject(root_img: &Path) -> Result<(), u8> {
    let audit = write_audit()?;
    super::dbg_ignore(root_img, &format!("rm {AUDIT_DESTINATION}"));
    super::dbg(root_img, &format!("write {} {AUDIT_DESTINATION}", audit.display()))?;
    super::dbg(root_img, &format!("sif {AUDIT_DESTINATION} mode {AUDIT_MODE}"))?;
    eprintln!("xtask rootfs: injected physical-hardware audit into {}", root_img.display());
    Ok(())
}

fn write_audit() -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target").join("smoke");
    std::fs::create_dir_all(&dir).map_err(|err| {
        eprintln!("xtask rootfs: mkdir hardware-audit directory failed: {err}");
        1u8
    })?;
    let path = dir.join(AUDIT_NAME);
    std::fs::write(&path, include_str!("../assets/oxide-hardware-audit.sh")).map_err(|err| {
        eprintln!("xtask rootfs: write hardware audit failed: {err}");
        1u8
    })?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    #[test]
    fn embedded_audit_has_the_stable_record_contract() {
        let body = include_str!("../assets/oxide-hardware-audit.sh");
        assert!(body.starts_with("#!/bin/sh\n"));
        assert!(body.contains("tag=OXIDE_HARDWARE_AUDIT"));
        assert!(body.contains("'%s|v1|%s|%s'"));
        assert!(body.contains("driver-assessment"));
    }
}
