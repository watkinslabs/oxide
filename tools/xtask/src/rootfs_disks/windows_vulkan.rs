//! Rootfs injection for the native Vulkan W6 smoke.

use std::fs;
use std::path::{Path, PathBuf};

use super::{dbg, probe_cargo_bin};

const DESTINATION: &str = "/usr/local/bin/windows-vulkan-smoke";
const SERVICE: &str = "/etc/systemd/system/windows-vulkan-smoke.service";
const LINK: &str = "/etc/systemd/system/multi-user.target.wants/windows-vulkan-smoke.service";

/// Inject the native Vulkan loader probe for either supported guest ABI.
/// # C: O(cargo + debugfs writes)
pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    let probe = probe_cargo_bin(arch, "vulkan_probe", "vulkan_probe")?;
    let service = write_service(arch)?;
    for command in ["mkdir /etc/systemd/system", "mkdir /etc/systemd/system/multi-user.target.wants"] {
        let _ = dbg(root_img, command);
    }
    let _ = dbg(root_img, &format!("rm {DESTINATION}"));
    dbg(root_img, &format!("write {} {DESTINATION}", probe.display()))?;
    dbg(root_img, &format!("sif {DESTINATION} mode 0100755"))?;
    let _ = dbg(root_img, &format!("rm {SERVICE}"));
    dbg(root_img, &format!("write {} {SERVICE}", service.display()))?;
    dbg(root_img, &format!("sif {SERVICE} mode 0100644"))?;
    let _ = dbg(root_img, &format!("rm {LINK}"));
    dbg(root_img, &format!("symlink {SERVICE} {LINK}"))?;
    eprintln!("xtask rootfs: injected native Vulkan smoke into {}", root_img.display());
    Ok(())
}

fn write_service(arch: &str) -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target/smoke");
    fs::create_dir_all(&dir).map_err(|_| 1u8)?;
    let path = dir.join(format!("windows-vulkan-smoke-{arch}.service"));
    let serial = crate::image_qemu::serial_device_name(arch);
    let body = format!("[Unit]\nDescription=Oxide native Vulkan W6 smoke\nAfter=basic.target systemd-udev-settle.service\n\n[Service]\nType=oneshot\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/{serial}\nExecStart={DESTINATION}\n\n[Install]\nWantedBy=multi-user.target\n");
    fs::write(&path, body).map_err(|_| 1u8)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke_contract_uses_a_stable_binary_and_service() {
        assert_eq!(super::DESTINATION, "/usr/local/bin/windows-vulkan-smoke");
        assert_eq!(super::SERVICE, "/etc/systemd/system/windows-vulkan-smoke.service");
        assert!(super::LINK.ends_with("windows-vulkan-smoke.service"));
    }
}
