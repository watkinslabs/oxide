use std::path::Path;

const PROBE_NAME: &str = "usb_scsi_probe";
const PROBE_DESTINATION: &str = "/usr/local/bin/usb_scsi_probe";

/// Inject one live USB Bulk-Only/SCSI probe into a smoke root. # C: O(CC+debugfs)
pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    let bin = super::probe_cargo(arch, PROBE_NAME)?;
    super::dbg_ignore(root_img, &format!("rm {PROBE_DESTINATION}"));
    super::dbg(root_img, &format!("write {} {PROBE_DESTINATION}", bin.display()))?;
    super::dbg(root_img, &format!("sif {PROBE_DESTINATION} mode 0100755"))?;
    eprintln!("xtask rootfs: injected USB SCSI smoke into {}", root_img.display());
    Ok(())
}
