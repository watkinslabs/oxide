use std::path::Path;

const PROBE_NAME: &str = "ata_sat_probe";
const PROBE_DESTINATION: &str = "/usr/local/bin/ata_sat_probe";

/// Inject one SG_IO ATA PASS-THROUGH acceptance probe. The smoke harness runs
/// it from its serial debug shell after the AHCI disk is published. # C: O(CC+debugfs)
pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    let bin = super::probe_cargo(arch, PROBE_NAME)?;
    super::dbg_ignore(root_img, &format!("rm {PROBE_DESTINATION}"));
    super::dbg(root_img, &format!("write {} {PROBE_DESTINATION}", bin.display()))?;
    super::dbg(root_img, &format!("sif {PROBE_DESTINATION} mode 0100755"))?;
    eprintln!("xtask rootfs: injected ATA SAT smoke into {}", root_img.display());
    Ok(())
}
