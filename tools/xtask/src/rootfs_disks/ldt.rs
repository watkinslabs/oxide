use std::path::{Path, PathBuf};

const PROBE_NAME: &str = "ldt_probe";
const PROBE_DESTINATION: &str = "/usr/local/bin/ldt_probe";
const SERVICE_NAME: &str = "ldt-smoke.service";
const SERVICE_DESTINATION: &str = "/etc/systemd/system/ldt-smoke.service";
const WANTS_DIRECTORY: &str = "/etc/systemd/system/basic.target.wants";
const WANTS_DESTINATION: &str = "/etc/systemd/system/basic.target.wants/ldt-smoke.service";

pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    if arch != "x86_64" { return Ok(()); }
    let bin = super::probe_cargo(arch, PROBE_NAME)?;
    let service = write_service(arch)?;
    super::dbg(root_img, "mkdir /etc/systemd/system")?;
    super::dbg(root_img, &format!("mkdir {WANTS_DIRECTORY}"))?;
    super::dbg_ignore(root_img, &format!("rm {PROBE_DESTINATION}"));
    super::dbg(root_img, &format!("write {} {PROBE_DESTINATION}", bin.display()))?;
    super::dbg(root_img, &format!("sif {PROBE_DESTINATION} mode 0100755"))?;
    super::dbg_ignore(root_img, &format!("rm {SERVICE_DESTINATION}"));
    super::dbg(root_img, &format!("write {} {SERVICE_DESTINATION}", service.display()))?;
    super::dbg_ignore(root_img, &format!("rm {WANTS_DESTINATION}"));
    super::dbg(root_img, &format!("symlink {WANTS_DESTINATION} ../{SERVICE_NAME}"))?;
    Ok(())
}

fn write_service(arch: &str) -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target").join("smoke");
    std::fs::create_dir_all(&dir).map_err(|_| 1u8)?;
    let path = dir.join(SERVICE_NAME);
    let serial = crate::image_qemu::serial_device_name(arch);
    let body = format!("[Unit]\nDescription=Oxide LDT smoke\nDefaultDependencies=no\nAfter=local-fs.target\nBefore=basic.target\n\n[Service]\nType=oneshot\nUser=root\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/{serial}\nExecStart={PROBE_DESTINATION}\n\n[Install]\nWantedBy=basic.target\n");
    std::fs::write(&path, body).map_err(|_| 1u8)?;
    Ok(path)
}
