use std::path::{Path, PathBuf};


const PROBE_NAME: &str = "swapfile_probe";
const PROBE_DESTINATION: &str = "/usr/local/bin/swapfile_probe";
const SERVICE_NAME: &str = "swapfile-smoke.service";
const SERVICE_DESTINATION: &str = "/etc/systemd/system/swapfile-smoke.service";
const WANTS_DIRECTORY: &str = "/etc/systemd/system/basic.target.wants";
const WANTS_DESTINATION: &str = "/etc/systemd/system/basic.target.wants/swapfile-smoke.service";

/// Inject a root-run ext4 swapfile smoke into one disposable boot root. # C: O(CC+debugfs)
pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    let bin = build_probe(arch)?;
    let service = write_service()?;
    super::dbg(root_img, "mkdir /etc/systemd/system")?;
    super::dbg(root_img, &format!("mkdir {WANTS_DIRECTORY}"))?;
    super::dbg_ignore(root_img, &format!("rm {PROBE_DESTINATION}"));
    super::dbg(root_img, &format!("write {} {PROBE_DESTINATION}", bin.display()))?;
    super::dbg(root_img, &format!("sif {PROBE_DESTINATION} mode 0100755"))?;
    super::dbg_ignore(root_img, &format!("rm {SERVICE_DESTINATION}"));
    super::dbg(root_img, &format!("write {} {SERVICE_DESTINATION}", service.display()))?;
    super::dbg_ignore(root_img, &format!("rm {WANTS_DESTINATION}"));
    super::dbg(root_img, &format!("symlink {WANTS_DESTINATION} ../{SERVICE_NAME}"))?;
    eprintln!("xtask rootfs: injected ext4 swapfile smoke into {}", root_img.display());
    Ok(())
}

fn build_probe(arch: &str) -> Result<PathBuf, u8> { super::probe_cargo(arch, PROBE_NAME) }

fn write_service() -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target").join("smoke");
    std::fs::create_dir_all(&dir).map_err(|e| { eprintln!("xtask rootfs: mkdir smoke dir failed: {e}"); 1u8 })?;
    let path = dir.join(SERVICE_NAME);
    let body = "[Unit]\n\
Description=Oxide ext4 swapfile smoke\n\
DefaultDependencies=no\n\
After=local-fs.target\n\
Before=basic.target\n\
\n\
[Service]\n\
Type=oneshot\n\
User=root\n\
StandardOutput=tty\n\
StandardError=tty\n\
TTYPath=/dev/ttyS0\n\
ExecStart=/usr/local/bin/swapfile_probe\n\
\n\
[Install]\n\
WantedBy=basic.target\n";
    std::fs::write(&path, body).map_err(|e| { eprintln!("xtask rootfs: write service failed: {e}"); 1u8 })?;
    Ok(path)
}
