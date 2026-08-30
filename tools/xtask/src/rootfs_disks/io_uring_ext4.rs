use std::path::{Path, PathBuf};

const PROBE_NAME: &str = "io_uring_ext4";
const PROBE_DESTINATION: &str = "/usr/local/bin/io_uring_ext4_probe";
const SERVICE_NAME: &str = "io-uring-ext4-smoke.service";
const SERVICE_DESTINATION: &str = "/etc/systemd/system/io-uring-ext4-smoke.service";
const WANTS_DESTINATION: &str = "/etc/systemd/system/basic.target.wants/io-uring-ext4-smoke.service";

/// Inject the scalar io_uring RWF durability probe into one disposable root.
pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    let bin = super::probe_cargo(arch, PROBE_NAME)?;
    let service = write_service(arch)?;
    super::dbg(root_img, "mkdir /etc/systemd/system")?;
    super::dbg(root_img, "mkdir /etc/systemd/system/basic.target.wants")?;
    super::dbg_ignore(root_img, &format!("rm {PROBE_DESTINATION}"));
    super::dbg(root_img, &format!("write {} {PROBE_DESTINATION}", bin.display()))?;
    super::dbg(root_img, &format!("sif {PROBE_DESTINATION} mode 0100755"))?;
    super::dbg_ignore(root_img, &format!("rm {SERVICE_DESTINATION}"));
    super::dbg(root_img, &format!("write {} {SERVICE_DESTINATION}", service.display()))?;
    super::dbg_ignore(root_img, &format!("rm {WANTS_DESTINATION}"));
    super::dbg(root_img, &format!("symlink {WANTS_DESTINATION} ../{SERVICE_NAME}"))?;
    eprintln!("xtask rootfs: injected io_uring ext4 smoke into {}", root_img.display());
    Ok(())
}

fn write_service(arch: &str) -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target").join("smoke");
    std::fs::create_dir_all(&dir).map_err(|e| { eprintln!("xtask rootfs: mkdir smoke dir failed: {e}"); 1u8 })?;
    let path = dir.join(SERVICE_NAME);
    let serial = crate::image_qemu::serial_device_name(arch);
    let body = format!("[Unit]\n\
Description=Oxide ext4 scalar io_uring RWF smoke\n\
After=local-fs.target\n\
\n\
[Service]\n\
Type=oneshot\n\
User=root\n\
StandardOutput=tty\n\
StandardError=tty\n\
TTYPath=/dev/{serial}\n\
ExecStart={PROBE_DESTINATION}\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n");
    std::fs::write(&path, body).map_err(|e| { eprintln!("xtask rootfs: write service failed: {e}"); 1u8 })?;
    Ok(path)
}
