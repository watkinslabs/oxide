use std::path::{Path, PathBuf};

const PROBE_NAME: &str = "v4l2_capture_probe";
const PROBE_DESTINATION: &str = "/usr/local/bin/v4l2_capture_probe";
const SERVICE_NAME: &str = "v4l2-capture-smoke.service";
const SERVICE_DESTINATION: &str = "/etc/systemd/system/v4l2-capture-smoke.service";
const WANTS_DIRECTORY: &str = "/etc/systemd/system/basic.target.wants";
const WANTS_DESTINATION: &str = "/etc/systemd/system/basic.target.wants/v4l2-capture-smoke.service";

/// Inject the V4L2 capture probe into one disposable boot root. # C: O(CC+debugfs)
pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    let bin = build_probe(arch)?;
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
    eprintln!("xtask rootfs: injected V4L2 capture smoke into {}", root_img.display());
    Ok(())
}

fn build_probe(arch: &str) -> Result<PathBuf, u8> { super::probe_cargo(arch, PROBE_NAME) }

/// The unit waits for the root filesystem and nothing else.
///
/// The node it opens is published by the kernel into devtmpfs before userspace
/// starts, so ordering after the device manager buys nothing and can cost
/// everything: a guest whose udev is stuck retrying a spawned helper would
/// hold the probe behind it and the gate would report a camera fault for a
/// network rule that timed out.
fn write_service(arch: &str) -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target").join("smoke");
    std::fs::create_dir_all(&dir).map_err(|e| { eprintln!("xtask rootfs: mkdir smoke dir failed: {e}"); 1u8 })?;
    let path = dir.join(SERVICE_NAME);
    let serial = crate::image_qemu::serial_device_name(arch);
    let body = format!("[Unit]\n\
Description=Oxide V4L2 capture smoke\n\
DefaultDependencies=no\n\
After=local-fs.target\n\
Before=basic.target\n\
\n\
[Service]\n\
Type=oneshot\n\
User=root\n\
StandardOutput=tty\n\
StandardError=tty\n\
TTYPath=/dev/{serial}\n\
ExecStart=/usr/local/bin/v4l2_capture_probe\n\
\n\
[Install]\n\
WantedBy=basic.target\n");
    std::fs::write(&path, body).map_err(|e| { eprintln!("xtask rootfs: write service failed: {e}"); 1u8 })?;
    Ok(path)
}
