// Opt-in injection of the SOL_NETLINK / SOL_SOCKET-on-netlink-fd differential
// smoke (`userspace/probes/sockopt_diff`). Mirrors `af_packet_diff::inject`:
// a oneshot systemd service on `basic.target`, output to the serial console
// so `tools/boot-smoke-sockopt-diff.sh` can scrape and diff it against a real
// Linux run of this same binary.

use std::path::{Path, PathBuf};

pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    let bin = super::probe_cargo(arch, "sockopt_diff")?;
    let service = write_service()?;
    super::dbg(root_img, "mkdir /etc/systemd/system")?;
    super::dbg(root_img, "mkdir /etc/systemd/system/basic.target.wants")?;
    super::dbg_ignore(root_img, "rm /usr/local/bin/sockopt_diff");
    super::dbg(root_img, &format!("write {} /usr/local/bin/sockopt_diff", bin.display()))?;
    super::dbg(root_img, "sif /usr/local/bin/sockopt_diff mode 0100755")?;
    super::dbg_ignore(root_img, "rm /etc/systemd/system/sockopt-diff-smoke.service");
    super::dbg(root_img, &format!("write {} /etc/systemd/system/sockopt-diff-smoke.service", service.display()))?;
    super::dbg_ignore(root_img, "rm /etc/systemd/system/basic.target.wants/sockopt-diff-smoke.service");
    super::dbg(root_img, "symlink /etc/systemd/system/basic.target.wants/sockopt-diff-smoke.service ../sockopt-diff-smoke.service")?;
    eprintln!("xtask rootfs: injected SOL_NETLINK/SOL_SOCKET differential smoke into {}", root_img.display());
    Ok(())
}

fn write_service() -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target").join("smoke");
    std::fs::create_dir_all(&dir).map_err(|e| { eprintln!("xtask rootfs: mkdir smoke dir failed: {e}"); 1u8 })?;
    let path = dir.join("sockopt-diff-smoke.service");
    // The probe forks to drop privilege for its capability-ladder cases
    // (`sock::priv_pair`); KillMode=control-group with the default
    // TimeoutStartSec is fine here since the child always exits promptly,
    // but User=root is required for the root half of every privileged case.
    let body = "[Unit]\n\
Description=Oxide SOL_NETLINK/SOL_SOCKET Linux differential smoke\n\
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
ExecStart=/usr/local/bin/sockopt_diff\n\
\n\
[Install]\n\
WantedBy=basic.target\n";
    std::fs::write(&path, body).map_err(|e| { eprintln!("xtask rootfs: write service failed: {e}"); 1u8 })?;
    Ok(path)
}
