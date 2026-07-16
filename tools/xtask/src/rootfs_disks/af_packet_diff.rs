use std::path::{Path, PathBuf};
use std::process::Command;
use crate::cmds::run;

const ARM_SYSROOT: &str = "/usr/aarch64-redhat-linux/sys-root/fc42";
const SOURCES: [&str; 8] = [
    "userspace/af_packet_diff/main.c",
    "userspace/af_packet_diff/common.c",
    "userspace/af_packet_diff/options.c",
    "userspace/af_packet_diff/rings.c",
    "userspace/af_packet_diff/fanout.c",
    "userspace/af_packet_diff/runtime.c",
    "userspace/af_packet_diff/extended.c",
    "userspace/af_packet_diff/recvfrom.c",
];

pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    let bin = build_probe(arch)?;
    let service = write_service()?;
    super::dbg(root_img, "mkdir /etc/systemd/system")?;
    super::dbg(root_img, "mkdir /etc/systemd/system/basic.target.wants")?;
    super::dbg_ignore(root_img, "rm /usr/local/bin/af_packet_diff");
    super::dbg(root_img, &format!("write {} /usr/local/bin/af_packet_diff", bin.display()))?;
    super::dbg(root_img, "sif /usr/local/bin/af_packet_diff mode 0100755")?;
    super::dbg_ignore(root_img, "rm /etc/systemd/system/af-packet-diff-smoke.service");
    super::dbg(root_img, &format!("write {} /etc/systemd/system/af-packet-diff-smoke.service", service.display()))?;
    super::dbg_ignore(root_img, "rm /etc/systemd/system/basic.target.wants/af-packet-diff-smoke.service");
    super::dbg(root_img, "symlink /etc/systemd/system/basic.target.wants/af-packet-diff-smoke.service ../af-packet-diff-smoke.service")?;
    eprintln!("xtask rootfs: injected AF_PACKET differential smoke into {}", root_img.display());
    Ok(())
}

fn build_probe(arch: &str) -> Result<PathBuf, u8> {
    let (cc, sysroot) = match arch {
        "x86_64"  => ("gcc", None),
        "aarch64" => ("aarch64-linux-gnu-gcc", Some(ARM_SYSROOT)),
        _ => { eprintln!("xtask rootfs: unsupported arch `{arch}` for AF_PACKET differential smoke"); return Err(2); }
    };
    if let Some(path) = sysroot {
        if !Path::new(path).is_dir() {
            eprintln!("xtask rootfs: missing {path} for AF_PACKET differential smoke");
            return Err(2);
        }
    }
    let out_dir = PathBuf::from("target").join("smoke").join(arch);
    std::fs::create_dir_all(&out_dir).map_err(|e| { eprintln!("xtask rootfs: mkdir smoke dir failed: {e}"); 1u8 })?;
    let out = out_dir.join("af_packet_diff");
    let mut c = Command::new(cc);
    if let Some(path) = sysroot { c.arg(format!("--sysroot={path}")); }
    c.args(["-O2", "-g", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread"]);
    c.args(SOURCES);
    c.arg("-o").arg(&out).arg("-pthread");
    run(c)?;
    Ok(out)
}

fn write_service() -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target").join("smoke");
    std::fs::create_dir_all(&dir).map_err(|e| { eprintln!("xtask rootfs: mkdir smoke dir failed: {e}"); 1u8 })?;
    let path = dir.join("af-packet-diff-smoke.service");
    let body = "[Unit]\n\
Description=Oxide AF_PACKET Linux differential smoke\n\
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
ExecStart=/usr/local/bin/af_packet_diff\n\
\n\
[Install]\n\
WantedBy=basic.target\n";
    std::fs::write(&path, body).map_err(|e| { eprintln!("xtask rootfs: write service failed: {e}"); 1u8 })?;
    Ok(path)
}
