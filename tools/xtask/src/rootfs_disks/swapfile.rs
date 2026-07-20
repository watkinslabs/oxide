use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cmds::run;

const X86_TRIPLET: &str = "x86_64-linux-musl";
const X86_CROSS_DIR: &str = "x86_64-linux-musl-cross";
const ARM_TRIPLET: &str = "aarch64-linux-musl";
const ARM_CROSS_DIR: &str = "aarch64-linux-musl-cross";
const PROBE_SOURCE: &str = "userspace/swapfile_probe/swapfile_probe.c";
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

fn build_probe(arch: &str) -> Result<PathBuf, u8> {
    let (triplet, cross_dir) = match arch {
        "x86_64" => (X86_TRIPLET, X86_CROSS_DIR),
        "aarch64" => (ARM_TRIPLET, ARM_CROSS_DIR),
        _ => { eprintln!("xtask rootfs: unsupported arch `{arch}` for ext4 swapfile smoke"); return Err(2); }
    };
    let cc = PathBuf::from(format!("vendor/cross/{cross_dir}/bin/{triplet}-cc"));
    if !cc.is_file() {
        eprintln!("xtask rootfs: missing {} for ext4 swapfile smoke", cc.display());
        return Err(2);
    }
    let out_dir = PathBuf::from("target").join("smoke").join(arch);
    std::fs::create_dir_all(&out_dir).map_err(|e| { eprintln!("xtask rootfs: mkdir smoke dir failed: {e}"); 1u8 })?;
    let out = out_dir.join(PROBE_NAME);
    let mut c = Command::new(cc);
    c.args(["-O2", "-static", "-Wall", "-Wextra", "-Werror", PROBE_SOURCE, "-o"]);
    c.arg(&out);
    run(c)?;
    Ok(out)
}

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
