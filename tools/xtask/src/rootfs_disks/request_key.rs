// Boot proof for the `request_key(2)` upcall.
//
// The helper itself is NOT injected: `/sbin/request-key` and its stock
// configuration come from the keyutils package in the image profile, so what
// this proves is the real distribution helper, not a stand-in we wrote. Only
// the probe and the unit that runs it are added here.

use std::path::{Path, PathBuf};
use std::process::Command;
use crate::cmds::run;

const SOURCE: &str = "userspace/request_key_probe/main.c";
/// The helper the kernel execs. Absent it, the probe can only report the ENOENT
/// that made this proof necessary, so the injection refuses rather than
/// producing a run whose failure would be ambiguous.
const HELPER: &str = "/sbin/request-key";

pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    require_helper(root_img)?;
    let bin = build_probe(arch)?;
    let service = write_service()?;
    super::dbg(root_img, "mkdir /etc/systemd/system")?;
    super::dbg(root_img, "mkdir /etc/systemd/system/basic.target.wants")?;
    super::dbg_ignore(root_img, "rm /usr/local/bin/request_key_probe");
    super::dbg(root_img, &format!("write {} /usr/local/bin/request_key_probe", bin.display()))?;
    super::dbg(root_img, "sif /usr/local/bin/request_key_probe mode 0100755")?;
    super::dbg_ignore(root_img, "rm /etc/systemd/system/request-key-smoke.service");
    super::dbg(root_img, &format!("write {} /etc/systemd/system/request-key-smoke.service", service.display()))?;
    super::dbg_ignore(root_img, "rm /etc/systemd/system/basic.target.wants/request-key-smoke.service");
    super::dbg(root_img, "symlink /etc/systemd/system/basic.target.wants/request-key-smoke.service ../request-key-smoke.service")?;
    eprintln!("xtask rootfs: injected request_key upcall proof into {}", root_img.display());
    Ok(())
}

/// Fail loudly when the image carries no helper: a probe that reports ENOENT
/// cannot tell a broken upcall from an image without keyutils, which is the
/// exact ambiguity this proof exists to remove.
fn require_helper(img: &Path) -> Result<(), u8> {
    let mut c = Command::new("debugfs");
    c.args(["-R", &format!("stat {HELPER}"), img.to_str().unwrap()]);
    c.stdout(std::process::Stdio::null());
    c.stderr(std::process::Stdio::null());
    if c.status().map(|s| s.success()).unwrap_or(false) { return Ok(()); }
    eprintln!("xtask rootfs: {HELPER} is not in the image — add keyutils to the images profile and rebuild");
    Err(2)
}

/// GNU cross-build, not musl: the probe reaches both syscalls through glibc's
/// `syscall(3)`, which is the entry point under test on both architectures.
fn build_probe(arch: &str) -> Result<PathBuf, u8> {
    let (cc, sysroot) = super::probe_cc(arch, "the request_key proof")?;
    let out_dir = PathBuf::from("target").join("smoke").join(arch);
    std::fs::create_dir_all(&out_dir).map_err(|e| { eprintln!("xtask rootfs: mkdir smoke dir failed: {e}"); 1u8 })?;
    let out = out_dir.join("request_key_probe");
    let mut c = Command::new(cc);
    if let Some(path) = sysroot { c.arg(format!("--sysroot={path}")); }
    c.args(["-O2", "-g", "-std=gnu11", "-Wall", "-Wextra", "-Werror"]);
    c.arg(SOURCE).arg("-o").arg(&out);
    run(c)?;
    Ok(out)
}

fn write_service() -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target").join("smoke");
    std::fs::create_dir_all(&dir).map_err(|e| { eprintln!("xtask rootfs: mkdir smoke dir failed: {e}"); 1u8 })?;
    let path = dir.join("request-key-smoke.service");
    let body = "[Unit]\n\
Description=Oxide request_key upcall proof\n\
After=basic.target\n\
\n\
[Service]\n\
Type=oneshot\n\
ExecStart=/bin/sh -c '/usr/local/bin/request_key_probe 2>&1 | /usr/bin/logger -t request-key-probe'\n\
\n\
[Install]\n\
WantedBy=basic.target\n";
    std::fs::write(&path, body).map_err(|e| { eprintln!("xtask rootfs: write service failed: {e}"); 1u8 })?;
    Ok(path)
}
