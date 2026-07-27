use std::path::{Path, PathBuf};
use std::process::Command;
use crate::cmds::run;

const ARM_SYSROOT: &str = "/usr/aarch64-redhat-linux/sys-root/fc42";
const SOURCES: [&str; 9] = [
    "userspace/wait_diff/main.c",
    "userspace/wait_diff/common.c",
    "userspace/wait_diff/sleep.c",
    "userspace/wait_diff/locks.c",
    "userspace/wait_diff/fdwait.c",
    "userspace/wait_diff/jobctl.c",
    "userspace/wait_diff/cputime.c",
    "userspace/wait_diff/mqueue.c",
    "userspace/wait_diff/syslog.c",
];

pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    let bin = build_probe(arch)?;
    let service = write_service()?;
    super::dbg(root_img, "mkdir /etc/systemd/system")?;
    super::dbg(root_img, "mkdir /etc/systemd/system/basic.target.wants")?;
    super::dbg_ignore(root_img, "rm /usr/local/bin/wait_diff");
    super::dbg(root_img, &format!("write {} /usr/local/bin/wait_diff", bin.display()))?;
    super::dbg(root_img, "sif /usr/local/bin/wait_diff mode 0100755")?;
    super::dbg_ignore(root_img, "rm /etc/systemd/system/wait-diff-smoke.service");
    super::dbg(root_img, &format!("write {} /etc/systemd/system/wait-diff-smoke.service", service.display()))?;
    super::dbg_ignore(root_img, "rm /etc/systemd/system/basic.target.wants/wait-diff-smoke.service");
    super::dbg(root_img, "symlink /etc/systemd/system/basic.target.wants/wait-diff-smoke.service ../wait-diff-smoke.service")?;
    eprintln!("xtask rootfs: injected interruptible-wait differential smoke into {}", root_img.display());
    Ok(())
}

/// GNU cross-build, not musl: the probe is a glibc-ABI program by
/// contract (`CLAUDE.md` ARM/x86 lockstep), and `mq_*`/`posix_openpt` are
/// exactly the glibc entry points under test.
fn build_probe(arch: &str) -> Result<PathBuf, u8> {
    let (cc, sysroot) = match arch {
        "x86_64"  => ("gcc", None),
        "aarch64" => ("aarch64-linux-gnu-gcc", Some(ARM_SYSROOT)),
        _ => { eprintln!("xtask rootfs: unsupported arch `{arch}` for wait differential smoke"); return Err(2); }
    };
    if let Some(path) = sysroot {
        if !Path::new(path).is_dir() {
            eprintln!("xtask rootfs: missing {path} for wait differential smoke");
            return Err(2);
        }
    }
    let out_dir = PathBuf::from("target").join("smoke").join(arch);
    std::fs::create_dir_all(&out_dir).map_err(|e| { eprintln!("xtask rootfs: mkdir smoke dir failed: {e}"); 1u8 })?;
    let out = out_dir.join("wait_diff");
    let mut c = Command::new(cc);
    if let Some(path) = sysroot { c.arg(format!("--sysroot={path}")); }
    c.args(["-O2", "-g", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread"]);
    c.args(SOURCES);
    c.arg("-o").arg(&out).args(["-pthread", "-lrt"]);
    run(c)?;
    Ok(out)
}

fn write_service() -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target").join("smoke");
    std::fs::create_dir_all(&dir).map_err(|e| { eprintln!("xtask rootfs: mkdir smoke dir failed: {e}"); 1u8 })?;
    let path = dir.join("wait-diff-smoke.service");
    let syslog = if std::env::var_os("OXIDE_WAIT_DIFF_SYSLOG").is_some() {
        "Environment=WAIT_DIFF_SYSLOG=1\n"
    } else { "" };
    // The probe stops and continues its own children, so it needs its own
    // control group left alone: KillMode=control-group with the default
    // TimeoutStartSec would reap a deliberately-stopped grandchild.
    let body = format!("[Unit]\n\
Description=Oxide interruptible-wait Linux differential smoke\n\
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
TimeoutStartSec=300\n\
{syslog}\
ExecStart=/usr/local/bin/wait_diff\n\
\n\
[Install]\n\
WantedBy=basic.target\n");
    std::fs::write(&path, body).map_err(|e| { eprintln!("xtask rootfs: write service failed: {e}"); 1u8 })?;
    Ok(path)
}
