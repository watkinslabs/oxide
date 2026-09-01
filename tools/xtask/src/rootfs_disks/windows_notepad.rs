//! Rootfs injection for the x86_64 Windows PE handoff smoke.

use std::path::Path;
use std::process::Command;
use std::fs;

use super::{dbg, probe_cargo};

/// Inject the Linux-personality launcher used by the Notepad boot probe.
/// # C: O(cargo)
pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    if arch != "x86_64" {
        eprintln!("xtask rootfs: Windows Notepad smoke requires x86_64, got {arch}");
        return Err(2);
    }
    let launcher = probe_cargo("x86_64", "windows-runtime")?;
    let wrapper = write_wrapper()?;
    let _ = mkdir(root_img, "/mnt");
    let _ = mkdir(root_img, "/mnt/windows");
    let _ = dbg(root_img, "rm /usr/local/bin/windows-runtime");
    dbg(root_img, &format!("write {} /usr/local/bin/windows-runtime", launcher.display()))?;
    dbg(root_img, "sif /usr/local/bin/windows-runtime mode 0100755")?;
    let _ = dbg(root_img, "rm /usr/local/bin/windows-notepad-smoke");
    dbg(root_img, &format!("write {} /usr/local/bin/windows-notepad-smoke", wrapper.display()))?;
    dbg(root_img, "sif /usr/local/bin/windows-notepad-smoke mode 0100755")?;
    eprintln!("xtask rootfs: injected Windows Notepad launcher into {}", root_img.display());
    Ok(())
}

fn write_wrapper() -> Result<std::path::PathBuf, u8> {
    let dir = std::path::PathBuf::from("target/smoke");
    fs::create_dir_all(&dir).map_err(|_| 1u8)?;
    let path = dir.join("windows-notepad-smoke");
    fs::write(&path, b"#!/bin/sh\nmount -t 9p -o trans=virtio,version=9P2000.L,msize=131096 windowswine /mnt/windows || exit 1\nls -ld /mnt/windows /mnt/windows/notepad.exe || exit 2\nls /mnt/windows >/dev/null || exit 3\nexec /usr/local/bin/windows-runtime /mnt/windows/notepad.exe 'C:\\notepad.exe' /mnt/windows\n").map_err(|_| 1u8)?;
    Ok(path)
}

fn mkdir(img: &Path, path: &str) -> Result<(), u8> {
    let mut c = Command::new("debugfs");
    c.args(["-w", "-R", &format!("mkdir {path}"), img.to_str().unwrap()]);
    c.stdout(std::process::Stdio::null());
    c.stderr(std::process::Stdio::null());
    if c.status().map(|s| s.success()).unwrap_or(false) { Ok(()) } else { Err(2) }
}
