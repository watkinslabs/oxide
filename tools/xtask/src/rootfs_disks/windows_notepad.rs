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
fs::write(&path, b"#!/bin/sh\nmkdir -p /mnt/windows /usr/share/wine/nls || exit 1\nmount -t 9p -o trans=virtio,version=9P2000.L,msize=131096 windowswine /mnt/windows || exit 1\nmount -t 9p -o trans=virtio,version=9P2000.L,msize=131096 winenls /usr/share/wine/nls || exit 1\nls -ld /mnt/windows/x86_64-windows /mnt/windows/x86_64-windows/notepad.exe || exit 2\nhead -c 2 /mnt/windows/x86_64-windows/notepad.exe >/dev/null || exit 4\nls /mnt/windows/x86_64-windows >/dev/null || exit 3\nls -l /usr/share/wine/nls/locale.nls || exit 7\ndd if=/usr/share/wine/nls/locale.nls of=/dev/null bs=4096 count=1 status=none || exit 8\ndd if=/mnt/windows/x86_64-windows/notepad.exe of=/dev/null bs=65536 count=1 status=none || exit 5\ndd if=/mnt/windows/x86_64-windows/notepad.exe of=/dev/null bs=1048576 count=1 status=none || exit 6\nexec /usr/local/bin/windows-runtime /mnt/windows/x86_64-windows/notepad.exe 'C:\\notepad.exe' /mnt/windows/x86_64-windows\n").map_err(|_| 1u8)?;
    Ok(path)
}

fn mkdir(img: &Path, path: &str) -> Result<(), u8> {
    let mut c = Command::new("debugfs");
    c.args(["-w", "-R", &format!("mkdir {path}"), img.to_str().unwrap()]);
    c.stdout(std::process::Stdio::null());
    c.stderr(std::process::Stdio::null());
    if c.status().map(|s| s.success()).unwrap_or(false) { Ok(()) } else { Err(2) }
}
