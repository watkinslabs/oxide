//! Rootfs injection for the x86_64 Windows PE handoff smoke.

use std::path::Path;
use std::process::Command;
use std::fs;

use super::{dbg, probe_cargo, probe_cargo_bin};

/// Inject the Linux-personality launcher used by the Notepad boot probe.
/// # C: O(cargo)
pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    if arch != "x86_64" {
        eprintln!("xtask rootfs: Windows Notepad smoke requires x86_64, got {arch}");
        return Err(2);
    }
    let launcher = probe_cargo("x86_64", "windows-runtime")?;
    let registryd = probe_cargo_bin("x86_64", "windows-registry", "registryd")?;
    let wrapper = write_wrapper()?;
    let _ = mkdir(root_img, "/mnt");
    let _ = mkdir(root_img, "/mnt/windows");
    let _ = dbg(root_img, "rm /usr/local/bin/windows-runtime");
    dbg(root_img, &format!("write {} /usr/local/bin/windows-runtime", launcher.display()))?;
    dbg(root_img, "sif /usr/local/bin/windows-runtime mode 0100755")?;
    let _ = dbg(root_img, "rm /usr/local/bin/registryd");
    dbg(root_img, &format!("write {} /usr/local/bin/registryd", registryd.display()))?;
    dbg(root_img, "sif /usr/local/bin/registryd mode 0100755")?;
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
    fs::write(&path, wrapper_script()).map_err(|_| 1u8)?;
    Ok(path)
}

fn wrapper_script() -> &'static [u8] {
b"#!/bin/sh\nmkdir -p /mnt/windows /usr/share/wine/nls /run/oxide /var/lib/oxide /var/lib/oxide/prefix || exit 1\nrm -f /run/oxide/registry.sock\n/usr/local/bin/registryd /run/oxide/registry.sock /var/lib/oxide/registry.db >/run/oxide/registryd.log 2>&1 &\nregistryd_pid=$!\ntrap 'kill $registryd_pid 2>/dev/null || true' EXIT\nregistryd_ready=0\nregistryd_wait=0\nwhile [ \"$registryd_wait\" -lt 100 ]; do\n    if [ -S /run/oxide/registry.sock ]; then registryd_ready=1; break; fi\n    kill -0 $registryd_pid 2>/dev/null || exit 9\n    registryd_wait=$((registryd_wait + 1))\n    sleep 0.1\ndone\n[ \"$registryd_ready\" -eq 1 ] || exit 10\nmount -t 9p -o trans=virtio,version=9P2000.L,msize=131096 windowswine /mnt/windows || exit 1\nmount -t 9p -o trans=virtio,version=9P2000.L,msize=131096 winenls /usr/share/wine/nls || exit 1\nls -ld /mnt/windows/x86_64-windows /mnt/windows/x86_64-windows/notepad.exe || exit 2\nhead -c 2 /mnt/windows/x86_64-windows/notepad.exe >/dev/null || exit 4\nls /mnt/windows/x86_64-windows >/dev/null || exit 3\nls -ld /mnt/windows/x86_64-unix || { echo '[WINDOWS-PE-UNIXLIB] missing sidecar directory' >&2; exit 11; }\nfor sidecar in ntdll.so win32u.so; do\n    [ -f /mnt/windows/x86_64-unix/$sidecar ] || { echo \"[WINDOWS-PE-UNIXLIB] missing $sidecar\" >&2; exit 12; }\ndone\necho '[WINDOWS-PE-UNIXLIB] sidecars=ntdll.so,win32u.so state=present'\nls -l /usr/share/wine/nls/locale.nls || exit 7\ndd if=/usr/share/wine/nls/locale.nls of=/dev/null bs=4096 count=1 status=none || exit 8\ndd if=/mnt/windows/x86_64-windows/notepad.exe of=/dev/null bs=65536 count=1 status=none || exit 5\ndd if=/mnt/windows/x86_64-windows/notepad.exe of=/dev/null bs=1048576 count=1 status=none || exit 6\nexec /usr/local/bin/windows-runtime --launch /mnt/windows/x86_64-windows/notepad.exe 'C:\\notepad.exe' 'C:\\notepad.exe' x86_64 /var/lib/oxide/prefix /mnt/windows /mnt/windows/x86_64-windows /mnt/windows/x86_64-unix /usr/share/wine/nls/locale.nls /run/oxide/registry.sock /var/lib/oxide/registry.db /mnt/windows/dxvk /mnt/windows/vkd3d-proton /mnt/windows/faudio\n"
}

#[cfg(test)]
mod tests {
    use super::wrapper_script;

    #[test]
    fn notepad_wrapper_starts_the_canonical_registry_owner_before_handoff() {
        let script = core::str::from_utf8(wrapper_script()).unwrap();
        assert!(script.contains("/usr/local/bin/registryd /run/oxide/registry.sock /var/lib/oxide/registry.db"));
        assert!(script.contains(" /run/oxide/registry.sock /var/lib/oxide/registry.db /mnt/windows/dxvk"));
        assert!(script.contains("trap 'kill $registryd_pid"));
        assert!(script.contains("registryd_ready=0"));
        assert!(script.contains("[ -S /run/oxide/registry.sock ]"));
        assert!(script.contains("kill -0 $registryd_pid"));
        assert!(script.contains("/mnt/windows/x86_64-unix"));
        assert!(script.contains("for sidecar in ntdll.so win32u.so"));
        assert!(script.contains("[WINDOWS-PE-UNIXLIB] sidecars=ntdll.so,win32u.so state=present"));
        assert!(script.contains("exec /usr/local/bin/windows-runtime"));
        assert!(script.contains("--launch"));
        assert!(script.contains(" x86_64 /var/lib/oxide/prefix /mnt/windows "));
    }

    #[test]
    fn notepad_wrapper_rejects_a_missing_unixlib_before_pe_handoff() {
        let script = core::str::from_utf8(wrapper_script()).unwrap();
        let sidecar_check = script.find("for sidecar in ntdll.so win32u.so").unwrap();
        let handoff = script.find("exec /usr/local/bin/windows-runtime").unwrap();
        assert!(sidecar_check < handoff);
        assert!(script.contains("exit 11"));
        assert!(script.contains("exit 12"));
    }
}

fn mkdir(img: &Path, path: &str) -> Result<(), u8> {
    let mut c = Command::new("debugfs");
    c.args(["-w", "-R", &format!("mkdir {path}"), img.to_str().unwrap()]);
    c.stdout(std::process::Stdio::null());
    c.stderr(std::process::Stdio::null());
    if c.status().map(|s| s.success()).unwrap_or(false) { Ok(()) } else { Err(2) }
}
