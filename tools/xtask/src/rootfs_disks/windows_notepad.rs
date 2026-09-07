//! Image-owned x86_64 Windows runtime staging for the Notepad smoke.

use std::fs;
use std::path::{Path, PathBuf};

use super::{dbg, dbg_ignore, probe_cargo, probe_cargo_bin};
mod catalog;
mod payload;

use catalog::{UNIXLIB_DIR, WINDOWS_DIR};

const IMAGE_ROOT: &str = "/usr/local/lib/oxide/windows";
const WINE_COMPAT_WINDOWS_DIR: &str = "/usr/lib/wine/x86_64-windows";
const WINE64_COMPAT_WINDOWS_DIR: &str = "/usr/lib64/wine/x86_64-windows";
const NLS_PATH: &str = "/usr/local/share/oxide/windows/nls/locale.nls";
const CONFIG_PATH: &str = "/etc/oxide/windows-runtime.conf";
const DESKTOP_PATH: &str = "/usr/share/applications/oxide-notepad.desktop";
const MIMEAPPS_PATH: &str = "/etc/xdg/mimeapps.list";
const PREFIX_DIR: &str = "/var/lib/oxide/windows-prefix";
// The native DOS drive namespace. A drive letter directory under the DOS root
// is the drive, exactly as a prefix `dosdevices` entry is: `c` is the system
// drive whose `windows/system32` holds every loadable module, and `z` is the
// link to the Unix root. Nothing maps a drive letter in code.
const DOS_ROOT: &str = "/windows";
const DOS_DRIVE_C: &str = "/windows/c";
const DOS_C_WINDOWS: &str = "/windows/c/windows";
const DOS_SYSTEM32: &str = "/windows/c/windows/system32";
const DOS_DRIVE_Z: &str = "/windows/z";
const UNIX_ROOT: &str = "/";
/// The image path the launch script names, which only its test reads back.
#[cfg(test)]
const IMAGE_WINDOWS_PATH: &str = r"C:\windows\system32\notepad.exe";
const REGISTRY_DB: &str = "/var/lib/oxide/registry.db";
const REGISTRY_SOCKET: &str = "/run/oxide/registry.sock";
const EMPTY_REGISTRY: &[u8] = b"OXREG\0\x01\0\0\0\0\0";

/// Stage the complete 64-bit launcher boundary into the boot root image.
/// # C: O(cargo + Wine catalog files + debugfs writes)
pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    if arch != "x86_64" { eprintln!("xtask rootfs: Windows runtime staging requires x86_64, got {arch}"); return Err(2); }
    // The Windows runtime is installed by the image compose from the
    // `oxide-wine` package this tree builds. Staging owns the launch
    // boundary around it and copies no Windows module from the build host.
    let wine = catalog::verify(root_img)?;
    let launcher = probe_cargo("x86_64", "windows-runtime")?;
    let compositor = probe_cargo("x86_64", "windows-compositor")?;
    let registryd = probe_cargo_bin("x86_64", "windows-registry", "registryd")?;
    verify_elf_dependencies(root_img, &[&launcher, &compositor, &registryd])?;
    let wrapper = write_wrapper()?;
    let config = write_config()?;
    let desktop = write_desktop_entry()?;
    let mimeapps = write_mimeapps()?;
    let registry_db = write_registry_seed()?;
    for dir in ["/usr/share/applications", "/etc/xdg", "/etc/oxide", "/var/lib/oxide", PREFIX_DIR, DOS_ROOT, DOS_DRIVE_C, DOS_C_WINDOWS, "/usr/lib/wine", "/usr/lib64/wine", format!("{IMAGE_ROOT}/dxvk").as_str(), format!("{IMAGE_ROOT}/vkd3d-proton").as_str(), format!("{IMAGE_ROOT}/faudio").as_str()] { mkdir(root_img, dir)?; }
    stage_file(root_img, &launcher, "/usr/local/bin/windows-runtime", "launcher", "0100755")?;
    stage_file(root_img, &compositor, "/usr/local/bin/windows-compositor", "GNOME Windows bridge", "0100755")?;
    stage_file(root_img, &registryd, "/usr/local/bin/registryd", "registryd", "0100755")?;
    stage_file(root_img, &wrapper, "/usr/local/bin/windows-notepad-smoke", "wrapper", "0100755")?;
    stage_file(root_img, &desktop, DESKTOP_PATH, "Notepad desktop entry", "0100644")?;
    stage_file(root_img, &mimeapps, MIMEAPPS_PATH, "Windows executable MIME association", "0100644")?;
    stage_file(root_img, &config, CONFIG_PATH, "configuration", "0100644")?;
    stage_file(root_img, &registry_db, REGISTRY_DB, "registry seed", "0100644")?;
    // Preserve the Oxide-owned catalog as the source of truth while exposing
    // the conventional Wine lookup path inside the generated image.
    let _ = dbg(root_img, &format!("rm {WINE_COMPAT_WINDOWS_DIR}"));
    dbg(root_img, &format!("symlink {WINE_COMPAT_WINDOWS_DIR} {WINDOWS_DIR}"))?;
    let _ = dbg(root_img, &format!("rm {WINE64_COMPAT_WINDOWS_DIR}"));
    dbg(root_img, &format!("symlink {WINE64_COMPAT_WINDOWS_DIR} {WINDOWS_DIR}"))?;
    // The system drive resolves to the one staged catalog rather than a second
    // copy of it: a duplicate set could disagree with the modules the launch
    // admits, and the loader and every native file open reach the same bytes
    // through the same drive letter.
    let _ = dbg(root_img, &format!("rm {DOS_SYSTEM32}"));
    dbg(root_img, &format!("symlink {DOS_SYSTEM32} {WINDOWS_DIR}"))?;
    let _ = dbg(root_img, &format!("rm {DOS_DRIVE_Z}"));
    dbg(root_img, &format!("symlink {DOS_DRIVE_Z} {UNIX_ROOT}"))?;
    payload::verify(root_img, &wine.version)?;
    eprintln!("xtask rootfs: staged Windows runtime image boundary wine={} PE_DLLS={} UNIXLIBS={} root={}", wine.version, wine.modules, wine.unixlibs, root_img.display());
    Ok(())
}

fn require_file(path: &Path, label: &str) -> Result<(), u8> { if path.is_file() && fs::metadata(path).map(|m| m.len() > 0).unwrap_or(false) { Ok(()) } else { eprintln!("xtask rootfs: {label} missing or empty at {}", path.display()); Err(2) } }
fn stage_file(image: &Path, source: &Path, destination: &str, label: &str, mode: &str) -> Result<(), u8> { require_file(source, label)?; let _ = dbg(image, &format!("rm {destination}")); dbg(image, &format!("write {} {destination}", source.display()))?; dbg(image, &format!("sif {destination} mode {mode}")) }
fn mkdir(image: &Path, path: &str) -> Result<(), u8> {
    // debugfs returns success for `stat` even when it prints "File not found",
    // so a stat-first existence test silently skipped every missing parent.
    // mkdir is idempotent for this staging boundary: tolerate EEXIST and let
    // the ordered list above establish each parent before its children.
    dbg_ignore(image, &format!("mkdir {path}"));
    Ok(())
}

fn verify_elf_dependencies(image: &Path, roots: &[&PathBuf]) -> Result<(), u8> {
    let temporary = Path::new("target/smoke");
    fs::create_dir_all(temporary).map_err(|_| 1u8)?;
    let mut command = std::process::Command::new("python3");
    command.arg("tools/windows-rootfs-elf-check.py").arg("--image").arg(image)
        .arg("--temp-dir").arg(temporary);
    for root in roots { command.arg("--elf").arg(root); }
    match command.status() {
        Ok(status) if status.success() => Ok(()),
        _ => { eprintln!("xtask rootfs: Windows runtime ELF dependency gate failed before staging"); Err(2) }
    }
}

fn write_wrapper() -> Result<PathBuf, u8> { let path = PathBuf::from("target/smoke/windows-notepad-smoke"); fs::create_dir_all(path.parent().unwrap()).map_err(|_| 1u8)?; fs::write(&path, wrapper_script()).map_err(|_| 1u8)?; Ok(path) }
fn write_desktop_entry() -> Result<PathBuf, u8> { let path = PathBuf::from("target/smoke/oxide-notepad.desktop"); fs::create_dir_all(path.parent().unwrap()).map_err(|_| 1u8)?; fs::write(&path, b"[Desktop Entry]\nType=Application\nName=Oxide Notepad\nComment=Run the staged Windows Notepad through the Oxide NT runtime\nExec=/usr/local/bin/windows-notepad-smoke\nTerminal=false\nCategories=Utility;TextEditor;\nMimeType=application/x-ms-dos-executable;application/x-msdownload;\n").map_err(|_| 1u8)?; Ok(path) }
fn write_mimeapps() -> Result<PathBuf, u8> { let path = PathBuf::from("target/smoke/mimeapps.list"); fs::create_dir_all(path.parent().unwrap()).map_err(|_| 1u8)?; fs::write(&path, b"[Default Applications]\napplication/x-ms-dos-executable=oxide-notepad.desktop\napplication/x-msdownload=oxide-notepad.desktop\n").map_err(|_| 1u8)?; Ok(path) }
fn write_config() -> Result<PathBuf, u8> { let path = PathBuf::from("target/smoke/windows-runtime.conf"); fs::create_dir_all(path.parent().unwrap()).map_err(|_| 1u8)?; fs::write(&path, format!("OXIDE_WINDOWS_PREFIX={PREFIX_DIR}\nOXIDE_WINDOWS_RUNTIME={IMAGE_ROOT}\nOXIDE_WINDOWS_DLL_CATALOG={WINDOWS_DIR}\nOXIDE_WINDOWS_UNIXLIB={UNIXLIB_DIR}\nOXIDE_WINDOWS_NLS={NLS_PATH}\nOXIDE_WINDOWS_REGISTRY_SOCKET={REGISTRY_SOCKET}\nOXIDE_WINDOWS_REGISTRY_DATABASE={REGISTRY_DB}\nOXIDE_WINDOWS_DXVK={IMAGE_ROOT}/dxvk\nOXIDE_WINDOWS_VKD3D={IMAGE_ROOT}/vkd3d-proton\nOXIDE_WINDOWS_FAUDIO={IMAGE_ROOT}/faudio\n")).map_err(|_| 1u8)?; Ok(path) }
fn write_registry_seed() -> Result<PathBuf, u8> { let path = PathBuf::from("target/smoke/oxide-registry.empty"); fs::create_dir_all(path.parent().unwrap()).map_err(|_| 1u8)?; fs::write(&path, EMPTY_REGISTRY).map_err(|_| 1u8)?; Ok(path) }

fn wrapper_script() -> &'static [u8] {
    br#"#!/bin/sh
set -eu
. /etc/oxide/windows-runtime.conf
# The configuration supplies image-owned read-only inputs. The per-user prefix,
# database and socket come from the runtime itself, which owns that policy: a
# normal user cannot write the root-owned defaults, and duplicating the
# selection in shell would be a second source of truth for it.
# A failed selection must stop the launch. Substituting straight into eval
# would discard its exit status and leave the root-owned configuration
# defaults in place, which is how a normal user reached /run/oxide at all.
# The compositor bridge needs the session's X display. gnome-shell creates
# that display after it starts, so its own environment never carries DISPLAY
# and neither does anything launched from a copy of it. A systemd user session
# publishes session-wide variables to the user manager for exactly this reason,
# so they are imported from there rather than guessed.
for name in DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS; do
    eval "value=\${$name:-}"
    if [ -z "$value" ]; then
        value=$(systemctl --user show-environment 2>/dev/null | sed -n "s/^$name=//p" | head -1)
        if [ -n "$value" ]; then eval "export $name=\$value"; fi
    fi
done
if [ -z "${DISPLAY:-}" ]; then
    printf '[WINDOWS-NOTEPAD] runtime-exit status=12 no-session-display\n'
    exit 12
fi
user_paths=$(/usr/local/bin/windows-runtime --user-paths) || exit 11
eval "$user_paths"
export OXIDE_WINDOWS_PREFIX OXIDE_WINDOWS_REGISTRY_DATABASE OXIDE_WINDOWS_REGISTRY_SOCKET
mkdir -p "$OXIDE_WINDOWS_PREFIX"
# One shared service per user database. The daemon takes the database lock
# before it touches the socket and exits successfully when another service
# already holds it, so starting it here can neither unlink a live endpoint nor
# produce a second owner. It is deliberately not killed on exit: the service
# outlives any one application, exactly as other per-user session services do.
/usr/local/bin/registryd "$OXIDE_WINDOWS_REGISTRY_SOCKET" "$OXIDE_WINDOWS_REGISTRY_DATABASE" >>"$(dirname "$OXIDE_WINDOWS_REGISTRY_SOCKET")/registryd.log" 2>&1 &
for attempt in $(seq 1 100); do
    [ -S "$OXIDE_WINDOWS_REGISTRY_SOCKET" ] && break
    sleep 0.1
done
[ -S "$OXIDE_WINDOWS_REGISTRY_SOCKET" ] || exit 10
# A launch from the desktop sends its diagnostics to the session, where they
# are invisible to anyone debugging the guest: two failures were narrowed only
# because a scripted run happened to put the same output on the console. Keep a
# copy beside the runtime state, and still write to stderr so a scripted run is
# unchanged. The fifo is used rather than a pipeline so the launch's own exit
# status is preserved.
# The runtime state directory is a tmpfs that does not survive the guest, so
# the log goes beside the prefix, which does. The launch writes its stderr
# there, and a follower copies the file to the real stderr *while the launch
# runs*: an acceptance run stops the guest with Notepad still up, so a replay
# that only happens once the launch returns never happens at all, and the
# bridge's own diagnostics -- the whole reason this capture exists -- were
# absent from every console log. The follower is used rather than a pipeline
# so the launch's own exit status is preserved.
oxide_log="$OXIDE_WINDOWS_PREFIX/windows-launch.log"
: > "$oxide_log" 2>/dev/null || oxide_log=/dev/null
follower=""
if [ "$oxide_log" != /dev/null ]; then tail -n +1 -f "$oxide_log" >&2 & follower=$!; fi
status=0
/usr/local/bin/windows-runtime --launch "$OXIDE_WINDOWS_DLL_CATALOG/notepad.exe" 'C:\windows\system32\notepad.exe' 'C:\windows\system32\notepad.exe' x86_64 "$OXIDE_WINDOWS_PREFIX" "$OXIDE_WINDOWS_RUNTIME" "$OXIDE_WINDOWS_DLL_CATALOG" "$OXIDE_WINDOWS_UNIXLIB" "$OXIDE_WINDOWS_NLS" "$OXIDE_WINDOWS_REGISTRY_SOCKET" "$OXIDE_WINDOWS_REGISTRY_DATABASE" 2>"$oxide_log" || status=$?
if [ -n "$follower" ]; then
    # Let the follower drain what the launch wrote last, then stop it.
    sleep 1
    kill "$follower" 2>/dev/null || true
    wait "$follower" 2>/dev/null || true
else
    cat "$oxide_log" >&2 2>/dev/null || true
fi
printf '[WINDOWS-NOTEPAD] runtime-exit status=%s\n' "$status"
exit "$status"
"#
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_and_wrapper_use_only_image_owned_paths() {
        let config = String::from_utf8(fs::read(write_config().unwrap()).unwrap()).unwrap(); assert!(config.contains(WINDOWS_DIR)); assert!(!config.contains("/usr/lib64/wine"));
        let script = std::str::from_utf8(wrapper_script()).unwrap(); assert!(script.contains(". /etc/oxide/windows-runtime.conf")); assert!(!script.contains("mount -t 9p")); assert!(script.contains("/usr/local/bin/windows-runtime --launch")); assert!(script.contains("[WINDOWS-NOTEPAD] runtime-exit status=")); let _ = fs::remove_file("target/smoke/windows-runtime.conf");
        // A normal user owns none of the root defaults, so the wrapper must
        // take its writable paths from the runtime's own selection.
        assert!(script.contains("windows-runtime --user-paths"), "wrapper must consume per-user path selection");
        // Removing a live endpoint or killing the service on one application's
        // exit is what made a second Windows application fail; neither may return.
        assert!(!script.contains("rm -f \"$OXIDE_WINDOWS_REGISTRY_SOCKET\""), "wrapper must not unlink a possibly live socket");
        assert!(!script.contains("kill $registryd_pid"), "wrapper must not kill the shared service");
        assert!(!script.contains("mkdir -p /run/oxide"), "wrapper must not require root-owned runtime directories");
        // Substituting straight into eval discards the selector's exit status,
        // which silently left the root-owned configuration defaults in place.
        assert!(script.contains("|| exit 11"), "a failed path selection must stop the launch");
        // gnome-shell creates the X display after it starts, so its own
        // environment never carries DISPLAY: the session publishes it to the
        // user manager, and that is where it must come from.
        assert!(script.contains("systemctl --user show-environment"), "wrapper must import the session display");
        assert!(script.contains("no-session-display"), "a session with no display must say so, not fail obscurely");
        // A desktop launch sends diagnostics to the session where nobody can
        // read them; the failures so far were narrowed only from a console run.
        assert!(script.contains("windows-launch.log"), "a desktop launch must leave its diagnostics on disk");
        assert!(!script.contains("mkfifo"), "the fifo capture lost the bridge child's output");
        assert!(!script.contains("eval \"$(/usr/local/bin/windows-runtime"), "path selection status must not be discarded");
        // The application directory the loader searches comes from this image
        // path. Naming the drive root left every runtime module lookup outside
        // the launch-time catalog with nowhere on the image to resolve.
        assert!(script.contains(&format!("'{IMAGE_WINDOWS_PATH}' '{IMAGE_WINDOWS_PATH}'")), "launch must name the system-directory image path");
    }
    #[test]
    fn registry_seed_is_versioned_and_not_executable() { assert_eq!(EMPTY_REGISTRY, b"OXREG\0\x01\0\0\0\0\0"); }
    /// Nothing in staging may read a Wine the build host installed: the
    /// image's own packaged tree is the only catalog. The conventional Wine
    /// lookup paths still appear as symlinks *inside* the image, so each is
    /// checked to be a guest symlink target and nothing else.
    #[test]
    fn staging_reads_no_host_wine_path_and_takes_no_wine_path_from_the_environment() {
        // The staging half only: this test names the forbidden paths itself.
        let source = include_str!("windows_notepad.rs").split("#[cfg(test)]").next().unwrap();
        for host in ["/usr/share/wine", "OXIDE_WINE_RUNTIME_ROOT", "OXIDE_WINE_NTDLL", "OXIDE_WINE_WIN32U", "OXIDE_WINE_NLS"] {
            assert!(!source.contains(host), "staging must not name {host}");
        }
        for guest in [WINE_COMPAT_WINDOWS_DIR, WINE64_COMPAT_WINDOWS_DIR] {
            let quoted = format!("\"{guest}\"");
            assert_eq!(source.matches(&quoted).count(), 1, "{guest} may only be the guest symlink constant");
        }
        assert!(!source.contains("var_os(\"OXIDE_WINE"), "no Wine path may enter through the environment");
    }
}
