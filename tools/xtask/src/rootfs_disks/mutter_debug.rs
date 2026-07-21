//! Opt-in GDM/Mutter diagnostic environment injection.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Install a GDM service drop-in that exports explicit, safe renderer
/// diagnostics. The host-only flags keep diagnostic behavior out of normal images.
pub(super) fn inject(root_img: &Path, mutter: Option<OsString>, clutter: Option<OsString>, override_driver: Option<OsString>) -> Result<(), u8> {
    let mutter = mutter.map(|value| safe_value("OXIDE_MUTTER_DEBUG", value, true)).transpose()?;
    let clutter = clutter.map(|value| safe_value("OXIDE_CLUTTER_DEBUG", value, true)).transpose()?;
    let override_driver = override_driver.map(|value|
        safe_value("OXIDE_MESA_LOADER_DRIVER_OVERRIDE", value, false)).transpose()?;
    let dropin = write_dropin(mutter.as_deref(), clutter.as_deref(), override_driver.as_deref())?;
    let environment = write_environment(mutter.as_deref(), clutter.as_deref(), override_driver.as_deref())?;
    debugfs(root_img, "mkdir /etc/systemd/system/gdm.service.d")?;
    let _ = debugfs(root_img, "rm /etc/systemd/system/gdm.service.d/oxide-mutter-debug.conf");
    debugfs(root_img, &format!("write {} /etc/systemd/system/gdm.service.d/oxide-mutter-debug.conf", dropin.display()))?;
    // gdm's system service does not propagate arbitrary environment entries
    // into the per-user systemd manager that owns org.gnome.Shell@wayland.
    // environment.d is the documented systemd user-manager input, so retain
    // the same opt-in diagnostics there as well.
    debugfs(root_img, "mkdir /etc/environment.d")?;
    let _ = debugfs(root_img, "rm /etc/environment.d/90-oxide-mutter-debug.conf");
    debugfs(root_img, &format!("write {} /etc/environment.d/90-oxide-mutter-debug.conf", environment.display()))?;
    eprintln!("xtask rootfs: injected Mutter/Clutter diagnostics for gdm.service");
    Ok(())
}

fn safe_value(name: &str, value: OsString, commas: bool) -> Result<String, u8> {
    let value = value.into_string().map_err(|_| {
        eprintln!("xtask rootfs: {name} must be valid UTF-8");
        2u8
    })?;
    let valid = |byte: u8| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-')
        || commas && byte == b',';
    if value.is_empty() || value.bytes().any(|byte| !valid(byte)) {
        eprintln!("xtask rootfs: {name} accepts only letters, digits, `_`, `-`, and optionally `,`");
        return Err(2);
    }
    Ok(value)
}

fn write_dropin(mutter: Option<&str>, clutter: Option<&str>, override_driver: Option<&str>) -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target").join("diagnostics");
    std::fs::create_dir_all(&dir).map_err(|err| {
        eprintln!("xtask rootfs: create diagnostics directory failed: {err}");
        1u8
    })?;
    let path = dir.join("oxide-mutter-debug.conf");
    let mutter = mutter.map(|value| format!("Environment=MUTTER_DEBUG={value}\n")).unwrap_or_default();
    let clutter = clutter.map(|value| format!("Environment=CLUTTER_DEBUG={value}\n")).unwrap_or_default();
    let override_driver = override_driver.map(|value| format!("Environment=MESA_LOADER_DRIVER_OVERRIDE={value}\n")).unwrap_or_default();
    std::fs::write(&path, format!("[Service]\n{mutter}{clutter}Environment=G_MESSAGES_DEBUG=all\nEnvironment=LIBGL_DEBUG=verbose\nEnvironment=EGL_LOG_LEVEL=debug\n{override_driver}")).map_err(|err| {
        eprintln!("xtask rootfs: write MUTTER_DEBUG drop-in failed: {err}");
        1u8
    })?;
    Ok(path)
}

fn write_environment(mutter: Option<&str>, clutter: Option<&str>, override_driver: Option<&str>) -> Result<PathBuf, u8> {
    let dir = PathBuf::from("target").join("diagnostics");
    let path = dir.join("oxide-mutter-debug.env");
    let mutter = mutter.map(|value| format!("MUTTER_DEBUG={value}\n")).unwrap_or_default();
    let clutter = clutter.map(|value| format!("CLUTTER_DEBUG={value}\n")).unwrap_or_default();
    let override_driver = override_driver.map(|value| format!("MESA_LOADER_DRIVER_OVERRIDE={value}\n")).unwrap_or_default();
    std::fs::write(&path, format!("{mutter}{clutter}{override_driver}G_MESSAGES_DEBUG=all\nLIBGL_DEBUG=verbose\nEGL_LOG_LEVEL=debug\n")).map_err(|err| {
        eprintln!("xtask rootfs: write environment.d diagnostic failed: {err}");
        1u8
    })?;
    Ok(path)
}

fn debugfs(img: &Path, request: &str) -> Result<(), u8> {
    let mut command = Command::new("debugfs");
    command.args(["-w", "-R", request, img.to_str().unwrap()]);
    command.stdout(std::process::Stdio::null());
    command.stderr(std::process::Stdio::null());
    if command.status().map(|status| status.success()).unwrap_or(false) {
        Ok(())
    } else {
        eprintln!("xtask rootfs: debugfs `{request}` failed");
        Err(2)
    }
}
