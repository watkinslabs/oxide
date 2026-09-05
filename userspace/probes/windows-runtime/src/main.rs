//! Small command-line entry point for the Windows handoff launcher.

use std::env;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::ExitCode;

use windows_runtime::RuntimeRequest;

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    if args.next().as_deref().is_some_and(|arg| arg == std::ffi::OsStr::new("--preflight")) {
        return preflight(&mut args);
    }
    let Some(image) = args.next() else { usage(); return ExitCode::from(2); };
    let Some(windows_path) = args.next() else { usage(); return ExitCode::from(2); };
    let Some(dll_dir) = args.next() else { usage(); return ExitCode::from(2); };
    if args.next().is_some() { usage(); return ExitCode::from(2); }

    let image = PathBuf::from(image);
    let dll_dir = PathBuf::from(dll_dir);
    let windows_path = windows_path.as_os_str().as_bytes();
    let profile = match windows_runtime::RuntimeProfile::from_environment(&dll_dir) {
        Ok(profile) => profile,
        Err(error) => { eprintln!("cannot resolve Windows runtime profile: {error:?}"); return ExitCode::from(1); }
    };
    let unixlib_dir = env::var_os("OXIDE_WINE_UNIXLIB_DIR").map(PathBuf::from).unwrap_or_else(|| dll_dir.parent().unwrap_or(&dll_dir).join("x86_64-unix"));
    let nls_path = env::var_os("OXIDE_WINE_NLS_PATH").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/usr/share/wine/nls/locale.nls"));
    let Some(registry_socket) = env::var_os("OXIDE_REGISTRY_SOCKET").map(PathBuf::from) else { eprintln!("windows-runtime: registry preflight requires OXIDE_REGISTRY_SOCKET"); return ExitCode::from(1); };
    let Some(registry_database) = env::var_os("OXIDE_REGISTRY_DATABASE").map(PathBuf::from) else { eprintln!("windows-runtime: registry preflight requires OXIDE_REGISTRY_DATABASE"); return ExitCode::from(1); };
    match RuntimeRequest::preflight(&image, windows_path, &dll_dir, &unixlib_dir, &nls_path, &registry_socket, &registry_database) {
        Ok(report) => eprintln!("windows-runtime: boot-artifact preflight passed image_bytes={} modules={} execution=not_attempted", report.image_bytes, report.module_count),
        Err(error) => { eprintln!("windows-runtime: boot-artifact preflight failed: {error}"); return ExitCode::from(1); }
    }
    let request = match RuntimeRequest::from_paths_with_environment(&image, windows_path, windows_path, &dll_dir, profile.environment().into_iter().chain(env::vars())) {
        Ok(request) => request,
        Err(error) => { eprintln!("cannot build Windows handoff: {error:?}"); return ExitCode::from(1); }
    };
    eprintln!("windows-runtime: execute-with-catalog modules={}", request.module_count());
    match request.execute_raw() {
        Ok(status) if status == 0 => { println!("Windows image committed: NTSTATUS=0x{status:08x}"); ExitCode::SUCCESS }
        Ok(status) => { eprintln!("Windows handoff rejected: NTSTATUS=0x{status:08x}"); ExitCode::from(1) }
        Err(error) => { eprintln!("Windows handoff failed: {error}"); ExitCode::from(1) }
    }
}

fn preflight(args: &mut impl Iterator<Item = std::ffi::OsString>) -> ExitCode {
    let values = args.map(PathBuf::from).collect::<Vec<_>>();
    if values.len() != 6 { usage(); return ExitCode::from(2); }
    match windows_runtime::RuntimeRequest::preflight(&values[0], b"C:\\notepad.exe", &values[1], &values[2], &values[3], &values[4], &values[5]) {
        Ok(report) => { println!("windows-runtime: PREFLIGHT PASS image_bytes={} modules={} execution=not_attempted", report.image_bytes, report.module_count); for check in report.checks.iter() { println!("windows-runtime: PREFLIGHT CHECK {check}"); } ExitCode::SUCCESS }
        Err(error) => { eprintln!("windows-runtime: PREFLIGHT FAIL {error}"); ExitCode::from(1) }
    }
}

fn usage() {
    eprintln!("usage: windows-runtime --preflight <image> <dll-directory> <unixlib-directory> <nls-file> <registry-socket> <registry-database> | <linux-image-path> <windows-image-path> <dll-directory>");
}
