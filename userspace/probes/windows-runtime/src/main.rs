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
    let values = args.collect::<Vec<_>>();
    if values.len() != 14 || values[3] != "x86_64" { usage(); return ExitCode::from(2); }
    let image = PathBuf::from(&values[0]);
    let windows_path = values[1].as_os_str().as_bytes();
    let command_line = values[2].as_os_str().as_bytes();
    let config = windows_runtime::ProtonLaunchConfig {
        architecture: windows_runtime::WindowsArchitecture::X86_64,
        prefix: PathBuf::from(&values[4]), runtime: PathBuf::from(&values[5]),
        dll_catalog: PathBuf::from(&values[6]), unixlib: PathBuf::from(&values[7]),
        nls: PathBuf::from(&values[8]), registry_socket: PathBuf::from(&values[9]),
        registry_database: PathBuf::from(&values[10]), dxvk: PathBuf::from(&values[11]),
        vkd3d: PathBuf::from(&values[12]), faudio: PathBuf::from(&values[13]),
    };
    match config.validate() {
        Ok(()) => {},
        Err(error) => { eprintln!("windows-runtime phase=preflight operation=launch_config outcome=fail error={error:?}"); return ExitCode::from(1); }
    }
    match RuntimeRequest::preflight(&image, windows_path, &config.dll_catalog, &config.unixlib, &config.nls, &config.registry_socket, &config.registry_database) {
        Ok(report) => eprintln!("windows-runtime phase=preflight operation=boot_artifact outcome=pass image_bytes={} modules={} execution=not_attempted", report.image_bytes, report.module_count),
        Err(error) => { eprintln!("windows-runtime phase=preflight operation=boot_artifact outcome=fail error={error}"); return ExitCode::from(1); }
    }
    let request = match RuntimeRequest::from_launch_config(&image, windows_path, command_line, &config) {
        Ok(request) => request,
        Err(error) => { eprintln!("windows-runtime phase=preflight operation=build_handoff outcome=fail error={error:?}"); return ExitCode::from(1); }
    };
    let selector = syscall::nt::NtService::ExecuteWithCatalog.entry();
    eprintln!("windows-runtime phase=handoff operation=execute_with_catalog outcome=attempt modules={} selector=0x{selector:016x}", request.module_count());
    match request.execute() {
        Ok(status) => { println!("windows-runtime phase=commit operation=execute_with_catalog outcome=committed ntstatus=0x{status:08x}"); ExitCode::SUCCESS }
        Err(windows_runtime::ExecuteError::KernelUnavailable { selector, errno }) => {
            eprintln!("windows-runtime phase=handoff operation=execute_with_catalog outcome=unavailable selector=0x{selector:016x} errno={errno}"); ExitCode::from(1)
        }
        Err(windows_runtime::ExecuteError::KernelRejected { selector, status }) => {
            eprintln!("windows-runtime phase=handoff operation=execute_with_catalog outcome=rejected selector=0x{selector:016x} ntstatus=0x{status:016x}"); ExitCode::from(1)
        }
        Err(windows_runtime::ExecuteError::KernelError { selector, errno }) => {
            eprintln!("windows-runtime phase=handoff operation=execute_with_catalog outcome=error selector=0x{selector:016x} errno={errno}"); ExitCode::from(1)
        }
    }
}

fn preflight(args: &mut impl Iterator<Item = std::ffi::OsString>) -> ExitCode {
    let values = args.map(PathBuf::from).collect::<Vec<_>>();
    if values.len() != 6 { usage(); return ExitCode::from(2); }
    match windows_runtime::RuntimeRequest::preflight(&values[0], b"C:\\notepad.exe", &values[1], &values[2], &values[3], &values[4], &values[5]) {
        Ok(report) => { println!("windows-runtime phase=preflight operation=boot_artifact outcome=pass image_bytes={} modules={} execution=not_attempted", report.image_bytes, report.module_count); for check in report.checks.iter() { println!("windows-runtime phase=preflight operation=check outcome=pass detail={check}"); } ExitCode::SUCCESS }
        Err(error) => { eprintln!("windows-runtime phase=preflight operation=boot_artifact outcome=fail error={error}"); ExitCode::from(1) }
    }
}

fn usage() {
    eprintln!("usage: windows-runtime --preflight <image> <dll-directory> <unixlib-directory> <nls-file> <registry-socket> <registry-database> | --launch <image> <windows-path> <command-line> x86_64 <prefix> <runtime> <dll-catalog> <unixlib> <nls-file> <registry-socket> <registry-database> <dxvk> <vkd3d> <faudio>");
}
