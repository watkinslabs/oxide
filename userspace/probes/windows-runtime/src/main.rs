//! Small command-line entry point for the Windows handoff launcher.

use std::env;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::ExitCode;

use windows_runtime::RuntimeRequest;

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(image) = args.next() else { usage(); return ExitCode::from(2); };
    let Some(windows_path) = args.next() else { usage(); return ExitCode::from(2); };
    let Some(dll_dir) = args.next() else { usage(); return ExitCode::from(2); };
    if args.next().is_some() { usage(); return ExitCode::from(2); }

    let image = PathBuf::from(image);
    let dll_dir = PathBuf::from(dll_dir);
    let windows_path = windows_path.as_os_str().as_bytes();
    let request = match RuntimeRequest::from_paths_with_environment(&image, windows_path, windows_path, &dll_dir, env::vars()) {
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

fn usage() {
    eprintln!("usage: windows-runtime <linux-image-path> <windows-image-path> <dll-directory>");
}
