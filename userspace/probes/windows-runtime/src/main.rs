//! Small command-line entry point for the Windows handoff launcher.

use std::env;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::ExitCode;

use windows_runtime::RuntimeRequest;
mod compositor;

fn main() -> ExitCode {
    let mut args = env::args_os();
    args.next();
    match args.next() {
        Some(flag) if flag == std::ffi::OsStr::new("--native-bootstrap") => native_bootstrap(),
        Some(flag) if flag == std::ffi::OsStr::new("--steam-launch") => {
            let Some(path) = args.next() else { usage(); return ExitCode::from(2); };
            if args.next().is_some() { usage(); return ExitCode::from(2); }
            steam_launch(PathBuf::from(path))
        }
        Some(flag) if flag == std::ffi::OsStr::new("--user-paths") => {
            if args.next().is_some() { usage(); return ExitCode::from(2); }
            user_paths()
        }
        Some(flag) if flag == std::ffi::OsStr::new("--preflight") => preflight(&mut args),
        Some(flag) if flag == std::ffi::OsStr::new("--launch") => launch(&mut args),
        _ => { usage(); ExitCode::from(2) }
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn native_bootstrap() -> ExitCode {
    let path = match env::var_os("OXIDE_WINE_UNIXLIB_PATH") {
        Some(path) => PathBuf::from(path),
        None => { eprintln!("windows-runtime bootstrap: missing OXIDE_WINE_UNIXLIB_PATH"); return ExitCode::from(1); }
    };
    let teb = match env::var("OXIDE_NT_TEB").ok().and_then(|value| parse_hex(&value)) {
        Some(value) => value,
        None => { eprintln!("windows-runtime bootstrap: missing OXIDE_NT_TEB"); return ExitCode::from(1); }
    };
    let peb = match env::var("OXIDE_NT_PEB").ok().and_then(|value| parse_hex(&value)) {
        Some(value) => value,
        None => { eprintln!("windows-runtime bootstrap: missing OXIDE_NT_PEB"); return ExitCode::from(1); }
    };
    if let Err(error) = windows_runtime::attach_native_thread(&path, teb, peb) {
        eprintln!("windows-runtime bootstrap: native attachment failed: {error:?}");
        return ExitCode::from(1);
    }
    if let Err(status) = windows_runtime::native_thread::install_factory(&path) {
        eprintln!("windows-runtime bootstrap: native factory registration failed: {status:#x}");
        return ExitCode::from(1);
    }
    if let Err(error) = windows_runtime::native_gdi::install() {
        eprintln!("windows-runtime bootstrap: native text registration failed: {error}");
        return ExitCode::from(1);
    }
    if let Err(error) = windows_runtime::load_and_register_unixlib(&path, b"win32u.so") {
        eprintln!("windows-runtime bootstrap: native registration failed: {error:?}");
        return ExitCode::from(1);
    }
    let entry = match env::var("OXIDE_PE_ENTRY").ok().and_then(|value| parse_hex(&value)) {
        Some(value) => value,
        None => { eprintln!("windows-runtime bootstrap: missing OXIDE_PE_ENTRY"); return ExitCode::from(1); }
    };
    let stack = match env::var("OXIDE_PE_STACK").ok().and_then(|value| parse_hex(&value)) {
        Some(value) => value,
        None => { eprintln!("windows-runtime bootstrap: missing OXIDE_PE_STACK"); return ExitCode::from(1); }
    };
    // SAFETY: the kernel supplied both values in the bootstrap environment;
    // the registration syscall validated the native table before this jump.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("mov rsp, {stack}; jmp {entry}", stack = in(reg) stack, entry = in(reg) entry, options(noreturn));
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("mov sp, x16", "mov x18, x15", "br x17",
            in("x16") stack, in("x17") entry, in("x15") teb, options(noreturn));
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn native_bootstrap() -> ExitCode {
    eprintln!("windows-runtime bootstrap: unsupported architecture");
    ExitCode::from(1)
}

fn parse_hex(value: &str) -> Option<u64> {
    let value = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X"))?;
    if value.is_empty() { return None; }
    u64::from_str_radix(value, 16).ok()
}

/// Print this user's launch paths as shell assignments, creating the private
/// directories that hold them. One owner selects these paths: the wrapper
/// consumes this output rather than recomputing the policy in shell.
fn user_paths() -> ExitCode {
    let input = windows_runtime::user_paths::UserPathInput::from_environment();
    let paths = match windows_runtime::user_paths::UserRuntimePaths::prepare(&input) {
        Ok(paths) => paths,
        Err(error) => { eprintln!("windows-runtime: user paths unavailable: {error:?}"); return ExitCode::from(1); }
    };
    for (name, path) in [("OXIDE_WINDOWS_PREFIX", &paths.prefix),
                         ("OXIDE_WINDOWS_REGISTRY_DATABASE", &paths.database),
                         ("OXIDE_WINDOWS_REGISTRY_SOCKET", &paths.socket)] {
        let bytes = path.as_os_str().as_bytes();
        // A path needing shell quoting cannot be emitted as an assignment
        // without inventing an escaping dialect; reject it instead.
        if bytes.iter().any(|byte| !matches!(byte, b'/' | b'.' | b'-' | b'_' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')) {
            eprintln!("windows-runtime: user path is not representable: {}", path.display());
            return ExitCode::from(1);
        }
        println!("{name}={}", path.display());
    }
    ExitCode::SUCCESS
}

fn launch(args: &mut impl Iterator<Item = std::ffi::OsString>) -> ExitCode {
    let values = args.collect::<Vec<_>>();
    if !valid_launch_args(&values) { usage(); return ExitCode::from(2); }
    let image = PathBuf::from(&values[0]);
    let windows_path = values[1].as_os_str().as_bytes();
    let command_line = values[2].as_os_str().as_bytes();
    match RuntimeRequest::preflight(&image, windows_path, &PathBuf::from(&values[6]), &PathBuf::from(&values[7]), &PathBuf::from(&values[8]), &PathBuf::from(&values[9]), &PathBuf::from(&values[10])) {
        Ok(report) => eprintln!("windows-runtime phase=preflight operation=boot_artifact outcome=pass image_bytes={} modules={} execution=not_attempted", report.image_bytes, report.module_count),
        Err(error) => { eprintln!("windows-runtime phase=preflight operation=boot_artifact outcome=fail error={error}"); return ExitCode::from(1); }
    }
    let request = match RuntimeRequest::from_windows_launch(&image, windows_path, command_line, &PathBuf::from(&values[4]), &PathBuf::from(&values[5]), &PathBuf::from(&values[6]), &PathBuf::from(&values[7]), &PathBuf::from(&values[8]), &PathBuf::from(&values[9]), &PathBuf::from(&values[10])) {
        Ok(request) => request,
        Err(error) => { eprintln!("windows-runtime phase=preflight operation=build_handoff outcome=fail error={error:?}"); return ExitCode::from(1); }
    };
    let selector = syscall::nt::NtService::ExecuteWithCatalog.entry();
    eprintln!("windows-runtime phase=handoff operation=execute_with_catalog outcome=attempt modules={} selector=0x{selector:016x}", request.module_count());
    let _compositor = match compositor::start() {
        Ok(session) => session,
        Err(error) => { eprintln!("windows-runtime: compositor startup failed: {error}"); return ExitCode::from(1); }
    };
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

fn valid_launch_args(values: &[std::ffi::OsString]) -> bool {
    values.len() == 11 && values[3] == "x86_64"
}

fn steam_launch(path: PathBuf) -> ExitCode {
    let record = match windows_runtime::SteamLaunchRecord::from_path(&path) {
        Ok(record) => record,
        Err(error) => { eprintln!("windows-runtime phase=preflight operation=steam_launch_record outcome=fail error={error:?}"); return ExitCode::from(1); }
    };
    eprintln!("windows-runtime phase=preflight operation=steam_launch_record outcome=pass appid={}", record.appid);
    let request = match record.into_request() {
        Ok(request) => request,
        Err(error) => { eprintln!("windows-runtime phase=preflight operation=build_handoff outcome=fail error={error:?}"); return ExitCode::from(1); }
    };
    match request.execute() {
        Ok(status) => { println!("windows-runtime phase=commit operation=steam_launch outcome=committed ntstatus=0x{status:08x}"); ExitCode::SUCCESS }
        Err(error) => { eprintln!("windows-runtime phase=handoff operation=steam_launch outcome=fail error={error:?}"); ExitCode::from(1) }
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
    eprintln!("usage: windows-runtime --user-paths | --steam-launch <record> | --preflight <image> <dll-directory> <unixlib-directory> <nls-file> <registry-socket> <registry-database> | --launch <image> <windows-path> <command-line> x86_64 <prefix> <runtime> <dll-catalog> <unixlib> <nls-file> <registry-socket> <registry-database>");
}

#[cfg(test)]
mod tests {
    use super::valid_launch_args;
    use std::ffi::OsString;

    #[test]
    fn launch_flag_is_consumed_before_validating_native_fields() {
        let mut args = vec![OsString::from("image.exe"), OsString::from("C:\\image.exe"), OsString::from("image.exe"), OsString::from("x86_64")];
        args.extend((0..7).map(|index| OsString::from(format!("field-{index}"))));
        assert_eq!(args.len(), 11);
        assert!(valid_launch_args(&args));
    }

    #[test]
    fn launch_architecture_must_be_x86_64() {
        let args = (0..11).map(|index| if index == 3 { OsString::from("aarch64") } else { OsString::from("field") }).collect::<Vec<_>>();
        assert!(!valid_launch_args(&args));
    }
}
