//! Fail-closed admission for the staged 64-bit Windows launch inputs.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::Path;

use super::{RuntimeRequest, MAX_IMAGE_BYTES};

const REQUIRED_WINDOWS_RESOURCES: &[&str] = &["user32.dll", "gdi32.dll"];
const REQUIRED_UNIX_RESOURCES: &[&str] = &["win32u.so"];

/// Evidence collected from one staged launch tree. It proves admission only;
/// no field implies that a PE entry point was executed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootArtifactReport { pub image_bytes: u64, pub module_count: usize, pub checks: Box<[String]> }

/// Actionable failures emitted by the boot-artifact admission boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreflightError { pub failures: Box<[String]> }

impl std::fmt::Display for PreflightError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(out, "{}", self.failures.join("; ")) }
}
impl std::error::Error for PreflightError {}

/// Validate mounted artifacts and the exact owned handoff records.
/// # C: O(image + DLLs + resource metadata)
pub(super) fn inspect(image_path: &Path, windows_path: &[u8], dll_dir: &Path, unixlib_dir: &Path, nls_path: &Path, registry_socket: &Path, registry_database: &Path) -> Result<BootArtifactReport, PreflightError> {
    let mut failures = Vec::new(); let mut checks = Vec::new();
    require_regular_nonempty("PE root", image_path, &mut failures);
    require_directory("Windows DLL directory", dll_dir, &mut failures);
    require_directory("Wine Unixlib directory", unixlib_dir, &mut failures);
    for name in REQUIRED_WINDOWS_RESOURCES { require_regular_nonempty(&format!("Windows resource {name}"), &dll_dir.join(name), &mut failures); }
    for name in REQUIRED_UNIX_RESOURCES { require_regular_nonempty(&format!("Unixlib resource {name}"), &unixlib_dir.join(name), &mut failures); }
    require_regular_nonempty("Wine NLS resource", nls_path, &mut failures);
    require_registry_endpoint(registry_socket, registry_database, &mut failures);
    if !failures.is_empty() { return Err(PreflightError { failures: failures.into_boxed_slice() }); }
    let request = RuntimeRequest::from_paths_with_environment(image_path, windows_path, windows_path, dll_dir, std::iter::empty::<(String, String)>())
        .map_err(|error| PreflightError { failures: vec![format!("PE32+ dependency/ABI admission failed: {error:?}")].into_boxed_slice() })?;
    let abi = request.abi();
    if abi.image_len == 0 || abi.image_len > MAX_IMAGE_BYTES { failures.push(format!("launcher ABI image length {} is outside 1..={MAX_IMAGE_BYTES}", abi.image_len)); }
    if abi.image_path_len == 0 || abi.command_line_len == 0 || abi.environment_len == 0 { failures.push("launcher ABI contains an empty path, command line, or environment record".into()); }
    if abi.module_count as usize != request.module_count() { failures.push(format!("launcher ABI module count {} differs from owned catalog {}", abi.module_count, request.module_count())); }
    if request.modules.iter().any(|module| module.name.eq_ignore_ascii_case(b"ntdll.dll")) { failures.push("native ntdll ownership violated: ntdll.dll was placed in the PE catalog".into()); }
    else { checks.push("native ntdll ownership: excluded from launcher catalog".into()); }
    if request.records.iter().any(|record| record.name.as_u64() == 0 || record.image.as_u64() == 0 || record.image_len == 0) { failures.push("launcher ABI contains a null or empty module record".into()); }
    else { checks.push(format!("launcher ABI records: {} validated", request.records.len())); }
    if !failures.is_empty() { return Err(PreflightError { failures: failures.into_boxed_slice() }); }
    checks.push(format!("PE32+ Notepad dependency closure: {} modules", request.module_count()));
    checks.push("registry endpoint: connected; database: readable and writable".into());
    checks.push("user32/GDI resources: user32.dll, gdi32.dll, win32u.so, locale.nls present".into());
    Ok(BootArtifactReport { image_bytes: abi.image_len, module_count: request.module_count(), checks: checks.into_boxed_slice() })
}

fn require_regular_nonempty(label: &str, path: &Path, failures: &mut Vec<String>) {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.len() > 0 => {}
        Ok(metadata) if !metadata.is_file() => failures.push(format!("{label} {} is not a regular file", path.display())),
        Ok(_) => failures.push(format!("{label} {} is empty", path.display())),
        Err(error) => failures.push(format!("{label} {} is unavailable: {error}", path.display())),
    }
}
fn require_directory(label: &str, path: &Path, failures: &mut Vec<String>) {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => failures.push(format!("{label} {} is not a directory", path.display())),
        Err(error) => failures.push(format!("{label} {} is unavailable: {error}", path.display())),
    }
}
fn require_registry_endpoint(socket: &Path, database: &Path, failures: &mut Vec<String>) {
    match fs::metadata(socket) {
        Ok(metadata) if metadata.file_type().is_socket() => match UnixStream::connect(socket) { Ok(_) => {}, Err(error) => failures.push(format!("registry endpoint {} is not accepting connections: {error}", socket.display())) },
        Ok(_) => failures.push(format!("registry endpoint {} is not a Unix stream socket", socket.display())),
        Err(error) => failures.push(format!("registry endpoint {} is unavailable: {error}", socket.display())),
    }
    match OpenOptions::new().read(true).write(true).open(database) { Ok(_) => {}, Err(error) => failures.push(format!("registry database {} is not readable and writable: {error}", database.display())) }
}

#[cfg(test)]
mod tests {
    use super::*; use std::os::unix::net::UnixListener; use std::thread;
    fn root() -> Option<std::path::PathBuf> { ["/usr/lib64/wine/x86_64-windows", "/usr/lib/wine/x86_64-windows"].iter().map(Path::new).find(|path| path.join("notepad.exe").is_file()).map(Path::to_owned) }
    fn resources(base: &Path) { fs::create_dir_all(base.join("unix")).unwrap(); for name in ["user32.dll", "gdi32.dll"] { fs::write(base.join(name), [1]).unwrap(); } fs::write(base.join("unix/win32u.so"), [1]).unwrap(); fs::write(base.join("locale.nls"), [1]).unwrap(); }
    #[test]
    fn staged_notepad_preflight_validates_real_closure_and_never_executes() {
        let Some(wine) = root() else { return }; let base = std::env::temp_dir().join(format!("oxide-boot-preflight-{}", std::process::id())); fs::create_dir_all(&base).unwrap(); resources(&base);
        let socket = base.join("registry.sock"); let db = base.join("registry.db"); fs::write(&db, [1]).unwrap(); let listener = UnixListener::bind(&socket).unwrap(); let server = thread::spawn(move || { let _ = listener.accept(); });
        let report = inspect(&wine.join("notepad.exe"), b"C:\\notepad.exe", &wine, &base.join("unix"), &base.join("locale.nls"), &socket, &db).unwrap(); assert!(report.module_count >= 8); assert!(report.checks.iter().any(|check| check.contains("native ntdll"))); server.join().unwrap(); let _ = fs::remove_dir_all(base);
    }
    #[test]
    fn missing_registry_endpoint_fails_closed_before_handoff() {
        let Some(wine) = root() else { return }; let base = std::env::temp_dir().join(format!("oxide-boot-preflight-missing-{}", std::process::id())); fs::create_dir_all(&base).unwrap(); resources(&base); fs::write(base.join("registry.db"), [1]).unwrap();
        let error = inspect(&wine.join("notepad.exe"), b"C:\\notepad.exe", &wine, &base.join("unix"), &base.join("locale.nls"), &base.join("missing.sock"), &base.join("registry.db")).unwrap_err(); assert!(error.failures.iter().any(|failure| failure.contains("registry endpoint"))); fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn missing_gui_resource_fails_closed_with_resource_diagnostic() {
        let Some(wine) = root() else { return }; let base = std::env::temp_dir().join(format!("oxide-boot-preflight-resource-{}", std::process::id())); fs::create_dir_all(base.join("unix")).unwrap(); fs::write(base.join("locale.nls"), [1]).unwrap(); fs::write(base.join("registry.db"), [1]).unwrap(); let socket = base.join("registry.sock"); let listener = UnixListener::bind(&socket).unwrap(); let server = thread::spawn(move || { let _ = listener.accept(); });
        let error = inspect(&wine.join("notepad.exe"), b"C:\\notepad.exe", &wine, &base.join("unix"), &base.join("locale.nls"), &socket, &base.join("registry.db")).unwrap_err(); assert!(error.failures.iter().any(|failure| failure.contains("win32u.so"))); server.join().unwrap(); fs::remove_dir_all(base).unwrap();
    }
}
