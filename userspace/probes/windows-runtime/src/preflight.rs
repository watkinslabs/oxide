//! Fail-closed admission for the staged 64-bit Windows launch inputs.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::Path;

use super::{BuildError, RuntimeRequest, MAX_IMAGE_BYTES};

const REQUIRED_WINDOWS_RESOURCES: &[&str] = &["user32.dll", "gdi32.dll"];
const REQUIRED_UNIX_RESOURCES: &[&str] = &["win32u.so"];

/// Evidence collected from one staged launch tree. It proves admission only;
/// no field implies that a PE entry point was executed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootArtifactReport { pub image_bytes: u64, pub module_count: usize, pub checks: Box<[String]> }

/// Actionable failures emitted by the boot-artifact admission boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreflightError { pub failures: Box<[String]> }

/// Immutable proof that one validated PE request has the GUI resources
/// required by Notepad. The entry is an RVA because mapping supplies its VA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotepadGuiReadiness {
    pub image_entry_rva: u32,
    pub user32_bytes: u64,
    pub gdi32_bytes: u64,
    pub win32u_bytes: u64,
}

/// Owned PE-plus-GUI handoff. It contains no execution method: callers must
/// explicitly submit its one request after the preflight proof is inspected.
pub struct NotepadRuntimeHandoff { request: RuntimeRequest, readiness: NotepadGuiReadiness }

impl NotepadRuntimeHandoff {
    /// Build one fail-closed handoff without invoking an NT selector.
    /// # C: O(image + DLLs + GUI resource metadata)
    pub fn preflight(image_path: &Path, windows_path: &[u8], dll_dir: &Path, unixlib_dir: &Path, nls_path: &Path, registry_socket: &Path, registry_database: &Path) -> Result<Self, PreflightError> {
        let mut failures = Vec::new(); validate_artifacts(image_path, dll_dir, unixlib_dir, nls_path, registry_socket, registry_database, &mut failures);
        if !failures.is_empty() { return Err(PreflightError { failures: failures.into_boxed_slice() }); }
        let request = RuntimeRequest::from_paths_with_environment(image_path, windows_path, windows_path, dll_dir, std::iter::empty::<(String, String)>()).map_err(build_error)?;
        let readiness = validate_request(&request, dll_dir, unixlib_dir, &mut failures);
        if !failures.is_empty() { return Err(PreflightError { failures: failures.into_boxed_slice() }); }
        let Some(readiness) = readiness else { failures.push("Notepad GUI resources could not be bound to the PE launch record".into()); return Err(PreflightError { failures: failures.into_boxed_slice() }); };
        Ok(Self { request, readiness })
    }

    /// Return the exact request covered by the readiness proof.
    /// # C: O(1)
    pub fn request(&self) -> &RuntimeRequest { &self.request }

    /// Return the entry/resource facts associated with that request.
    /// # C: O(1)
    pub fn readiness(&self) -> &NotepadGuiReadiness { &self.readiness }
}

impl std::fmt::Display for PreflightError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(out, "{}", self.failures.join("; ")) }
}
impl std::error::Error for PreflightError {}

/// Validate mounted artifacts and the exact owned handoff records.
/// # C: O(image + DLLs + resource metadata)
pub(super) fn inspect(image_path: &Path, windows_path: &[u8], dll_dir: &Path, unixlib_dir: &Path, nls_path: &Path, registry_socket: &Path, registry_database: &Path) -> Result<BootArtifactReport, PreflightError> {
    let handoff = NotepadRuntimeHandoff::preflight(image_path, windows_path, dll_dir, unixlib_dir, nls_path, registry_socket, registry_database)?;
    let request = handoff.request();
    let mut failures = Vec::new(); let mut checks = Vec::new();
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

fn build_error(error: BuildError) -> PreflightError {
    PreflightError { failures: vec![format!("PE32+ dependency/ABI admission failed: {error:?}")].into_boxed_slice() }
}

fn validate_artifacts(image_path: &Path, dll_dir: &Path, unixlib_dir: &Path, nls_path: &Path, registry_socket: &Path, registry_database: &Path, failures: &mut Vec<String>) {
    require_regular_nonempty("PE root", image_path, failures);
    require_directory("Windows DLL directory", dll_dir, failures);
    require_directory("Wine Unixlib directory", unixlib_dir, failures);
    for name in REQUIRED_WINDOWS_RESOURCES { require_regular_nonempty(&format!("Windows resource {name}"), &dll_dir.join(name), failures); }
    for name in REQUIRED_UNIX_RESOURCES { require_regular_nonempty(&format!("Unixlib resource {name}"), &unixlib_dir.join(name), failures); }
    require_regular_nonempty("Wine NLS resource", nls_path, failures);
    require_registry_endpoint(registry_socket, registry_database, failures);
}

fn validate_request(request: &RuntimeRequest, dll_dir: &Path, unixlib_dir: &Path, failures: &mut Vec<String>) -> Option<NotepadGuiReadiness> {
    let image = match pe::parse(&request.image) {
        Ok(image) => image,
        Err(error) => { failures.push(format!("PE32+ startup image rejected: {error:?}")); return None; }
    };
    if image.entry_rva == 0 || !image.sections.iter().any(|section| section.characteristics.contains(pe::SectionFlags::MEM_EXECUTE)
        && image.entry_rva >= section.virtual_address
        && image.entry_rva < section.virtual_address.saturating_add(section.virtual_size.max(section.raw_size))) {
        failures.push("PE32+ startup entry is not inside an executable section".into());
    }
    let imports = image.imports().ok();
    for required in [b"user32.dll".as_slice(), b"gdi32.dll".as_slice()] {
        if !imports.as_ref().is_some_and(|items| items.iter().any(|item| item.name.eq_ignore_ascii_case(required))) { failures.push(format!("Notepad PE does not import required GUI module {}", String::from_utf8_lossy(required))); }
        if !request.modules.iter().any(|module| module.name.eq_ignore_ascii_case(required)) { failures.push(format!("GUI module {} is absent from the same PE launch catalog", String::from_utf8_lossy(required))); }
    }
    let resource = |path: &Path| fs::metadata(path).ok().filter(|metadata| metadata.is_file() && metadata.len() > 0).map(|metadata| metadata.len());
    let user32_bytes = resource(&dll_dir.join("user32.dll"));
    let gdi32_bytes = resource(&dll_dir.join("gdi32.dll"));
    let win32u_bytes = resource(&unixlib_dir.join("win32u.so"));
    if user32_bytes.is_none() || gdi32_bytes.is_none() || win32u_bytes.is_none() { return None; }
    Some(NotepadGuiReadiness { image_entry_rva: image.entry_rva, user32_bytes: user32_bytes.unwrap(), gdi32_bytes: gdi32_bytes.unwrap(), win32u_bytes: win32u_bytes.unwrap() })
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

    #[test]
    fn notepad_readiness_binds_entry_and_gui_resources_to_one_request() {
        let Some(wine) = root() else { return };
        let base = std::env::temp_dir().join(format!("oxide-notepad-readiness-{}", std::process::id())); let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("unix")).unwrap(); fs::write(base.join("unix/win32u.so"), [1]).unwrap(); fs::write(base.join("locale.nls"), [1]).unwrap(); fs::write(base.join("registry.db"), [1]).unwrap();
        let socket = base.join("registry.sock"); let listener = UnixListener::bind(&socket).unwrap(); let server = thread::spawn(move || { let _ = listener.accept(); });
        let handoff = NotepadRuntimeHandoff::preflight(&wine.join("notepad.exe"), b"C:\\notepad.exe", &wine, &base.join("unix"), &base.join("locale.nls"), &socket, &base.join("registry.db")).unwrap();
        assert_eq!(handoff.request().module_count(), handoff.request().abi().module_count as usize);
        assert!(handoff.readiness().image_entry_rva > 0); assert!(handoff.readiness().user32_bytes > 0); assert!(handoff.readiness().gdi32_bytes > 0); assert!(handoff.readiness().win32u_bytes > 0);
        server.join().unwrap(); fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn notepad_readiness_rejects_an_empty_windows_entry_path_before_handoff() {
        let Some(wine) = root() else { return };
        let base = std::env::temp_dir().join(format!("oxide-notepad-readiness-invalid-{}", std::process::id())); let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("unix")).unwrap(); fs::write(base.join("unix/win32u.so"), [1]).unwrap(); fs::write(base.join("locale.nls"), [1]).unwrap(); fs::write(base.join("registry.db"), [1]).unwrap();
        let socket = base.join("registry.sock"); let listener = UnixListener::bind(&socket).unwrap(); let server = thread::spawn(move || { let _ = listener.accept(); });
        let error = match NotepadRuntimeHandoff::preflight(&wine.join("notepad.exe"), b"", &wine, &base.join("unix"), &base.join("locale.nls"), &socket, &base.join("registry.db")) { Ok(_) => panic!("empty entry path was admitted"), Err(error) => error };
        assert!(error.failures.iter().any(|failure| failure.contains("InvalidUtf8Path"))); server.join().unwrap(); fs::remove_dir_all(base).unwrap();
    }
}
