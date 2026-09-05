//! Linux-personality launcher for an owned 64-bit PE module catalog.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::collections::{HashMap, HashSet};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use pe::catalog::ModuleCatalog;
use syscall::nt_exec::{NtExecModule, NtExecRequest};
use syscall::UserPtr;

mod preflight;
mod dxvk;
mod steam;
pub use preflight::{BootArtifactReport, PreflightError};
pub use dxvk::DxvkRuntimeAdmission;
pub use steam::SteamLaunchRecord;

const MAX_IMAGE_BYTES: u64 = 1 << 31;

/// Failure before the kernel handoff. No invalid catalog is submitted.
#[derive(Debug)]
pub enum BuildError {
    Io(io::Error),
    InvalidRoot(pe::Error),
    InvalidModule { path: PathBuf, error: pe::Error },
    MissingModule { name: Vec<u8> },
    UnresolvedImport { module: Vec<u8>, dll: Vec<u8>, symbol: Vec<u8> },
    InvalidUtf8Path,
    TooLarge,
    CatalogTooLarge,
    InvalidAddress,
    InvalidEnvironment,
    AmbiguousModule { name: Vec<u8>, first: PathBuf, second: PathBuf },
    UnsupportedArchitecture,
    InvalidLaunchConfiguration { field: &'static str },
}

/// Result of the first kernel operation after userspace admission. A missing
/// Oxide NT selector is terminal; it must never be reported as a launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecuteError {
    KernelUnavailable { selector: u64, errno: i32 },
    KernelRejected { selector: u64, status: u64 },
    KernelError { selector: u64, errno: i32 },
}

impl From<io::Error> for BuildError {
    fn from(error: io::Error) -> Self { Self::Io(error) }
}

struct ModuleBuffer { name: Box<[u8]>, image: Box<[u8]> }

/// Windows architecture admitted by the native NT personality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsArchitecture { X86_64 }

/// One immutable, x86-64 VKD3D-Proton installation admitted to a launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vkd3dProtonRuntime {
    pub path: PathBuf,
    pub version: String,
    pub identity: String,
}

impl Vkd3dProtonRuntime {
    /// Read the immutable Proton version record into an owned admission
    /// record; callers cannot substitute an identity after staging.
    /// # C: O(version record bytes)
    pub fn from_path(path: PathBuf) -> Result<Self, BuildError> {
        let record = fs::read_to_string(path.join("version")).map_err(|_| BuildError::InvalidLaunchConfiguration { field: "vkd3d version" })?;
        let mut fields = record.split_whitespace();
        let version = fields.next().ok_or(BuildError::InvalidLaunchConfiguration { field: "vkd3d identity" })?.to_owned();
        let identity = fields.next().ok_or(BuildError::InvalidLaunchConfiguration { field: "vkd3d identity" })?.to_owned();
        if fields.next().is_some() { return Err(BuildError::InvalidLaunchConfiguration { field: "vkd3d identity" }); }
        Ok(Self { path, version, identity })
    }

    /// Validate the installed VKD3D-Proton directory and its Proton identity
    /// record before the launcher reads an image or DLL catalog.
    /// # C: O(path bytes + identity bytes)
    pub fn validate(&self) -> Result<(), BuildError> {
        let bytes = self.path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.contains(&0) || !self.path.is_absolute() || !self.path.is_dir() {
            return Err(BuildError::InvalidLaunchConfiguration { field: "vkd3d" });
        }
        if !valid_version(&self.version) || !valid_identity(&self.identity) {
            return Err(BuildError::InvalidLaunchConfiguration { field: "vkd3d identity" });
        }
        let record = fs::read_to_string(self.path.join("version")).map_err(|_| BuildError::InvalidLaunchConfiguration { field: "vkd3d version" })?;
        let mut fields = record.split_whitespace();
        if fields.next() != Some(self.version.as_str()) || fields.next() != Some(self.identity.as_str()) || fields.next().is_some() {
            return Err(BuildError::InvalidLaunchConfiguration { field: "vkd3d identity" });
        }
        Ok(())
    }
}

/// Immutable per-game Proton/Wine launch admission record.
///
/// The DLL catalog is a staged directory owned by the launch record; the
/// request builder derives the kernel catalog from that directory and never
/// consults an unrelated host search path.  Registry paths identify the one
/// endpoint and database shared by this prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtonLaunchConfig {
    pub architecture: WindowsArchitecture,
    pub prefix: PathBuf,
    pub runtime: PathBuf,
    pub dll_catalog: PathBuf,
    pub unixlib: PathBuf,
    pub nls: PathBuf,
    pub registry_socket: PathBuf,
    pub registry_database: PathBuf,
    pub dxvk: PathBuf,
    pub vkd3d: Vkd3dProtonRuntime,
    pub faudio: PathBuf,
}

impl ProtonLaunchConfig {
    /// Validate the complete launch boundary before reading the PE catalog.
    /// # C: O(path bytes + filesystem metadata)
    pub fn validate(&self) -> Result<(), BuildError> {
        self.validate_and_admit_dxvk().map(|_| ())
    }

    fn validate_and_admit_dxvk(&self) -> Result<DxvkRuntimeAdmission, BuildError> {
        if !cfg!(target_arch = "x86_64") || self.architecture != WindowsArchitecture::X86_64 {
            return Err(BuildError::UnsupportedArchitecture);
        }
        let paths = [
            ("prefix", &self.prefix), ("runtime", &self.runtime),
            ("dll_catalog", &self.dll_catalog), ("unixlib", &self.unixlib),
            ("nls", &self.nls), ("registry_socket", &self.registry_socket),
            ("registry_database", &self.registry_database), ("dxvk", &self.dxvk),
            ("faudio", &self.faudio),
        ];
        for (field, path) in paths {
            let bytes = path.as_os_str().as_bytes();
            if bytes.is_empty() || bytes.contains(&0) || !path.is_absolute() {
                return Err(BuildError::InvalidLaunchConfiguration { field });
            }
        }
        for (field, path) in [("prefix", &self.prefix), ("runtime", &self.runtime), ("dll_catalog", &self.dll_catalog), ("unixlib", &self.unixlib), ("dxvk", &self.dxvk), ("faudio", &self.faudio)] {
            if !path.is_dir() { return Err(BuildError::InvalidLaunchConfiguration { field }); }
        }
        if !self.nls.is_file() || !self.registry_database.is_file() {
            return Err(BuildError::InvalidLaunchConfiguration { field: "launch resources" });
        }
        let dxvk = DxvkRuntimeAdmission::admit(&self.dxvk, &self.runtime)?;
        if !fs::metadata(&self.registry_socket).map(|metadata| metadata.file_type().is_socket()).unwrap_or(false) || UnixStream::connect(&self.registry_socket).is_err() {
            return Err(BuildError::InvalidLaunchConfiguration { field: "registry_socket" });
        }
        self.vkd3d.validate()?;
        Ok(dxvk)
    }

    /// Build the Wine-derived environment owned by this game launch.
    /// # C: O(path bytes)
    fn profile(&self) -> RuntimeProfile {
        RuntimeProfile {
            prefix: self.prefix.clone(), wine_runtime: self.runtime.clone(),
            dxvk: self.dxvk.clone(), vkd3d: self.vkd3d.path.clone(), faudio: self.faudio.clone(),
        }
    }
}

/// Deterministic component selection for one Steam/Proton prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeProfile {
    pub prefix: PathBuf,
    pub wine_runtime: PathBuf,
    pub dxvk: PathBuf,
    pub vkd3d: PathBuf,
    pub faudio: PathBuf,
}

impl RuntimeProfile {
    /// Resolve one profile from host-owned paths and explicit overrides.
    /// # C: O(path bytes)
    pub fn from_environment(dll_dir: &Path) -> Result<Self, BuildError> {
        let runtime = env_path("STEAM_COMPAT_TOOL_PATHS", dll_dir);
        let prefix = env_path("WINEPREFIX", Path::new("/var/lib/oxide/prefix"));
        let dxvk = env_path("DXVK_PATH", &runtime.join("dxvk"));
        let vkd3d = env_path("VKD3D_PROTON_PATH", &runtime.join("vkd3d-proton"));
        let faudio = env_path("FAUDIO_PATH", &runtime.join("faudio"));
        let profile = Self { prefix, wine_runtime: runtime, dxvk, vkd3d, faudio };
        for path in [&profile.prefix, &profile.wine_runtime, &profile.dxvk, &profile.vkd3d, &profile.faudio] {
            let bytes = path.as_os_str().as_bytes();
            if bytes.is_empty() || bytes.contains(&0) { return Err(BuildError::InvalidEnvironment); }
        }
        Ok(profile)
    }

    /// Return the fixed launch variables consumed by Wine-derived components.
    /// # C: O(path bytes)
    pub fn environment(&self) -> Vec<(String, String)> {
        vec![
            ("WINEPREFIX".into(), self.prefix.to_string_lossy().into_owned()),
            ("WINEARCH".into(), "win64".into()),
            ("STEAM_COMPAT_DATA_PATH".into(), self.prefix.to_string_lossy().into_owned()),
            ("STEAM_COMPAT_TOOL_PATHS".into(), self.wine_runtime.to_string_lossy().into_owned()),
            ("DXVK_PATH".into(), self.dxvk.to_string_lossy().into_owned()),
            ("VKD3D_PROTON_PATH".into(), self.vkd3d.to_string_lossy().into_owned()),
            ("FAUDIO_PATH".into(), self.faudio.to_string_lossy().into_owned()),
            ("WINEDLLOVERRIDES".into(), "d3d9,d3d10core,d3d11,dxgi=n;d3d12=n".into()),
            ("OXIDE_NT_PERSONALITY".into(), "native".into()),
        ]
    }
}

fn env_path(name: &str, default: &Path) -> PathBuf {
    std::env::var_os(name).map(PathBuf::from).unwrap_or_else(|| default.to_owned())
}

fn valid_version(value: &str) -> bool {
    let mut parts = value.strip_prefix('v').unwrap_or(value).split('.');
    let valid = parts.clone().count() == 3 && parts.all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
    valid
}

fn valid_identity(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Owns every byte referenced by one `NtExecRequest` until the call returns.
pub struct RuntimeRequest {
    // These fields are retained solely because the ABI records contain raw
    // pointers into them; moving or dropping them before execute_raw returns
    // would invalidate the handoff.
    #[allow(dead_code)]
    image: Box<[u8]>,
    #[allow(dead_code)]
    image_path: Box<[u8]>,
    #[allow(dead_code)]
    command_line: Box<[u8]>,
    #[allow(dead_code)]
    environment: Box<[u8]>,
    modules: Vec<ModuleBuffer>,
    #[allow(dead_code)]
    records: Box<[NtExecModule]>,
    request: NtExecRequest,
}

impl RuntimeRequest {
    /// Admit one explicit Proton launch and produce the existing NT handoff.
    /// # C: O(PE + DLL catalog bytes)
    pub fn from_launch_config(image_path: &Path, windows_path: &[u8], command_line: &[u8], config: &ProtonLaunchConfig) -> Result<Self, BuildError> {
        let dxvk = config.validate_and_admit_dxvk()?;
        Self::from_paths_with_environment_and_paths(image_path, windows_path, command_line, &config.dll_catalog, &dxvk.modules, config.profile().environment())
    }

    /// Read a PE32+ root and every non-native DLL in `dll_dir` using the Linux personality.
    /// # C: O(root + DLL directory bytes)
    pub fn from_paths(image_path: &Path, windows_path: &[u8], dll_dir: &Path) -> Result<Self, BuildError> {
        let profile = RuntimeProfile::from_environment(dll_dir)?;
        Self::from_paths_with_environment(image_path, windows_path, windows_path, dll_dir, profile.environment())
    }

    /// Read a PE32+ root and build an owned handoff with an explicit command line.
    /// # C: O(root + DLL directory bytes)
    pub fn from_paths_with_command_line(image_path: &Path, windows_path: &[u8], command_line: &[u8], dll_dir: &Path) -> Result<Self, BuildError> {
        let profile = RuntimeProfile::from_environment(dll_dir)?;
        Self::from_paths_with_environment(image_path, windows_path, command_line, dll_dir, profile.environment())
    }

    /// Read a PE32+ root and preserve approved launch configuration in its Windows environment.
    /// # C: O(root + DLL directory bytes + environment bytes)
    pub fn from_paths_with_environment<I>(image_path: &Path, windows_path: &[u8], command_line: &[u8], dll_dir: &Path, environment: I) -> Result<Self, BuildError>
    where I: IntoIterator<Item = (String, String)> {
        Self::from_paths_with_environment_and_paths(image_path, windows_path, command_line, dll_dir, &[], environment)
    }

    /// Build one owned catalog from the primary Wine directory and admitted
    /// component paths, rejecting duplicate identities across sources.
    /// # C: O(root + component paths + DLL bytes + environment bytes)
    fn from_paths_with_environment_and_paths<I>(image_path: &Path, windows_path: &[u8], command_line: &[u8], dll_dir: &Path, component_paths: &[PathBuf], environment: I) -> Result<Self, BuildError>
    where I: IntoIterator<Item = (String, String)> {
        if windows_path.is_empty() || windows_path.len() > u32::MAX as usize || windows_path.contains(&0) { return Err(BuildError::InvalidUtf8Path); }
        if command_line.is_empty() || command_line.len() > u32::MAX as usize || command_line.contains(&0) { return Err(BuildError::InvalidUtf8Path); }
        let image = fs::read(image_path).map_err(|error| {
            eprintln!("windows-runtime: read image {}: {error}", image_path.display()); BuildError::Io(error)
        })?;
        validate_size(image.len() as u64)?;
        let root = pe::parse(&image).map_err(BuildError::InvalidRoot)?;
        let mut catalog = ModuleCatalog::new();
        let mut modules = Vec::new();
        let available = stage_module_paths_from_admitted_dirs(&[dll_dir], component_paths)?;
        let mut pending: Vec<Vec<u8>> = root.imports().map_err(BuildError::InvalidRoot)?
            .into_iter().map(|import| dependency_name(import.name).to_ascii_lowercase()).collect();
        let mut seen = HashSet::new();
        while let Some(name) = pending.pop() {
            if name.eq_ignore_ascii_case(b"ntdll.dll") || !seen.insert(name.clone()) { continue; }
            let path = available.get(&name).ok_or_else(|| BuildError::MissingModule { name: name.clone() })?;
            let blob = fs::read(&path).map_err(|error| {
                eprintln!("windows-runtime: read {}: {error}", path.display()); BuildError::Io(error)
            })?;
            validate_size(blob.len() as u64)?;
            let dependency = pe::parse(&blob).map_err(|error| BuildError::InvalidModule { path: path.clone(), error })?;
            pending.extend(dependency.imports().map_err(|error| BuildError::InvalidModule { path: path.clone(), error })?
                .into_iter().map(|import| dependency_name(import.name).to_ascii_lowercase()));
            let module_name = path.file_name().ok_or(BuildError::InvalidUtf8Path)?.as_bytes();
            catalog.add(module_name, &blob).map_err(|error| BuildError::InvalidModule { path: path.clone(), error })?;
            modules.push(ModuleBuffer { name: module_name.to_vec().into_boxed_slice(), image: blob.into_boxed_slice() });
            if modules.len() > syscall::nt_exec::MAX_EXEC_MODULES { return Err(BuildError::CatalogTooLarge); }
        }
        let image = image.into_boxed_slice();
        validate_import_closure(&image, &modules)?;
        let image_path = windows_path.to_vec().into_boxed_slice();
        let command_line = command_line.to_vec().into_boxed_slice();
        let environment = environment_block(environment)?;
        let mut records = Vec::with_capacity(modules.len().max(1));
        for module in &modules {
            records.push(NtExecModule {
                name: user_ptr(module.name.as_ptr())?, name_len: module.name.len() as u32, _padding: 0,
                image: user_ptr(module.image.as_ptr())?, image_len: module.image.len() as u64,
            });
        }
        if records.is_empty() {
            records.push(NtExecModule { name: user_ptr(image_path.as_ptr())?, name_len: 0, _padding: 0, image: user_ptr(image.as_ptr())?, image_len: 0 });
        }
        let records = records.into_boxed_slice();
        let request = NtExecRequest {
            image: user_ptr(image.as_ptr())?, image_len: image.len() as u64,
            image_path: user_ptr(image_path.as_ptr())?, image_path_len: image_path.len() as u32, _path_padding: 0,
            command_line: user_ptr(command_line.as_ptr())?, command_line_len: command_line.len() as u32, _command_padding: 0,
            environment: user_ptr(environment.as_ptr())?, environment_len: environment.len() as u32, _environment_padding: 0,
            modules: user_ptr(records.as_ptr())?, module_count: modules.len() as u32, _modules_padding: 0,
        };
        Ok(Self { image, image_path, command_line, environment, modules, records, request })
    }

    /// Return the fixed ABI record passed to the tagged NT selector. # C: O(1)
    pub fn abi(&self) -> &NtExecRequest { &self.request }

    /// Number of runtime-supplied DLL records. # C: O(1)
    pub fn module_count(&self) -> usize { self.modules.len() }

    /// Submit the request. On a normal Linux kernel this returns `-1` with
    /// `ENOSYS`; only an Oxide NT-capable kernel consumes the selector.
    /// # C: O(1) plus kernel handoff
    pub fn execute_raw(&self) -> io::Result<u64> {
        let selector = syscall::nt::NtService::ExecuteWithCatalog.entry();
        // SAFETY: request and all nested buffers remain owned and immovable for
        // the complete libc syscall; the kernel copies every referenced range.
        let result = unsafe { libc::syscall(selector as libc::c_long, &self.request as *const NtExecRequest) };
        if result == -1 { Err(io::Error::last_os_error()) } else { Ok(result as u64) }
    }

    /// Invoke the staged x86-64 launcher handoff and classify its terminal
    /// boundary result without manufacturing success on Linux or NT reject.
    /// # C: O(1) plus kernel handoff
    pub fn execute(&self) -> Result<u64, ExecuteError> {
        let selector = syscall::nt::NtService::ExecuteWithCatalog.entry();
        // SAFETY: request and nested buffers remain owned until this syscall
        // returns; the kernel copies all user ranges before committing state.
        let result = unsafe { libc::syscall(selector as libc::c_long, &self.request as *const NtExecRequest) };
        if result == -1 {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
            if errno == libc::ENOSYS { Err(ExecuteError::KernelUnavailable { selector, errno }) }
            else { Err(ExecuteError::KernelError { selector, errno }) }
        } else {
            let status = result as u64;
            if status == 0 { Ok(status) }
            else { Err(ExecuteError::KernelRejected { selector, status }) }
        }
    }

    /// Inspect staged inputs without entering the NT execution selector.
    /// # C: O(image + DLLs + resource metadata)
    pub fn preflight(image_path: &Path, windows_path: &[u8], dll_dir: &Path, unixlib_dir: &Path, nls_path: &Path, registry_socket: &Path, registry_database: &Path) -> Result<BootArtifactReport, PreflightError> {
        preflight::inspect(image_path, windows_path, dll_dir, unixlib_dir, nls_path, registry_socket, registry_database)
    }
}

fn user_ptr<T>(address: *const T) -> Result<UserPtr<T>, BuildError> {
    if address.is_null() { return Err(BuildError::InvalidAddress); }
    UserPtr::new(address as u64).map_err(|_| BuildError::InvalidAddress)
}

fn validate_size(size: u64) -> Result<(), BuildError> {
    if size == 0 || size > MAX_IMAGE_BYTES { Err(BuildError::TooLarge) } else { Ok(()) }
}

const PROTON_ENVIRONMENT_KEYS: &[&str] = &[
    "WINEPREFIX", "WINEARCH", "WINEDLLOVERRIDES", "WINEDEBUG", "WINEESYNC", "WINEFSYNC", "FAUDIO_PATH", "OXIDE_NT_PERSONALITY",
    "STEAM_COMPAT_CLIENT_INSTALL_PATH", "STEAM_COMPAT_DATA_PATH", "STEAM_COMPAT_INSTALL_PATH",
    "STEAM_COMPAT_TOOL_PATHS", "STEAM_COMPAT_MOUNTS", "STEAM_COMPAT_LIBRARY_PATHS",
    "PROTON_LOG", "PROTON_DUMP_DEBUG_COMMANDS", "PROTON_USE_WINED3D",
    "DXVK_LOG_LEVEL", "DXVK_LOG_PATH", "DXVK_CONFIG_FILE", "DXVK_ASYNC", "VKD3D_CONFIG",
    "VKD3D_DEBUG", "VKD3D_LOG_FILE", "SteamAppId", "SteamGameId",
];

fn environment_block<I>(environment: I) -> Result<Box<[u8]>, BuildError>
where I: IntoIterator<Item = (String, String)> {
    let defaults = [("SystemRoot", "C:\\Windows"), ("PROCESSOR_ARCHITECTURE", "AMD64"),
        ("TEMP", "C:\\Windows\\Temp"),
        ("TMP", "C:\\Windows\\Temp"), ("PATH", "C:\\Windows\\System32;C:\\Windows")];
    let mut entries = defaults.iter().map(|(name, value)| ((*name).to_string(), (*value).to_string())).collect::<Vec<_>>();
    for (name, value) in environment {
        if !is_proton_environment_key(&name) { continue; }
        if name.is_empty() || name.contains('=') || name.contains('\0') || value.contains('\0') { return Err(BuildError::InvalidEnvironment); }
        if let Some(existing) = entries.iter_mut().find(|(key, _)| key.eq_ignore_ascii_case(&name)) {
            existing.1 = value;
        } else {
            entries.push((name, value));
        }
    }
    let mut units = Vec::new();
    for (name, value) in entries {
        units.extend(format!("{name}={value}").encode_utf16());
        units.push(0);
    }
    units.push(0);
    let mut bytes = Vec::with_capacity(units.len() * 2);
    for unit in units { bytes.extend_from_slice(&unit.to_le_bytes()); }
    Ok(bytes.into_boxed_slice())
}

fn is_proton_environment_key(name: &str) -> bool {
    PROTON_ENVIRONMENT_KEYS.iter().any(|key| name.eq_ignore_ascii_case(key))
        || ["STEAM_COMPAT_", "PROTON_", "DXVK_", "VKD3D_"].iter().any(|prefix| name.len() > prefix.len() && name.get(..prefix.len()).is_some_and(|head| head.eq_ignore_ascii_case(prefix)))
}

#[cfg(test)]
fn environment_entries(block: &[u8]) -> Option<Vec<String>> {
    if block.len() % 2 != 0 { return None; }
    let units = block.chunks_exact(2).map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]])).collect::<Vec<_>>();
    if units.last().copied() != Some(0) || units.len() < 2 || units[units.len() - 2] != 0 { return None; }
    let mut entries = Vec::new();
    for value in units[..units.len() - 1].split(|unit| *unit == 0) {
        entries.push(String::from_utf16(value).ok()?);
    }
    Some(entries)
}

fn is_dll(path: &Path) -> bool {
    path.extension().and_then(OsStr::to_str).is_some_and(|extension| extension.eq_ignore_ascii_case("dll"))
}

/// Build the PE search index before reading any module bytes. Wine's loader
/// searches an ordered path list; this native launcher receives one primary
/// directory plus already-selected component paths, so duplicate
/// case-insensitive names are an ambiguity rather than a precedence decision.
/// Sorting entries makes the reported pair stable despite filesystem order.
#[cfg(test)]
fn stage_module_paths_from_dirs(dll_dirs: &[&Path]) -> Result<HashMap<Vec<u8>, PathBuf>, BuildError> {
    stage_module_paths_from_admitted_dirs(dll_dirs, &[])
}

fn stage_module_paths_from_admitted_dirs(dll_dirs: &[&Path], component_paths: &[PathBuf]) -> Result<HashMap<Vec<u8>, PathBuf>, BuildError> {
    let mut paths = Vec::new();
    for dll_dir in dll_dirs {
        let entries = fs::read_dir(dll_dir).map_err(|error| {
            eprintln!("windows-runtime: read_dir {}: {error}", dll_dir.display()); BuildError::Io(error)
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                eprintln!("windows-runtime: directory entry {}: {error}", dll_dir.display()); BuildError::Io(error)
            })?;
            let path = entry.path();
            if is_dll(&path) { paths.push(path); }
        }
    }
    paths.extend(component_paths.iter().cloned());
    paths.sort_by(|left, right| {
        left.file_name().map(OsStr::as_bytes).cmp(&right.file_name().map(OsStr::as_bytes))
    });
    let mut available = HashMap::new();
    for path in paths {
        let name = path.file_name().ok_or(BuildError::InvalidUtf8Path)?.as_bytes();
        if name.eq_ignore_ascii_case(b"ntdll.dll") { continue; }
        let key = name.to_ascii_lowercase();
        if let Some(first) = available.insert(key.clone(), path.clone()) {
            return Err(BuildError::AmbiguousModule { name: key, first, second: path });
        }
    }
    Ok(available)
}

/// Use the shared PE API-set schema for graph identity, matching the kernel
/// loader's dependency resolver instead of treating contracts as filesystem
/// module names.
fn dependency_name(name: &[u8]) -> &[u8] {
    pe::apiset::target(name).unwrap_or(name)
}

/// Validate the complete PE dependency graph before constructing the raw
/// kernel ABI. Native ntdll exports are resolved by the kernel-owned runtime;
/// every other import must name a catalog member and an actual export in that
/// member. This keeps the handoff all-or-nothing and avoids discovering a
/// broken transitive import after an address space has been published.
fn validate_import_closure(root: &[u8], modules: &[ModuleBuffer]) -> Result<(), BuildError> {
    let mut images = HashMap::new();
    for module in modules {
        images.insert(module.name.to_ascii_lowercase(), module.image.as_ref());
    }
    let validate = |module_name: &[u8], image: &[u8]| -> Result<(), BuildError> {
        let parsed = pe::parse(image).map_err(|error| BuildError::InvalidModule { path: PathBuf::from(String::from_utf8_lossy(module_name).into_owned()), error })?;
        for import in parsed.imports().map_err(|error| BuildError::InvalidModule { path: PathBuf::from(String::from_utf8_lossy(module_name).into_owned()), error })? {
            let dependency_name = pe::apiset::target(import.name).unwrap_or(import.name);
            if dependency_name.eq_ignore_ascii_case(b"ntdll.dll") { continue; }
            let Some(dependency) = images.get(&dependency_name.to_ascii_lowercase()) else {
                return Err(BuildError::MissingModule { name: import.name.to_vec() });
            };
            let dependency = pe::parse(dependency).map_err(|error| BuildError::InvalidModule { path: PathBuf::from(String::from_utf8_lossy(dependency_name).into_owned()), error })?;
            for thunk in parsed.import_thunks(&import).map_err(|error| BuildError::InvalidModule { path: PathBuf::from(String::from_utf8_lossy(module_name).into_owned()), error })? {
                if dependency.export_target(&thunk).map_err(|error| BuildError::InvalidModule { path: PathBuf::from(String::from_utf8_lossy(&import.name).into_owned()), error })?.is_none() {
                    let symbol = match thunk { pe::ImportThunk::Name { name, .. } => name.to_vec(), pe::ImportThunk::Ordinal(value) => value.to_le_bytes().to_vec() };
                    return Err(BuildError::UnresolvedImport { module: module_name.to_vec(), dll: import.name.to_vec(), symbol });
                }
            }
        }
        Ok(())
    };
    validate(b"notepad.exe", root)?;
    for module in modules { validate(&module.name, &module.image)?; }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment_text(bytes: &[u8]) -> String {
        let units = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect::<Vec<_>>();
        String::from_utf16(&units).unwrap()
    }

    #[test]
    fn proton_launch_configuration_is_preserved_in_the_windows_block() {
        let block = environment_block([
            ("STEAM_COMPAT_DATA_PATH".to_string(), "/games/compatdata/123".to_string()),
            ("WINEPREFIX".to_string(), "/games/prefix".to_string()),
            ("DXVK_LOG_LEVEL".to_string(), "none".to_string()),
        ]).unwrap();
        let text = environment_text(&block);
        assert!(text.contains("STEAM_COMPAT_DATA_PATH=/games/compatdata/123\0"));
        assert!(text.contains("WINEPREFIX=/games/prefix\0"));
        assert!(text.contains("DXVK_LOG_LEVEL=none\0"));
        assert!(text.contains("SystemRoot=C:\\Windows\0"));
    }

    #[test]
    fn launch_configuration_overrides_defaults_without_duplicate_names() {
        let block = environment_block([
            ("WINEPREFIX".to_string(), "/games/first".to_string()),
            ("wineprefix".to_string(), "/games/second".to_string()),
            ("UNRELATED_HOST_SETTING".to_string(), "must-not-cross".to_string()),
        ]).unwrap();
        let text = environment_text(&block);
        assert_eq!(text.to_ascii_uppercase().matches("WINEPREFIX=").count(), 1);
        assert!(!text.contains("UNRELATED_HOST_SETTING"));
        assert!(text.contains("WINEPREFIX=/games/second\0"));
    }

    #[test]
    fn malformed_launch_configuration_is_rejected_before_handoff() {
        assert!(matches!(environment_block([(String::from("DXVK_LOG_LEVEL"), String::from("bad\0value"))]), Err(BuildError::InvalidEnvironment)));
        assert!(matches!(environment_block([(String::from("DXVK_=NAME"), String::from("value"))]), Err(BuildError::InvalidEnvironment)));
    }

    #[test]
    fn profile_composes_one_prefix_with_all_proton_components() {
        let profile = RuntimeProfile {
            prefix: PathBuf::from("/games/compatdata/123/pfx"),
            wine_runtime: PathBuf::from("/opt/proton/files"),
            dxvk: PathBuf::from("/opt/proton/files/lib64/dxvk"),
            vkd3d: PathBuf::from("/opt/proton/files/lib64/vkd3d-proton"),
            faudio: PathBuf::from("/opt/proton/files/lib64/faudio"),
        };
        let block = environment_block(profile.environment()).unwrap();
        let entries = environment_entries(&block).unwrap();
        for expected in [
            "WINEPREFIX=/games/compatdata/123/pfx",
            "WINEARCH=win64",
            "STEAM_COMPAT_DATA_PATH=/games/compatdata/123/pfx",
            "STEAM_COMPAT_TOOL_PATHS=/opt/proton/files",
            "DXVK_PATH=/opt/proton/files/lib64/dxvk",
            "VKD3D_PROTON_PATH=/opt/proton/files/lib64/vkd3d-proton",
            "FAUDIO_PATH=/opt/proton/files/lib64/faudio",
            "WINEDLLOVERRIDES=d3d9,d3d10core,d3d11,dxgi=n;d3d12=n",
            "OXIDE_NT_PERSONALITY=native",
        ] { assert!(entries.iter().any(|entry| entry == expected), "missing {expected}"); }
    }

    #[test]
    fn profile_rejects_nul_in_a_component_path() {
        let result = RuntimeProfile::from_environment(Path::new("/runtime\0dlls"));
        assert!(matches!(result, Err(BuildError::InvalidEnvironment)));
    }

    #[test]
    fn vkd3d_admission_requires_matching_version_and_commit_identity() {
        let base = std::env::temp_dir().join(format!("oxide-vkd3d-admission-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let identity = "0123456789012345678901234567890123456789";
        fs::write(base.join("version"), format!("v3.0.1 {identity}\n")).unwrap();
        let valid = Vkd3dProtonRuntime { path: base.clone(), version: "v3.0.1".into(), identity: identity.into() };
        assert!(valid.validate().is_ok());
        assert_eq!(Vkd3dProtonRuntime::from_path(base.clone()).unwrap(), valid);
        let mut wrong = valid.clone();
        wrong.identity = "fedcba9876543210fedcba9876543210fedcba98".into();
        assert!(matches!(wrong.validate(), Err(BuildError::InvalidLaunchConfiguration { field: "vkd3d identity" })));
        let mut malformed = valid;
        malformed.version = "v3.0".into();
        assert!(matches!(malformed.validate(), Err(BuildError::InvalidLaunchConfiguration { field: "vkd3d identity" })));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn launch_config_rejects_relative_paths_before_image_or_catalog_reads() {
        let config = ProtonLaunchConfig {
            architecture: WindowsArchitecture::X86_64,
            prefix: PathBuf::from("prefix"), runtime: PathBuf::from("runtime"),
            dll_catalog: PathBuf::from("dlls"), unixlib: PathBuf::from("unix"),
            nls: PathBuf::from("locale.nls"), registry_socket: PathBuf::from("registry.sock"),
            registry_database: PathBuf::from("registry.db"), dxvk: PathBuf::from("dxvk"),
            vkd3d: Vkd3dProtonRuntime { path: PathBuf::from("vkd3d"), version: "v3.0.1".into(), identity: "0123456789012345678901234567890123456789".into() }, faudio: PathBuf::from("faudio"),
        };
        assert!(matches!(RuntimeRequest::from_launch_config(Path::new("does-not-exist.exe"), b"C:\\game.exe", b"C:\\game.exe", &config), Err(BuildError::InvalidLaunchConfiguration { field: "prefix" })));
    }

    #[test]
    fn launch_config_rejects_missing_catalog_before_image_read() {
        let base = std::env::temp_dir().join(format!("oxide-proton-config-{}", std::process::id()));
        fs::create_dir_all(base.join("prefix")).unwrap(); fs::create_dir_all(base.join("runtime")).unwrap(); fs::create_dir_all(base.join("unix")).unwrap();
        fs::write(base.join("locale.nls"), [1]).unwrap(); fs::write(base.join("registry.db"), [1]).unwrap();
        let config = ProtonLaunchConfig {
            architecture: WindowsArchitecture::X86_64,
            prefix: base.join("prefix"), runtime: base.join("runtime"),
            dll_catalog: base.join("missing-dlls"), unixlib: base.join("unix"),
            nls: base.join("locale.nls"), registry_socket: base.join("missing.sock"),
            registry_database: base.join("registry.db"), dxvk: base.join("dxvk"),
            vkd3d: Vkd3dProtonRuntime { path: base.join("vkd3d"), version: "v3.0.1".into(), identity: "0123456789012345678901234567890123456789".into() }, faudio: base.join("faudio"),
        };
        assert!(matches!(config.validate(), Err(BuildError::InvalidLaunchConfiguration { field: "dll_catalog" })));
        fs::remove_dir_all(base).unwrap();
    }

    fn wine_root() -> Option<&'static Path> {
        ["/usr/lib64/wine/x86_64-windows", "/usr/lib/wine/x86_64-windows"].iter()
            .map(Path::new).find(|root| root.join("notepad.exe").is_file())
    }

    #[test]
    fn installed_64_bit_notepad_builds_an_owned_handoff() {
        let Some(root) = wine_root() else { return };
        let request = RuntimeRequest::from_paths(&root.join("notepad.exe"), b"C:\\notepad.exe", root).unwrap();
        assert_eq!(request.abi().image_len > 0, true);
        assert_eq!(request.abi().image_path_len, 14);
        assert_eq!(request.abi().command_line_len, 14);
        assert!(request.module_count() >= 8);
        assert!(request.module_count() < 64, "Notepad closure must fit the kernel catalog limit");
        assert_eq!(request.abi().module_count as usize, request.module_count());
        assert!(!request.modules.iter().any(|module| module.name.eq_ignore_ascii_case(b"ntdll.dll")));
        assert_eq!(std::mem::size_of::<NtExecRequest>(), 80);
        assert_eq!(std::mem::size_of::<NtExecModule>(), 32);
    }

    #[test]
    fn installed_notepad_registry_imports_are_exported_by_64_bit_advapi32() {
        let Some(root) = wine_root() else { return };
        let notepad = fs::read(root.join("notepad.exe")).unwrap(); let image = pe::parse(&notepad).unwrap();
        let advapi = image.imports().unwrap().into_iter().find(|import| import.name.eq_ignore_ascii_case(b"advapi32.dll")).expect("Notepad registry imports must name advapi32");
        let names = image.import_thunks(&advapi).unwrap();
        for required in [b"RegCloseKey".as_slice(), b"RegCreateKeyExW".as_slice(), b"RegOpenKeyW".as_slice(), b"RegQueryValueExW".as_slice(), b"RegSetValueExW".as_slice()] {
            assert!(names.iter().any(|import| matches!(import, pe::ImportThunk::Name { name, .. } if *name == required)), "Notepad must import {required:?}");
        }
        let advapi_bytes = fs::read(root.join("advapi32.dll")).unwrap(); let advapi_image = pe::parse(&advapi_bytes).unwrap();
        for required in [b"RegCloseKey".as_slice(), b"RegCreateKeyExW".as_slice(), b"RegOpenKeyExW".as_slice(), b"RegQueryValueExW".as_slice(), b"RegSetValueExW".as_slice()] {
            assert!(advapi_image.export_rva(&pe::ImportThunk::Name { hint: 0, name: required }).unwrap().is_some(), "64-bit advapi32 must export {required:?}");
        }
    }

    #[test]
    fn installed_64_bit_notepad_import_graph_has_no_unresolved_catalog_exports() {
        let Some(root) = wine_root() else { return };
        let image_bytes = fs::read(root.join("notepad.exe")).unwrap();
        let image = pe::parse(&image_bytes).unwrap();
        let mut checked = 0usize;
        for import in image.imports().unwrap() {
            let Some(blob) = fs::read_dir(root).unwrap().filter_map(Result::ok)
                .map(|entry| entry.path())
                .find(|path| path.file_name().is_some_and(|name| name.as_bytes().eq_ignore_ascii_case(import.name)))
                .map(|path| fs::read(path).unwrap()) else { panic!("Notepad dependency {:?} is absent", import.name); };
            let dependency = pe::parse(&blob).unwrap();
            for thunk in image.import_thunks(&import).unwrap() {
                assert!(dependency.export_target(&thunk).unwrap().is_some(), "Notepad import {:?}!{:?} is absent", import.name, thunk);
                checked += 1;
            }
        }
        assert!(checked > 100, "Notepad import closure unexpectedly small: {checked}");
    }

    #[test]
    fn installed_64_bit_wine_vulkan_modules_form_a_closed_pe_catalog() {
        let Some(root) = wine_root() else { return };
        for module in ["vulkan-1.dll", "winevulkan.dll"] {
            let image = root.join(module);
            if !image.is_file() { return; }
            let request = RuntimeRequest::from_paths(&image, b"C:\\windows\\vulkan.exe", root).unwrap();
            assert!(request.module_count() > 0, "{module} must retain its PE dependencies");
            assert!(request.module_count() < 64, "{module} dependency closure must fit the NT catalog");
        }
    }

    #[test]
    fn malformed_dll_is_rejected_before_handoff() {
        let base = std::env::temp_dir().join(format!("oxide-windows-runtime-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("notepad.exe"), b"not-pe").unwrap();
        fs::write(base.join("bad.dll"), b"not-pe").unwrap();
        let result = RuntimeRequest::from_paths(&base.join("notepad.exe"), b"C:\\bad.exe", &base);
        assert!(matches!(result, Err(BuildError::InvalidRoot(pe::Error::Enoexec))));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn non_amd64_root_is_rejected_before_catalog_construction() {
        let Some(root) = wine_root() else { return };
        let base = std::env::temp_dir().join(format!("oxide-windows-arch-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        let mut image = fs::read(root.join("notepad.exe")).unwrap();
        image[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
        let image_path = base.join("notepad.exe");
        fs::write(&image_path, image).unwrap();
        let result = RuntimeRequest::from_paths(&image_path, b"C:\\notepad.exe", root);
        assert!(matches!(result, Err(BuildError::InvalidRoot(pe::Error::Enoexec))));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn handoff_rejects_empty_and_nul_containing_windows_paths() {
        let root = std::path::Path::new("/tmp");
        assert!(matches!(RuntimeRequest::from_paths(root, b"", root), Err(BuildError::InvalidUtf8Path)));
        assert!(matches!(RuntimeRequest::from_paths(root, b"C:\\bad\0.exe", root), Err(BuildError::InvalidUtf8Path)));
    }

    #[test]
    fn image_size_limit_is_checked_before_catalog_work() {
        assert!(validate_size(0).is_err());
        assert!(validate_size(MAX_IMAGE_BYTES).is_ok());
        assert!(validate_size(MAX_IMAGE_BYTES + 1).is_err());
    }

    #[test]
    fn only_case_insensitive_dll_suffixes_enter_the_catalog() {
        assert!(is_dll(std::path::Path::new("KERNEL32.DLL")));
        assert!(is_dll(std::path::Path::new("ucrtbase.dll")));
        assert!(!is_dll(std::path::Path::new("notepad.exe")));
        assert!(!is_dll(std::path::Path::new("lib.dll.bak")));
        assert!(!is_dll(std::path::Path::new("DLL")));
    }

    #[test]
    fn duplicate_case_insensitive_module_names_are_rejected_deterministically() {
        let base = std::env::temp_dir().join(format!("oxide-windows-runtime-duplicates-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("USER32.DLL"), []).unwrap();
        fs::write(base.join("user32.dll"), []).unwrap();
        let result = stage_module_paths_from_dirs(&[base.as_path()]);
        match result {
            Err(BuildError::AmbiguousModule { name, first, second }) => {
                assert_eq!(name, b"user32.dll");
                assert_eq!(first.file_name().unwrap().as_bytes(), b"USER32.DLL");
                assert_eq!(second.file_name().unwrap().as_bytes(), b"user32.dll");
            }
            other => panic!("expected deterministic duplicate rejection, got {other:?}"),
        }
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn launch_catalog_merges_owned_component_sources_without_precedence_fallback() {
        let base = std::env::temp_dir().join(format!("oxide-windows-runtime-components-{}", std::process::id()));
        let wine = base.join("wine");
        let dxvk = base.join("dxvk");
        fs::create_dir_all(&wine).unwrap();
        fs::create_dir_all(&dxvk).unwrap();
        fs::write(wine.join("kernel32.dll"), []).unwrap();
        fs::write(dxvk.join("d3d11.dll"), []).unwrap();
        fs::write(dxvk.join("dxgi.dll"), []).unwrap();
        let available = stage_module_paths_from_dirs(&[wine.as_path(), dxvk.as_path()]).unwrap();
        assert_eq!(available.get(b"kernel32.dll".as_slice()), Some(&wine.join("kernel32.dll")));
        assert_eq!(available.get(b"d3d11.dll".as_slice()), Some(&dxvk.join("d3d11.dll")));
        fs::write(wine.join("DXGI.DLL"), []).unwrap();
        assert!(matches!(stage_module_paths_from_dirs(&[wine.as_path(), dxvk.as_path()]), Err(BuildError::AmbiguousModule { .. })));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn launch_catalog_uses_only_the_admitted_component_paths() {
        let base = std::env::temp_dir().join(format!("oxide-windows-runtime-admitted-{}", std::process::id()));
        let wine = base.join("wine");
        let dxvk = base.join("dxvk");
        fs::create_dir_all(&wine).unwrap();
        fs::create_dir_all(&dxvk).unwrap();
        let d3d11 = dxvk.join("d3d11.dll");
        let dxgi = dxvk.join("dxgi.dll");
        fs::write(&d3d11, []).unwrap();
        fs::write(&dxgi, []).unwrap();
        fs::write(dxvk.join("d3d9.dll"), []).unwrap();
        let admitted = vec![d3d11, dxgi];
        let available = stage_module_paths_from_admitted_dirs(&[wine.as_path()], &admitted).unwrap();
        assert!(available.contains_key(b"d3d11.dll".as_slice()));
        assert!(available.contains_key(b"dxgi.dll".as_slice()));
        assert!(!available.contains_key(b"d3d9.dll".as_slice()));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn api_set_dependencies_use_their_kernel_host_identity() {
        assert_eq!(dependency_name(b"api-ms-win-core-file-l1-2-0.dll"), b"kernelbase.dll");
        assert_eq!(dependency_name(b"kernel32.dll"), b"kernel32.dll");
    }

    #[test]
    fn null_host_pointer_cannot_become_an_nt_user_pointer() {
        assert!(matches!(user_ptr::<u8>(core::ptr::null()), Err(BuildError::InvalidAddress)));
    }

    #[test]
    fn catalog_record_lengths_are_bounded_by_the_fixed_abi_types() {
        assert_eq!(std::mem::align_of::<NtExecRequest>(), 8);
        assert_eq!(std::mem::align_of::<NtExecModule>(), 8);
        assert_eq!(std::mem::size_of::<NtExecRequest>(), 80);
        assert_eq!(std::mem::size_of::<NtExecModule>(), 32);
    }

    #[test]
    fn x64_environment_publishes_native_processor_architecture() {
        let block = environment_block(core::iter::empty()).unwrap();
        let entries = environment_entries(&block).expect("environment must be UTF-16 and double-NUL terminated");
        assert!(entries.iter().any(|entry| entry == "PROCESSOR_ARCHITECTURE=AMD64"));
        assert!(!entries.iter().any(|entry| entry.starts_with("PROCESSOR_ARCHITEW6432=")));
    }

    #[test]
    fn selector_is_not_a_linux_syscall_number() {
        assert_eq!(syscall::nt::NtService::ExecuteWithCatalog as u32, 38);
        assert_eq!(syscall::nt::NtService::ExecuteWithCatalog.entry(), 0x4e54_0000_0000_0026);
    }

    #[test]
    fn linux_host_rejects_oxide_selector_without_false_success() {
        if !cfg!(target_os = "linux") { return; }
        let Some(root) = wine_root() else { return };
        let request = RuntimeRequest::from_paths(&root.join("notepad.exe"), b"C:\\notepad.exe", root).unwrap();
        let error = request.execute_raw().unwrap_err();
        assert!(error.raw_os_error().is_some(), "unsupported selector must remain an error");
    }

    #[test]
    fn linux_host_reports_the_first_unavailable_nt_operation_structurally() {
        if !cfg!(target_os = "linux") { return; }
        let Some(root) = wine_root() else { return };
        let request = RuntimeRequest::from_paths(&root.join("notepad.exe"), b"C:\\notepad.exe", root).unwrap();
        let error = request.execute().unwrap_err();
        let selector = syscall::nt::NtService::ExecuteWithCatalog.entry();
        assert!(matches!(error,
            ExecuteError::KernelUnavailable { selector: got, .. }
                | ExecuteError::KernelError { selector: got, .. } if got == selector));
    }

    #[test]
    fn execution_outcomes_do_not_conflate_rejection_and_unavailability() {
        let selector = syscall::nt::NtService::ExecuteWithCatalog.entry();
        assert_ne!(ExecuteError::KernelUnavailable { selector, errno: libc::ENOSYS },
            ExecuteError::KernelRejected { selector, status: 0xc000_000d });
    }
}
