//! Strict per-game Steam/Proton launch-record admission.

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::{BuildError, ProtonLaunchConfig, RuntimeRequest, Vkd3dProtonRuntime, WindowsArchitecture};

const RECORD_HEADER: &str = "oxide-steam-launch-v1";
const REQUIRED_FIELDS: &[&str] = &[
    "appid", "image", "windows_path", "command_line", "compat_data", "prefix", "runtime",
    "dll_catalog", "unixlib", "nls", "registry_socket", "registry_database",
    "dxvk", "vkd3d", "vkd3d_version", "vkd3d_identity", "faudio",
];

/// One immutable Steam game launch description. All paths are supplied by the
/// owning Steam/Proton staging operation and are validated before PE bytes are read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SteamLaunchRecord {
    pub appid: u32,
    pub image: PathBuf,
    pub windows_path: Vec<u8>,
    pub command_line: Vec<u8>,
    pub compat_data: PathBuf,
    pub config: ProtonLaunchConfig,
    source_path: PathBuf,
    source_bytes: Vec<u8>,
}

/// Canonical Proton compatibility-data handoff for one Steam launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtonCompatibilityHandoff {
    pub appid: u32,
    pub data_path: PathBuf,
    pub prefix: PathBuf,
    pub tool_path: PathBuf,
}

impl SteamLaunchRecord {
    /// Parse one complete record; duplicate, unknown, missing, and malformed fields fail closed.
    /// # C: O(record bytes)
    pub fn from_path(path: &Path) -> Result<Self, BuildError> {
        let source_path = canonical_record(path)?;
        let bytes = fs::read(&source_path).map_err(BuildError::Io)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| BuildError::InvalidLaunchConfiguration { field: "steam launch record" })?;
        let mut fields = std::collections::HashMap::new();
        let mut lines = text.lines();
        if lines.next() != Some(RECORD_HEADER) {
            return Err(BuildError::InvalidLaunchConfiguration { field: "steam launch header" });
        }
        for line in lines {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.is_empty() { continue; }
            let Some((name, value)) = line.split_once('=') else {
                return Err(BuildError::InvalidLaunchConfiguration { field: "steam launch field" });
            };
            if !REQUIRED_FIELDS.contains(&name) || value.is_empty() || fields.insert(name, value).is_some() {
                return Err(BuildError::InvalidLaunchConfiguration { field: "steam launch field" });
            }
        }
        if fields.len() != REQUIRED_FIELDS.len() {
            return Err(BuildError::InvalidLaunchConfiguration { field: "steam launch fields" });
        }
        let get = |name: &str| fields.get(name).copied().ok_or(BuildError::InvalidLaunchConfiguration { field: "steam launch fields" });
        let appid = get("appid")?.parse::<u32>().map_err(|_| BuildError::InvalidLaunchConfiguration { field: "appid" })?;
        if appid == 0 { return Err(BuildError::InvalidLaunchConfiguration { field: "appid" }); }
        let image = PathBuf::from(get("image")?);
        let windows_path = get("windows_path")?.as_bytes().to_vec();
        let command_line = get("command_line")?.as_bytes().to_vec();
        if windows_path.contains(&0) || command_line.contains(&0) {
            return Err(BuildError::InvalidLaunchConfiguration { field: "steam launch text" });
        }
        let path = |name: &str| Ok::<PathBuf, BuildError>(PathBuf::from(get(name)?));
        let compat_data = path("compat_data")?;
        let config = ProtonLaunchConfig {
            architecture: WindowsArchitecture::X86_64,
            prefix: path("prefix")?, runtime: path("runtime")?, dll_catalog: path("dll_catalog")?,
            unixlib: path("unixlib")?, nls: path("nls")?, registry_socket: path("registry_socket")?,
            registry_database: path("registry_database")?, dxvk: path("dxvk")?,
            vkd3d: Vkd3dProtonRuntime { path: path("vkd3d")?, version: get("vkd3d_version")?.to_owned(), identity: get("vkd3d_identity")?.to_owned() },
            faudio: path("faudio")?,
        };
        Ok(Self { appid, image, windows_path, command_line, compat_data, config, source_path, source_bytes: bytes })
    }

    /// Validate and canonicalize Proton compatibility roots before PE or
    /// component bytes can cross the launch boundary.
    /// # C: O(path bytes + filesystem metadata)
    pub fn compatibility_handoff(&self) -> Result<ProtonCompatibilityHandoff, BuildError> {
        let data_path = canonical_directory("compat_data", &self.compat_data)?;
        let prefix = canonical_directory("prefix", &self.config.prefix)?;
        let tool_path = canonical_directory("runtime", &self.config.runtime)?;
        if data_path.file_name().and_then(|name| name.to_str()).and_then(|name| name.parse::<u32>().ok()) != Some(self.appid)
            || prefix.file_name().and_then(|name| name.to_str()) != Some("pfx")
            || !prefix.starts_with(&data_path) || prefix == data_path {
            return Err(BuildError::InvalidLaunchConfiguration { field: "compatibility roots" });
        }
        Ok(ProtonCompatibilityHandoff { appid: self.appid, data_path, prefix, tool_path })
    }

    /// Validate record-owned paths and build the existing owned NT request.
    /// # C: O(path bytes + filesystem metadata + PE/catalog bytes)
    pub fn into_request(self) -> Result<RuntimeRequest, BuildError> {
        if fs::read(&self.source_path).map_err(BuildError::Io)? != self.source_bytes {
            return Err(BuildError::InvalidLaunchConfiguration { field: "steam launch source" });
        }
        let image_bytes = self.image.as_os_str().as_bytes();
        if image_bytes.is_empty() || image_bytes.contains(&0) || !self.image.is_absolute() || !self.image.is_file() {
            return Err(BuildError::InvalidLaunchConfiguration { field: "image" });
        }
        let handoff = self.compatibility_handoff()?;
        self.config.validate()?;
        let mut environment = self.config.profile().environment();
        environment.push(("STEAM_COMPAT_DATA_PATH".to_owned(), handoff.data_path.to_string_lossy().into_owned()));
        environment.push(("STEAM_COMPAT_TOOL_PATHS".to_owned(), handoff.tool_path.to_string_lossy().into_owned()));
        environment.push(("SteamAppId".to_owned(), self.appid.to_string()));
        environment.push(("SteamGameId".to_owned(), self.appid.to_string()));
        RuntimeRequest::from_paths_with_environment(&self.image, &self.windows_path, &self.command_line, &self.config.dll_catalog, environment)
    }
}

fn canonical_record(path: &Path) -> Result<PathBuf, BuildError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.contains(&0) || !path.is_absolute() {
        return Err(BuildError::InvalidLaunchConfiguration { field: "steam launch source" });
    }
    let canonical = fs::canonicalize(path).map_err(|_| BuildError::InvalidLaunchConfiguration { field: "steam launch source" })?;
    if !fs::metadata(&canonical).map(|metadata| metadata.is_file()).unwrap_or(false) {
        return Err(BuildError::InvalidLaunchConfiguration { field: "steam launch source" });
    }
    Ok(canonical)
}

fn canonical_directory(field: &'static str, path: &Path) -> Result<PathBuf, BuildError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.contains(&0) || !path.is_absolute() {
        return Err(BuildError::InvalidLaunchConfiguration { field });
    }
    let canonical = fs::canonicalize(path).map_err(|_| BuildError::InvalidLaunchConfiguration { field })?;
    if !canonical.is_dir() { return Err(BuildError::InvalidLaunchConfiguration { field }); }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(extra: &str) -> String {
        format!("{RECORD_HEADER}\nappid=1234\nimage=/games/1234/game.exe\nwindows_path=C:\\\\game.exe\ncommand_line=C:\\\\game.exe -windowed\ncompat_data=/games/1234\nprefix=/games/1234/pfx\nruntime=/opt/proton\ndll_catalog=/opt/proton/files/lib64/wine/x86_64-windows\nunixlib=/opt/proton/files/lib64/wine/x86_64-unix\nnls=/opt/proton/files/share/wine/nls.nls\nregistry_socket=/run/oxide/registry.sock\nregistry_database=/games/1234/registry.db\ndxvk=/opt/proton/dxvk\nvkd3d=/opt/proton/vkd3d-proton\nvkd3d_version=v3.0.1\nvkd3d_identity=0123456789012345678901234567890123456789\nfaudio=/opt/proton/faudio\n{extra}")
    }

    #[test]
    fn complete_record_is_owned_without_validating_host_paths() {
        let base = std::env::temp_dir().join(format!("oxide-steam-record-{}", std::process::id()));
        std::fs::write(&base, record("")).unwrap();
        let launch = SteamLaunchRecord::from_path(&base).unwrap();
        assert_eq!(launch.appid, 1234);
        assert_eq!(launch.image, PathBuf::from("/games/1234/game.exe"));
        assert_eq!(launch.config.vkd3d.identity.len(), 40);
        std::fs::remove_file(base).unwrap();
    }

    #[test]
    fn duplicate_or_unknown_record_fields_fail_closed() {
        for extra in ["appid=5678\n", "other=value\n"] {
            let base = std::env::temp_dir().join(format!("oxide-steam-record-invalid-{}", std::process::id()));
            std::fs::write(&base, record(extra)).unwrap();
            assert!(matches!(SteamLaunchRecord::from_path(&base), Err(BuildError::InvalidLaunchConfiguration { field: "steam launch field" })));
            std::fs::remove_file(base).unwrap();
        }
    }

    #[test]
    fn missing_record_field_is_not_silently_defaulted() {
        let base = std::env::temp_dir().join(format!("oxide-steam-record-missing-{}", std::process::id()));
        let text = record("").replace("faudio=/opt/proton/faudio\n", "");
        std::fs::write(&base, text).unwrap();
        assert!(matches!(SteamLaunchRecord::from_path(&base), Err(BuildError::InvalidLaunchConfiguration { field: "steam launch fields" })));
        std::fs::remove_file(base).unwrap();
    }

    #[test]
    fn compatibility_handoff_canonicalizes_data_root_and_tool_path() {
        let base = std::env::temp_dir().join(format!("oxide-proton-handoff-{}", std::process::id()));
        let data = base.join("1234");
        let prefix = data.join("pfx");
        let runtime = base.join("proton");
        fs::create_dir_all(&prefix).unwrap();
        fs::create_dir_all(&runtime).unwrap();
        let mut launch = SteamLaunchRecord::from_path(&write_record(&base, &format!("compat_data={}\nprefix={}\nruntime={}\n", data.display(), prefix.display(), runtime.display()))).unwrap();
        launch.config.prefix = prefix;
        launch.config.runtime = runtime;
        let handoff = launch.compatibility_handoff().unwrap();
        assert_eq!(handoff.appid, 1234);
        assert_eq!(handoff.data_path, fs::canonicalize(data).unwrap());
        assert_eq!(handoff.prefix, fs::canonicalize(handoff.data_path.join("pfx")).unwrap());
        assert_eq!(handoff.tool_path, fs::canonicalize(base.join("proton")).unwrap());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn compatibility_handoff_rejects_prefix_outside_data_root() {
        let base = std::env::temp_dir().join(format!("oxide-proton-handoff-invalid-{}", std::process::id()));
        let data = base.join("compatdata");
        let prefix = base.join("foreign").join("pfx");
        let runtime = base.join("proton");
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&prefix).unwrap();
        fs::create_dir_all(&runtime).unwrap();
        let record_path = write_record(&base, &format!("compat_data={}\nprefix={}\nruntime={}\n", data.display(), prefix.display(), runtime.display()));
        let launch = SteamLaunchRecord::from_path(&record_path).unwrap();
        assert!(matches!(launch.compatibility_handoff(), Err(BuildError::InvalidLaunchConfiguration { field: "compatibility roots" })));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn mutated_record_source_fails_before_image_or_catalog_admission() {
        let base = std::env::temp_dir().join(format!("oxide-steam-record-mutated-{}", std::process::id()));
        let record_path = write_record(&base, "");
        let launch = SteamLaunchRecord::from_path(&record_path).unwrap();
        fs::write(&record_path, record("command_line=C:\\\\game.exe -safe\n")).unwrap();
        assert!(matches!(launch.into_request(), Err(BuildError::InvalidLaunchConfiguration { field: "steam launch source" })));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn appid_must_own_the_compatibility_data_directory() {
        let base = std::env::temp_dir().join(format!("oxide-steam-record-appid-{}", std::process::id()));
        let data = base.join("5678");
        let prefix = data.join("pfx");
        let runtime = base.join("proton");
        fs::create_dir_all(&prefix).unwrap();
        fs::create_dir_all(&runtime).unwrap();
        let record_path = write_record(&base, &format!("compat_data={}\nprefix={}\nruntime={}\n", data.display(), prefix.display(), runtime.display()));
        let launch = SteamLaunchRecord::from_path(&record_path).unwrap();
        assert!(matches!(launch.compatibility_handoff(), Err(BuildError::InvalidLaunchConfiguration { field: "compatibility roots" })));
        fs::remove_dir_all(base).unwrap();
    }

    fn write_record(base: &Path, replacements: &str) -> PathBuf {
        let mut text = record("");
        for line in replacements.lines() {
            let name = line.split_once('=').unwrap().0;
            let old = text.lines().find(|current| current.starts_with(&format!("{name}=")).to_owned()).unwrap().to_owned();
            text = text.replace(&format!("{old}\n"), &format!("{line}\n"));
        }
        let path = base.join("launch.record");
        fs::create_dir_all(base).unwrap();
        fs::write(&path, text).unwrap();
        path
    }
}
