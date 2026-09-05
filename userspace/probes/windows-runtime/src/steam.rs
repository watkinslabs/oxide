//! Strict per-game Steam/Proton launch-record admission.

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::{BuildError, ProtonLaunchConfig, RuntimeRequest, Vkd3dProtonRuntime, WindowsArchitecture};

const RECORD_HEADER: &str = "oxide-steam-launch-v1";
const REQUIRED_FIELDS: &[&str] = &[
    "appid", "image", "windows_path", "command_line", "prefix", "runtime",
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
    pub config: ProtonLaunchConfig,
}

impl SteamLaunchRecord {
    /// Parse one complete record; duplicate, unknown, missing, and malformed fields fail closed.
    /// # C: O(record bytes)
    pub fn from_path(path: &Path) -> Result<Self, BuildError> {
        let bytes = fs::read(path).map_err(BuildError::Io)?;
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
        let config = ProtonLaunchConfig {
            architecture: WindowsArchitecture::X86_64,
            prefix: path("prefix")?, runtime: path("runtime")?, dll_catalog: path("dll_catalog")?,
            unixlib: path("unixlib")?, nls: path("nls")?, registry_socket: path("registry_socket")?,
            registry_database: path("registry_database")?, dxvk: path("dxvk")?,
            vkd3d: Vkd3dProtonRuntime { path: path("vkd3d")?, version: get("vkd3d_version")?.to_owned(), identity: get("vkd3d_identity")?.to_owned() },
            faudio: path("faudio")?,
        };
        Ok(Self { appid, image, windows_path, command_line, config })
    }

    /// Validate record-owned paths and build the existing owned NT request.
    /// # C: O(path bytes + filesystem metadata + PE/catalog bytes)
    pub fn into_request(self) -> Result<RuntimeRequest, BuildError> {
        let image_bytes = self.image.as_os_str().as_bytes();
        if image_bytes.is_empty() || image_bytes.contains(&0) || !self.image.is_absolute() || !self.image.is_file() {
            return Err(BuildError::InvalidLaunchConfiguration { field: "image" });
        }
        self.config.validate()?;
        let mut environment = self.config.profile().environment();
        environment.push(("SteamAppId".to_owned(), self.appid.to_string()));
        environment.push(("SteamGameId".to_owned(), self.appid.to_string()));
        RuntimeRequest::from_paths_with_environment(&self.image, &self.windows_path, &self.command_line, &self.config.dll_catalog, environment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(extra: &str) -> String {
        format!("{RECORD_HEADER}\nappid=1234\nimage=/games/1234/game.exe\nwindows_path=C:\\\\game.exe\ncommand_line=C:\\\\game.exe -windowed\nprefix=/games/1234/pfx\nruntime=/opt/proton\ndll_catalog=/opt/proton/files/lib64/wine/x86_64-windows\nunixlib=/opt/proton/files/lib64/wine/x86_64-unix\nnls=/opt/proton/files/share/wine/nls.nls\nregistry_socket=/run/oxide/registry.sock\nregistry_database=/games/1234/registry.db\ndxvk=/opt/proton/dxvk\nvkd3d=/opt/proton/vkd3d-proton\nvkd3d_version=v3.0.1\nvkd3d_identity=0123456789012345678901234567890123456789\nfaudio=/opt/proton/faudio\n{extra}")
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
}
