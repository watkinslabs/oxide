use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use windows_runtime::user_paths::{ensure_private_dir, validate_runtime_dir, UserPathError, UserPathInput, UserRuntimePaths};

fn root(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("oxide-user-paths-{name}-{}", std::process::id()))
}

fn input(home: &Path) -> UserPathInput {
    UserPathInput {
        prefix: None, database: None, socket: None, home: home.to_path_buf(),
        xdg_data_home: None, xdg_state_home: None, xdg_runtime_dir: Some(home.join("run")),
    }
}

#[test]
fn defaults_use_home_fallbacks_and_absolute_xdg_values() {
    let base = root("defaults");
    let mut value = input(&base.join("home"));
    let paths = UserRuntimePaths::select(&value).unwrap();
    assert_eq!(paths.prefix, base.join("home/.local/share/oxide/windows-prefix"));
    assert_eq!(paths.database, base.join("home/.local/state/oxide/registry.db"));
    assert_eq!(paths.socket, base.join("home/run/oxide/registry.sock"));
    value.xdg_data_home = Some(base.join("data"));
    value.xdg_state_home = Some(base.join("state"));
    value.xdg_runtime_dir = Some(base.join("runtime"));
    let paths = UserRuntimePaths::select(&value).unwrap();
    assert_eq!(paths.prefix, base.join("data/oxide/windows-prefix"));
    assert_eq!(paths.database, base.join("state/oxide/registry.db"));
    assert_eq!(paths.socket, base.join("runtime/oxide/registry.sock"));
    let _ = fs::remove_dir_all(base);
}

#[test]
fn explicit_paths_do_not_require_home_or_runtime_defaults() {
    let value = UserPathInput {
        prefix: Some(PathBuf::from("/explicit/prefix")),
        database: Some(PathBuf::from("/explicit/registry.db")),
        socket: Some(PathBuf::from("/explicit/registry.sock")),
        home: PathBuf::new(), xdg_data_home: None, xdg_state_home: None, xdg_runtime_dir: None,
    };
    assert_eq!(UserRuntimePaths::select(&value).unwrap().socket, PathBuf::from("/explicit/registry.sock"));
}

#[test]
fn absolute_xdg_defaults_need_no_home_and_reject_nul() {
    let mut value = input(Path::new(""));
    value.xdg_data_home = Some(PathBuf::from("/user/data"));
    value.xdg_state_home = Some(PathBuf::from("/user/state"));
    value.xdg_runtime_dir = Some(PathBuf::from("/user/run"));
    let paths = UserRuntimePaths::select(&value).unwrap();
    assert_eq!(paths.prefix, PathBuf::from("/user/data/oxide/windows-prefix"));
    assert_eq!(paths.database, PathBuf::from("/user/state/oxide/registry.db"));
    value.xdg_data_home = Some(PathBuf::from(OsString::from_vec(b"/bad\0data".to_vec())));
    assert!(matches!(UserRuntimePaths::select(&value), Err(UserPathError::NulPath("XDG_DATA_HOME"))));
}

#[test]
fn relative_xdg_values_are_ignored_independently() {
    let base = root("relative-xdg");
    let mut value = input(&base.join("home"));
    value.xdg_data_home = Some(PathBuf::from("relative-data"));
    value.xdg_state_home = Some(PathBuf::from("relative-state"));
    let paths = UserRuntimePaths::select(&value).unwrap();
    assert_eq!(paths.prefix, base.join("home/.local/share/oxide/windows-prefix"));
    assert_eq!(paths.database, base.join("home/.local/state/oxide/registry.db"));
    let _ = fs::remove_dir_all(base);
}

#[test]
fn relative_nul_and_missing_runtime_inputs_fail_closed() {
    let mut value = input(Path::new("/home/user"));
    value.prefix = Some(PathBuf::from("relative"));
    assert!(matches!(UserRuntimePaths::select(&value), Err(UserPathError::RelativePath("prefix"))));
    value.prefix = Some(PathBuf::from(OsString::from_vec(b"/bad\0prefix".to_vec())));
    assert!(matches!(UserRuntimePaths::select(&value), Err(UserPathError::NulPath("prefix"))));
    value.prefix = None;
    value.xdg_runtime_dir = None;
    assert!(matches!(UserRuntimePaths::select(&value), Err(UserPathError::MissingRuntimeDir)));
}

#[test]
fn runtime_symlink_is_rejected() {
    let base = root("symlink");
    fs::create_dir_all(&base).unwrap();
    let target = base.join("target");
    let link = base.join("runtime");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(matches!(validate_runtime_dir(&link), Err(UserPathError::RuntimeSymlink(_))));
    let _ = fs::remove_dir_all(base);
}

#[test]
fn fresh_private_directory_is_created_atomically_private() {
    let base = root("fresh");
    fs::create_dir_all(&base).unwrap();
    let child = base.join("private");
    ensure_private_dir(&child).unwrap();
    assert_eq!(fs::symlink_metadata(&child).unwrap().mode() & 0o7777, 0o700);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn existing_nonprivate_directory_is_not_rechmoded() {
    let base = root("existing");
    fs::create_dir_all(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(ensure_private_dir(&base), Err(UserPathError::RuntimePermissions { .. })));
    assert_eq!(fs::symlink_metadata(&base).unwrap().mode() & 0o7777, 0o755);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn concurrent_creation_revalidates_the_existing_winner() {
    let base = root("race");
    fs::create_dir_all(&base).unwrap();
    let child = Arc::new(base.join("private"));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let child = Arc::clone(&child);
        workers.push(std::thread::spawn(move || ensure_private_dir(&child)));
    }
    for worker in workers { worker.join().unwrap().unwrap(); }
    assert_eq!(fs::symlink_metadata(&*child).unwrap().mode() & 0o7777, 0o700);
    let _ = fs::remove_dir_all(base);
}
