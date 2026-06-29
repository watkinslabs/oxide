//! fsconfig param-type model (Linux `enum fs_value_type`, `fs/fsopen.c`
//! `SYSCALL_DEFINE5(fsconfig)`). The new mount API delivers ONE structured
//! parameter at a time, and the command byte (`FSCONFIG_SET_FLAG`/`_STRING`/
//! `_FD`/`_PATH`/`_PATH_EMPTY`/`_BINARY`) picks the typed value. Fails-before:
//! `FsValue` carried only `Flag`/`String`, so a `SET_FD`/`SET_PATH`/`SET_BINARY`
//! command had no typed representation and the value was dropped or coerced to a
//! string. These prove each command maps to a distinct typed `FsValue`, that the
//! typed accessors round-trip, and that a legacy backend rejects the value types
//! its comma-blob `->mount` cannot parse.

use std::sync::Arc;

use vfs::fs::fs_context::{
    vfs_parse_fs_param, FsContext, FsParameter, FsValue,
};
use vfs::superblock::{FileSystemType, SuperBlock};
use vfs::{KResult, VfsError};

struct Ty;
impl FileSystemType for Ty {
    fn name(&self) -> &str { "ptfs" }
    fn mount(&self, _src: &str, _opts: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

fn ctx() -> FsContext { FsContext::for_mount(Arc::new(Ty), 0) }

#[test]
fn each_command_maps_to_distinct_typed_value() {
    assert_eq!(FsParameter::flag("ro").value, FsValue::Flag);
    assert_eq!(FsParameter::string("size", "64m").value, FsValue::String("64m".to_string()));
    assert_eq!(FsParameter::fd("fd", 7).value, FsValue::File(7));
    assert_eq!(FsParameter::path("upperdir", "/a").value,
        FsValue::Filename { path: "/a".to_string(), empty: false });
    assert_eq!(FsParameter::path_empty("dir", "").value,
        FsValue::Filename { path: String::new(), empty: true });
    assert_eq!(FsParameter::blob("data", &[1, 2, 3]).value, FsValue::Blob(vec![1, 2, 3]));
}

#[test]
fn typed_accessors_round_trip_and_reject_wrong_type() {
    let s = FsParameter::string("k", "v");
    assert_eq!(s.as_str(), Some("v"));
    assert_eq!(s.as_fd(), None);
    assert_eq!(s.as_path(), None);
    assert_eq!(s.as_blob(), None);

    let f = FsParameter::fd("k", 11);
    assert_eq!(f.as_fd(), Some(11));
    assert_eq!(f.as_str(), None);

    let p = FsParameter::path_empty("k", "/mnt");
    assert_eq!(p.as_path(), Some(("/mnt", true)));
    assert_eq!(p.as_fd(), None);

    let b = FsParameter::blob("k", b"raw");
    assert_eq!(b.as_blob(), Some(&b"raw"[..]));
}

#[test]
fn legacy_backend_accepts_flag_and_string() {
    let mut fc = ctx();
    vfs_parse_fs_param(&mut fc, &FsParameter::flag("noexec")).unwrap();
    vfs_parse_fs_param(&mut fc, &FsParameter::string("mode", "0755")).unwrap();
    assert_eq!(fc.params().len(), 2);
    let opts = fc.legacy_options();
    assert!(opts.contains("noexec") && opts.contains("mode=0755"), "{opts}");
}

#[test]
fn legacy_backend_rejects_fd_path_blob_value_types() {
    // A legacy comma-blob `->mount` cannot parse an fd/path/binary value
    // (Linux `legacy_parse_param` default → invalf → -EINVAL).
    for p in [
        FsParameter::fd("fd", 3),
        FsParameter::path("upperdir", "/u"),
        FsParameter::path_empty("dir", ""),
        FsParameter::blob("data", &[0xde, 0xad]),
    ] {
        let mut fc = ctx();
        assert_eq!(vfs_parse_fs_param(&mut fc, &p).unwrap_err(), VfsError::Einval,
            "legacy backend rejects {:?}", p.value);
        assert_eq!(fc.params().len(), 0, "rejected param not accumulated");
    }
}

#[test]
fn source_must_be_a_string_not_fd_or_path() {
    // `source` is the generic handler's key; only a string value is a valid
    // source (Linux `vfs_parse_fs_param_source`).
    let mut fc = ctx();
    assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::fd("source", 3)).unwrap_err(),
        VfsError::Einval);
    let mut fc2 = ctx();
    assert_eq!(vfs_parse_fs_param(&mut fc2, &FsParameter::path("source", "/dev/x")).unwrap_err(),
        VfsError::Einval);
    // A string source still works.
    let mut fc3 = ctx();
    vfs_parse_fs_param(&mut fc3, &FsParameter::string("source", "/dev/vda1")).unwrap();
    assert_eq!(fc3.source(), Some("/dev/vda1"));
}
