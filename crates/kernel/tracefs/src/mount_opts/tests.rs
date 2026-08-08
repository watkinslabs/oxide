use super::*;
use kernfs::mount_opts::{DirAttr, DEFAULT_ROOT_PERM};

/// tracefs refuses what it does not declare; debugfs accepts it. Same option
/// string, two answers, because the reference gives two answers.
#[test]
fn tracefs_refuses_an_unknown_key_and_debugfs_swallows_it() {
    assert_eq!(TRACEFS_UNKNOWN, UnknownKey::Refuse);
    assert_eq!(DEBUGFS_UNKNOWN, UnknownKey::Ignore);
    assert!(opts_for_mount(TRACEFS_PARAMS, "bogus=1", &[], TRACEFS_UNKNOWN).is_err());
    assert!(opts_for_mount(DEBUGFS_PARAMS, "bogus=1", &[], DEBUGFS_UNKNOWN).is_ok());
}

/// `source` is debugfs's fourth parameter and is not tracefs's third.
#[test]
fn only_debugfs_declares_source() {
    assert_eq!(TRACEFS_PARAMS.len(), 3);
    assert_eq!(DEBUGFS_PARAMS.len(), 4);
    assert!(DEBUGFS_PARAMS.iter().any(|s| s.name == "source"));
    assert!(!TRACEFS_PARAMS.iter().any(|s| s.name == "source"));
    for t in [TRACEFS_PARAMS, DEBUGFS_PARAMS] {
        for k in ["uid", "gid", "mode"] {
            assert!(t.iter().any(|s| s.name == k), "{k}");
        }
    }
}

/// configfs takes nothing, and says so in a form that can be checked.
#[test]
fn configfs_declares_no_parameters_and_refuses_every_key() {
    assert!(CONFIGFS_PARAMS.is_empty());
    assert!(mount_configfs("", &[]).is_ok());
    for bad in ["uid=0", "mode=755", "anything"] {
        assert_eq!(mount_configfs(bad, &[]), Err(VfsError::Einval), "{bad}");
    }
}

/// Even the lenient filesystem refuses a value it cannot read: leniency covers
/// an unrecognised NAME, never a bad value under a name it does declare.
#[test]
fn debugfs_leniency_does_not_extend_to_a_bad_value() {
    for bad in ["mode=9", "uid=x", "mode="] {
        assert!(opts_for_mount(DEBUGFS_PARAMS, bad, &[], DEBUGFS_UNKNOWN).is_err(), "{bad}");
    }
    let o = opts_for_mount(DEBUGFS_PARAMS, "bogus,uid=17", &[], DEBUGFS_UNKNOWN).expect("lenient");
    assert_eq!(o.uid, Some(17), "the declared key in the same blob still lands");
}

/// The enforcement: the tracefs mount's options reach the inode a `stat` of
/// `/sys/kernel/tracing` reads. Every other test here stays off the global
/// tree so this one owns it.
#[test]
fn tracefs_mount_options_land_on_the_tracefs_root_inode() {
    let root = crate::trace_root();
    assert_eq!(root.as_inode().perm(), Some(DEFAULT_ROOT_PERM), "born world-searchable");

    mount_tracefs("uid=1000,gid=1001,mode=750", &[]).expect("a tracefs mount");
    assert_eq!(root.attr(), DirAttr { uid: 1000, gid: 1001, perm: 0o750 });
    let inode = root.as_inode();
    assert_eq!((inode.uid(), inode.gid(), inode.perm()), (Some(1000), Some(1001), Some(0o750)));

    // A second mount naming only `gid` moves only `gid`.
    mount_tracefs("gid=5", &[]).expect("second mount");
    assert_eq!(root.attr(), DirAttr { uid: 1000, gid: 5, perm: 0o750 });

    // A refused mount changes nothing.
    assert!(mount_tracefs("bogus=1", &[]).is_err());
    assert!(mount_tracefs("mode=9", &[]).is_err());
    assert_eq!(root.attr(), DirAttr { uid: 1000, gid: 5, perm: 0o750 });
}

/// A parameter whose value is a pinned open file cannot belong to any of these
/// filesystems, so it is refused rather than silently ignored.
#[test]
fn a_pinned_parameter_is_refused() {
    assert!(mount_tracefs("", &[vfs::fs::FsParameter::string("uid", "0")]).is_err());
    assert!(mount_configfs("", &[vfs::fs::FsParameter::string("uid", "0")]).is_err());
}
