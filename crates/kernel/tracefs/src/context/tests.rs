use super::*;
use kernfs::mount_opts::DirAttr;
use vfs::fs::{vfs_parse_fs_param, FsFlags, FsType};

fn mount_context() -> FsContext {
    let ty = FsType::with_context_parameters(
        "debugfs-test", crate::fs_impl::DEBUGFS_SUPER_MAGIC, FsFlags::empty(),
        Arc::new(DebugfsContextOps), crate::mount_opts::DEBUGFS_PARAMS,
    );
    FsContext::for_mount(ty, 0)
}

/// The whole point of the typed context: an unrecognised key does not fail the
/// mount, and the recognised ones in the same string still take effect.
#[test]
fn an_unknown_key_is_swallowed_while_the_declared_ones_are_consumed() {
    let mut fc = mount_context();
    for (k, v) in [("bogus", "1"), ("uid", "1000"), ("nosuchthing", "x"), ("mode", "700")] {
        vfs_parse_fs_param(&mut fc, &FsParameter::string(k, v))
            .unwrap_or_else(|_| panic!("debugfs refused -o {k}={v}"));
    }
    vfs_parse_fs_param(&mut fc, &FsParameter::flag("alsobogus")).expect("a bare unknown word");
    let opts = *state(&mut fc).lock();
    assert_eq!((opts.uid, opts.mode, opts.gid), (Some(1000), Some(0o700), None));
}

/// Leniency stops at the value: a declared key with an unreadable value is the
/// same refusal it is anywhere else.
#[test]
fn a_declared_key_with_a_bad_value_still_fails_the_mount() {
    for (k, v) in [("mode", "9"), ("uid", "x"), ("gid", "")] {
        let mut fc = mount_context();
        assert!(vfs_parse_fs_param(&mut fc, &FsParameter::string(k, v)).is_err(),
            "-o {k}={v} must fail");
    }
    // A declared value-taking key given as a bare flag is a shape error.
    let mut fc = mount_context();
    assert!(vfs_parse_fs_param(&mut fc, &FsParameter::flag("uid")).is_err());
}

/// `source` reaches the VFS's own source rung, including its refusal of a
/// second one — debugfs declares the key but stores nothing of its own.
#[test]
fn source_is_recorded_by_the_vfs_and_a_second_one_is_refused() {
    let mut fc = mount_context();
    vfs_parse_fs_param(&mut fc, &FsParameter::string("source", "none")).expect("source");
    assert_eq!(fc.source(), Some("none"));
    assert!(vfs_parse_fs_param(&mut fc, &FsParameter::string("source", "other")).is_err());
    assert!(state(&mut fc).lock().is_empty(), "source sets no root attribute");
}

/// Building the tree is what stamps the root — this test owns the debugfs
/// global tree, so no other test in this crate touches it.
#[test]
fn realizing_the_context_stamps_the_debugfs_root() {
    let root = crate::debug_root();
    let mut fc = mount_context();
    for (k, v) in [("uid", "12"), ("gid", "34"), ("mode", "710")] {
        vfs_parse_fs_param(&mut fc, &FsParameter::string(k, v)).expect("declared");
    }
    let opts = *state(&mut fc).lock();
    stamp_debugfs(&opts);
    assert_eq!(root.attr(), DirAttr { uid: 12, gid: 34, perm: 0o710 });
    let inode = root.as_inode();
    assert_eq!((inode.uid(), inode.gid(), inode.perm()), (Some(12), Some(34), Some(0o710)));

    // An option-less mount of the same tree leaves it alone.
    let mut fc2 = mount_context();
    vfs_parse_fs_param(&mut fc2, &FsParameter::string("bogus", "1")).expect("swallowed");
    stamp_debugfs(&*state(&mut fc2).lock());
    assert_eq!(root.attr(), DirAttr { uid: 12, gid: 34, perm: 0o710 });
}
