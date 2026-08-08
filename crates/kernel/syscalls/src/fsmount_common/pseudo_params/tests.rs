use super::*;
use kernfs::mount_opts::{DirAttr, DEFAULT_ROOT_PERM};
use vfs::VfsError;

const TEST_MAGIC: u64 = 0xde5e_81e4;

/// efivarfs's contract: two keys, and neither of them is `mode`.
#[test]
fn efivarfs_declares_owner_and_nothing_else() {
    assert_eq!(EFIVARFS_PARAMS.len(), 2);
    for k in ["uid", "gid"] { assert!(EFIVARFS_PARAMS.iter().any(|s| s.name == k), "{k}"); }
    assert!(!EFIVARFS_PARAMS.iter().any(|s| s.name == "mode"));
    assert!(pseudo_with_root_attr("efivarfs", TEST_MAGIC, EFIVARFS_PARAMS, "mode=700", &[]).is_err());
    assert!(pseudo_with_root_attr("efivarfs", TEST_MAGIC, EFIVARFS_PARAMS, "uid=0,gid=0", &[]).is_ok());
}

/// The mount's owner reaches the root inode of the instance it created, and
/// only that instance — each mount builds its own tree.
#[test]
fn an_efivarfs_mount_owns_its_own_root() {
    let fs = pseudo_with_root_attr("efivarfs", TEST_MAGIC, EFIVARFS_PARAMS, "uid=17,gid=18", &[])
        .expect("mount");
    assert_eq!(fs.root_dir().attr(), DirAttr { uid: 17, gid: 18, perm: DEFAULT_ROOT_PERM });
    let inode = fs.root_dir().as_inode();
    assert_eq!((inode.uid(), inode.gid()), (Some(17), Some(18)));

    let other = pseudo_with_root_attr("efivarfs", TEST_MAGIC, EFIVARFS_PARAMS, "", &[])
        .expect("option-less mount");
    assert_eq!(other.root_dir().attr(), DirAttr::default(), "a second mount is its own tree");
}

/// bpffs declares the reference's seven, and the three that name the root are
/// the three that land on it.
#[test]
fn bpffs_declares_seven_parameters_and_consumes_the_three_that_name_the_root() {
    assert_eq!(BPF_PARAMS.len(), 7);
    for k in ["uid", "gid", "mode",
              "delegate_cmds", "delegate_maps", "delegate_progs", "delegate_attachs"] {
        assert!(BPF_PARAMS.iter().any(|s| s.name == k), "{k} is not declared");
    }
    let fs = pseudo_with_root_attr("bpf", TEST_MAGIC, BPF_PARAMS, "uid=0,gid=0,mode=700", &[])
        .expect("mount");
    assert_eq!(fs.root_dir().attr(), DirAttr { uid: 0, gid: 0, perm: 0o700 });
}

/// A `delegate_*` value is accepted — refusing it would fail a mount the
/// reference completes — and is a string, not a number. It names no root
/// attribute: the answer belongs to the bpf token subsystem, and this test
/// records exactly which half of the table each name is in so the split cannot
/// drift silently.
#[test]
fn a_delegate_value_is_accepted_as_a_string_and_names_no_root_attribute() {
    let mut names_root = 0;
    for spec in BPF_PARAMS {
        let probe = match spec.name {
            "uid" | "gid" => "0",
            "mode" => "700",
            _ => "any",
        };
        let blob = alloc::format!("{}={}", spec.name, probe);
        assert!(pseudo_with_root_attr("bpf", TEST_MAGIC, BPF_PARAMS, &blob, &[]).is_ok(),
            "{} is declared but refused", spec.name);
        // A value-taking key given as a bare word is still a shape error.
        assert!(pseudo_with_root_attr("bpf", TEST_MAGIC, BPF_PARAMS, spec.name, &[]).is_err(),
            "{} needs a value", spec.name);

        let mut o = kernfs::mount_opts::RootAttrOpts::default();
        let sets = kernfs::mount_opts::apply_param(&mut o, spec.name, Some(probe)).expect("parse");
        assert_eq!(sets, !spec.name.starts_with("delegate_"), "{}", spec.name);
        if sets { names_root += 1; }
    }
    assert_eq!(names_root, 3, "uid/gid/mode are the three bpffs options this mount enforces");
}

#[test]
fn a_key_outside_the_bpffs_table_is_refused() {
    for bad in ["size=64m", "delegate=any", "delegate_cmd=any", "nosuchopt"] {
        assert!(pseudo_with_root_attr("bpf", TEST_MAGIC, BPF_PARAMS, bad, &[]).is_err(), "{bad}");
    }
}

/// A type that declares no parameters mounts clean and refuses everything else
/// — that refusal is the whole content of the declaration.
#[test]
fn a_no_parameter_type_mounts_clean_and_refuses_every_option() {
    let fs = pseudo_no_params("securityfs", TEST_MAGIC, "", &[]).expect("plain mount");
    assert_eq!(fs.root_dir().attr(), DirAttr::default());
    for bad in ["uid=0", "mode=755", "anything", "anything=1"] {
        assert_eq!(pseudo_no_params("securityfs", TEST_MAGIC, bad, &[]).err(),
            Some(VfsError::Einval), "{bad}");
    }
}

#[test]
fn a_pinned_parameter_is_refused_by_every_table_here() {
    let pinned = [FsParameter::string("uid", "0")];
    assert!(pseudo_with_root_attr("efivarfs", TEST_MAGIC, EFIVARFS_PARAMS, "", &pinned).is_err());
    assert!(pseudo_with_root_attr("bpf", TEST_MAGIC, BPF_PARAMS, "", &pinned).is_err());
    assert!(pseudo_no_params("mqueue", TEST_MAGIC, "", &pinned).is_err());
}
