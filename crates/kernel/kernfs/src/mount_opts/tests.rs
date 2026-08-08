use super::*;
use alloc::format;

fn parse(specs: &'static [FsParamSpec], data: &str) -> Result<RootAttrOpts, VfsError> {
    opts_for_mount(specs, data, &[], UnknownKey::Refuse)
}

#[test]
fn mode_is_read_in_octal_and_masked_to_the_caller_settable_bits() {
    let o = parse(ROOT_ATTR_PARAMS, "mode=755").expect("mode");
    assert_eq!(o.mode, Some(0o755), "mode is OCTAL, not decimal 755");
    let o = parse(ROOT_ATTR_PARAMS, "mode=170777").expect("masked, not refused");
    assert_eq!(o.mode, Some(0o777), "S_IALLUGO keeps only the low 12 bits");
    assert_eq!(o.mode.unwrap() & !S_IALLUGO, 0);
}

#[test]
fn a_uid_or_gid_of_zero_is_a_value_and_not_an_absence() {
    let o = parse(ROOT_ATTR_PARAMS, "uid=0,gid=0").expect("root-owned");
    assert_eq!((o.uid, o.gid), (Some(0), Some(0)));
    assert!(!o.is_empty());
    assert!(show_options(&o).contains(",uid=0"));
}

#[test]
fn an_option_less_mount_names_nothing_and_therefore_changes_nothing() {
    let o = parse(ROOT_ATTR_PARAMS, "").expect("no options");
    assert_eq!(o, RootAttrOpts::default());
    assert!(o.is_empty());
    let live = DirAttr { uid: 42, gid: 43, perm: 0o700 };
    assert_eq!(o.apply_to(live), live, "an unnamed field keeps what is already there");
}

#[test]
fn only_the_named_fields_are_folded_onto_what_is_already_there() {
    let o = parse(ROOT_ATTR_PARAMS, "gid=5").expect("gid");
    let live = DirAttr { uid: 42, gid: 43, perm: 0o700 };
    assert_eq!(o.apply_to(live), DirAttr { uid: 42, gid: 5, perm: 0o700 });

    let o = parse(ROOT_ATTR_PARAMS, "uid=1000,gid=1000,mode=750").expect("all three");
    assert_eq!(o.apply_to(DirAttr::default()), DirAttr { uid: 1000, gid: 1000, perm: 0o750 });
}

#[test]
fn a_fresh_root_is_root_owned_and_world_searchable() {
    assert_eq!(DirAttr::default(), DirAttr { uid: 0, gid: 0, perm: 0o755 });
}

#[test]
fn a_key_the_table_does_not_list_is_refused() {
    for bad in ["bogus=1", "size=64m", "nr_inodes=10"] {
        assert_eq!(parse(ROOT_ATTR_PARAMS, bad), Err(VfsError::Einval), "{bad}");
    }
    // efivarfs has no `mode=`; that it is a DIFFERENT table is the only reason
    // `-o mode=700` fails there and succeeds on tracefs.
    assert_eq!(parse(OWNER_ONLY_PARAMS, "mode=700"), Err(VfsError::Einval));
    assert!(parse(ROOT_ATTR_PARAMS, "mode=700").is_ok());
    assert!(parse(OWNER_ONLY_PARAMS, "uid=0,gid=0").is_ok());
}

#[test]
fn an_unparseable_value_is_refused_even_where_an_unknown_key_is_ignored() {
    for bad in ["mode=", "mode=9", "mode=abc", "uid=-1", "uid=x", "gid="] {
        assert_eq!(parse(ROOT_ATTR_PARAMS, bad), Err(VfsError::Einval), "{bad}");
        assert_eq!(opts_for_mount(ROOT_ATTR_PARAMS, bad, &[], UnknownKey::Ignore),
            Err(VfsError::Einval), "{bad} is a bad VALUE, not an unknown key");
    }
    // 8 and 9 are not octal digits: `mode=800` is a typo, not 0o800.
    assert_eq!(parse(ROOT_ATTR_PARAMS, "mode=800"), Err(VfsError::Einval));
}

#[test]
fn value_shape_is_enforced_and_is_a_different_refusal_from_an_unknown_key() {
    for k in ["uid", "gid", "mode"] {
        assert_eq!(parse(ROOT_ATTR_PARAMS, k), Err(VfsError::Einval), "-o {k} needs a value");
        assert_eq!(opts_for_mount(ROOT_ATTR_PARAMS, k, &[], UnknownKey::Ignore),
            Err(VfsError::Einval), "-o {k} is a shape error, which leniency does not cover");
    }
}

/// debugfs's leniency: an unknown KEY is swallowed, and the options that ARE
/// declared still take effect in the same blob.
#[test]
fn a_lenient_filesystem_ignores_an_unknown_key_and_still_honours_the_rest() {
    let o = opts_for_mount(ROOT_ATTR_SOURCE_PARAMS, "bogus,alsobogus=7,uid=17,mode=700",
        &[], UnknownKey::Ignore).expect("debugfs swallows what it does not know");
    assert_eq!((o.uid, o.mode), (Some(17), Some(0o700)));
    assert_eq!(opts_for_mount(ROOT_ATTR_SOURCE_PARAMS, "bogus", &[], UnknownKey::Refuse),
        Err(VfsError::Einval), "a strict table refuses the same blob");
}

/// `source` is declared where the reference declares it, and consuming it is a
/// no-op: the VFS records the source before the filesystem is consulted.
#[test]
fn source_is_declared_where_the_reference_declares_it_and_sets_no_attribute() {
    let o = parse(ROOT_ATTR_SOURCE_PARAMS, "source=none,uid=3").expect("source");
    assert_eq!(o.uid, Some(3));
    assert_eq!(o.mode, None);
    assert_eq!(parse(ROOT_ATTR_PARAMS, "source=none"), Err(VfsError::Einval),
        "tracefs does not declare source");
}

#[test]
fn a_pinned_parameter_is_refused_because_no_key_here_takes_one() {
    assert_eq!(opts_for_mount(ROOT_ATTR_PARAMS, "", &[FsParameter::string("uid", "0")],
        UnknownKey::Refuse), Err(VfsError::Einval));
}

/// The table and the parse must agree — a name in one and not the other is how
/// an option becomes accepted-and-ignored. Every name in these three tables
/// EXCEPT `source` must set a root attribute; `source` is the one key the VFS
/// answers before the filesystem is consulted.
#[test]
fn every_declared_parameter_is_one_the_parse_consumes() {
    for (specs, len) in [(ROOT_ATTR_PARAMS, 3), (ROOT_ATTR_SOURCE_PARAMS, 4),
                         (OWNER_ONLY_PARAMS, 2)] {
        assert_eq!(specs.len(), len, "a new parameter needs a case here and an enforcement site");
        for spec in specs {
            let probe = match spec.name {
                "uid" | "gid" => "0",
                "mode" => "700",
                "source" => "none",
                other => panic!("undeclared-but-listed parameter {other}"),
            };
            let blob = format!("{}={}", spec.name, probe);
            assert!(opts_for_mount(specs, &blob, &[], UnknownKey::Refuse).is_ok(),
                "{} is declared but refused", spec.name);

            let mut o = RootAttrOpts::default();
            let sets_attr = apply_param(&mut o, spec.name, Some(probe))
                .unwrap_or_else(|_| panic!("{} declared but unparseable", spec.name));
            assert_eq!(sets_attr, spec.name != "source",
                "{} is declared here but lands on no root attribute", spec.name);
            assert_eq!(o.is_empty(), !sets_attr);
        }
    }
}

/// A key a filesystem declares but answers elsewhere parses to "no attribute"
/// rather than to a failure — that is what lets bpffs declare `delegate_*`
/// without this module pretending to enforce it.
#[test]
fn a_declared_key_answered_elsewhere_sets_no_attribute_and_is_not_an_error() {
    let mut o = RootAttrOpts::default();
    assert_eq!(apply_param(&mut o, "delegate_cmds", Some("any")), Ok(false));
    assert_eq!(apply_param(&mut o, "source", Some("none")), Ok(false));
    assert!(o.is_empty());
    // But a root attribute given no value is still an error, not a shrug.
    for k in ["uid", "gid", "mode"] { assert_eq!(apply_param(&mut o, k, None), Err(())); }
}

/// An empty table is a declaration, and it refuses everything.
#[test]
fn the_no_parameter_declaration_refuses_every_key() {
    assert!(NO_PARAMETERS.is_empty());
    for bad in ["uid=0", "mode=700", "anything", "anything=1"] {
        assert_eq!(opts_for_mount(NO_PARAMETERS, bad, &[], UnknownKey::Refuse),
            Err(VfsError::Einval), "{bad}");
    }
    assert!(opts_for_mount(NO_PARAMETERS, "", &[], UnknownKey::Refuse).is_ok());
}

#[test]
fn the_shown_options_round_trip() {
    assert_eq!(show_options(&RootAttrOpts::default()), "");
    let o = parse(ROOT_ATTR_PARAMS, "uid=0,gid=5,mode=20").expect("parse");
    assert_eq!(show_options(&o), ",uid=0,gid=5,mode=020",
        "modes print with three digits so they read back as the same value");
    assert_eq!(parse(ROOT_ATTR_PARAMS, show_options(&o).trim_start_matches(',')), Ok(o));
}

/// The enforcement, not just the parse: the tree node the mount stamped is what
/// a later inode rebuild is built from, so the option survives the icache
/// dropping the inode.
#[test]
fn stamping_a_root_changes_the_inode_and_survives_a_rebuild() {
    let root = PseudoDir::new_root(crate::PSEUDO_ROOT_INO, 0x1234);
    assert_eq!(root.as_inode().uid(), Some(0));
    assert_eq!(root.as_inode().perm(), Some(DEFAULT_ROOT_PERM));

    let opts = parse(ROOT_ATTR_PARAMS, "uid=1000,gid=1000,mode=750").expect("parse");
    apply_root_attr(&root, &opts);

    assert_eq!(root.attr(), DirAttr { uid: 1000, gid: 1000, perm: 0o750 });
    let live = root.as_inode();
    assert_eq!((live.uid(), live.gid(), live.perm()), (Some(1000), Some(1000), Some(0o750)));
    drop(live);
    // A fresh build, as the next lookup after an icache eviction would do.
    let rebuilt = PseudoDir::new_root(crate::PSEUDO_ROOT_INO, 0x1234);
    rebuilt.set_attr(DirAttr { uid: 1000, gid: 1000, perm: 0o750 });
    assert_eq!((rebuilt.as_inode().uid(), rebuilt.as_inode().perm()), (Some(1000), Some(0o750)));
}

#[test]
fn a_mount_that_names_nothing_does_not_reset_a_root_an_earlier_mount_stamped() {
    let root = PseudoDir::new_root(crate::PSEUDO_ROOT_INO, 0x1234);
    apply_root_attr(&root, &parse(ROOT_ATTR_PARAMS, "uid=7,mode=700").expect("first"));
    apply_root_attr(&root, &parse(ROOT_ATTR_PARAMS, "").expect("second, option-less"));
    assert_eq!(root.attr(), DirAttr { uid: 7, gid: 0, perm: 0o700 });

    apply_root_attr(&root, &parse(ROOT_ATTR_PARAMS, "gid=9").expect("third"));
    assert_eq!(root.attr(), DirAttr { uid: 7, gid: 9, perm: 0o700 },
        "only the named field moves");
}
