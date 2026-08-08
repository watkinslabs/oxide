// Option-table + journalled-quota-file-name behaviour, encoded so the
// contract can be re-checked without reading any other implementation.

use crate::mount_opts::flags::*;
use crate::mount_opts::Ext4MountOpts;
use super::parsed;

use vfs::{QuotaType, VfsError};

const USR: usize = 0;
const GRP: usize = 1;

#[test]
fn empty_data_touches_no_quota_option() {
    let o = Ext4MountOpts::parse("").expect("empty option string is valid");
    assert_eq!(o.mask, 0);
    assert_eq!(o.vals, 0);
    assert!(!o.spec_jquota);
    assert!(!o.spec_jqfmt);
    assert!(o.other.is_empty());
}

#[test]
fn flag_options_set_their_documented_bits() {
    let table = [
        ("quota",    EXT4_MOUNT_QUOTA | EXT4_MOUNT_USRQUOTA),
        ("usrquota", EXT4_MOUNT_QUOTA | EXT4_MOUNT_USRQUOTA),
        ("grpquota", EXT4_MOUNT_QUOTA | EXT4_MOUNT_GRPQUOTA),
        ("prjquota", EXT4_MOUNT_QUOTA | EXT4_MOUNT_PRJQUOTA),
    ];
    for (opt, bits) in table {
        let o = Ext4MountOpts::parse(opt).expect("flag option parses");
        assert_eq!(o.vals, bits, "{opt} values");
        assert_eq!(o.mask, bits, "{opt} mask");
    }
}

#[test]
fn noquota_masks_every_quota_bit_and_sets_none() {
    let o = Ext4MountOpts::parse("noquota").expect("noquota parses");
    assert_eq!(o.mask, EXT4_MOUNT_QUOTA_MASK);
    assert_eq!(o.vals, 0);
}

#[test]
fn quota_and_noquota_do_not_conflict_last_one_wins() {
    // Not an error: the option table is set/clear, so the later token wins.
    let off = Ext4MountOpts::parse("usrquota,noquota").expect("usrquota,noquota parses");
    assert_eq!(off.vals, 0);
    assert_eq!(off.mask, EXT4_MOUNT_QUOTA_MASK);

    let on = Ext4MountOpts::parse("noquota,usrquota").expect("noquota,usrquota parses");
    assert_eq!(on.vals, EXT4_MOUNT_QUOTA | EXT4_MOUNT_USRQUOTA);
    assert_eq!(on.mask, EXT4_MOUNT_QUOTA_MASK);
}

#[test]
fn flag_option_given_a_value_is_einval() {
    for opt in ["quota=1", "usrquota=1", "grpquota=x", "prjquota=", "noquota=0"] {
        assert_eq!(Ext4MountOpts::parse(opt).err(), Some(VfsError::Einval), "{opt}");
    }
}

#[test]
fn journalled_quota_file_names_land_in_their_class_slot() {
    let o = Ext4MountOpts::parse("usrjquota=aquota.user,grpjquota=aquota.group")
        .expect("journalled quota names parse");
    assert_eq!(o.qf_name(USR), Some("aquota.user"));
    assert_eq!(o.qf_name(GRP), Some("aquota.group"));
    assert!(o.spec_jquota);
    assert!(o.names_slot(USR) && o.names_slot(GRP));
    // Naming a file is not itself a plain-quota option.
    assert_eq!(o.vals, 0);
}

#[test]
fn empty_journalled_quota_name_un_names_the_class() {
    let o = Ext4MountOpts::parse("usrjquota=aquota.user,usrjquota=")
        .expect("empty name un-names");
    assert_eq!(o.qf_name(USR), None);
    assert!(o.spec_jquota);
    assert!(o.names_slot(USR));
}

#[test]
fn journalled_quota_file_must_sit_in_the_filesystem_root() {
    for opt in ["usrjquota=quota/aquota.user", "grpjquota=/aquota.group"] {
        assert_eq!(Ext4MountOpts::parse(opt).err(), Some(VfsError::Einval), "{opt}");
    }
}

#[test]
fn repeating_the_same_journalled_name_is_accepted_a_different_one_is_not() {
    let same = Ext4MountOpts::parse("usrjquota=aquota.user,usrjquota=aquota.user")
        .expect("identical repeat is accepted");
    assert_eq!(same.qf_name(USR), Some("aquota.user"));

    assert_eq!(
        Ext4MountOpts::parse("usrjquota=aquota.user,usrjquota=other.user").err(),
        Some(VfsError::Einval),
    );
}

#[test]
fn value_option_without_a_value_is_einval() {
    for opt in ["usrjquota", "grpjquota", "jqfmt"] {
        assert_eq!(Ext4MountOpts::parse(opt).err(), Some(VfsError::Einval), "{opt}");
    }
}

#[test]
fn jqfmt_accepts_exactly_the_three_quota_formats() {
    let table = [
        ("jqfmt=vfsold", vfs::QFMT_VFS_OLD),
        ("jqfmt=vfsv0",  vfs::QFMT_VFS_V0),
        ("jqfmt=vfsv1",  vfs::QFMT_VFS_V1),
    ];
    for (opt, fmt) in table {
        let o = Ext4MountOpts::parse(opt).expect("jqfmt parses");
        assert!(o.spec_jqfmt, "{opt}");
        assert_eq!(o.jquota_fmt, fmt, "{opt}");
    }
    for opt in ["jqfmt=vfsv2", "jqfmt=", "jqfmt=VFSV1"] {
        assert_eq!(Ext4MountOpts::parse(opt).err(), Some(VfsError::Einval), "{opt}");
    }
}

#[test]
fn jqfmt_name_round_trips_and_rejects_unknown_ids() {
    for name in ["vfsold", "vfsv0", "vfsv1"] {
        let id = jqfmt_from_name(name).expect("known name");
        assert_eq!(jqfmt_name(id), Some(name));
    }
    assert_eq!(jqfmt_name(0), None);
    assert_eq!(jqfmt_from_name("vfsv3"), None);
}

#[test]
fn limit_bit_maps_each_quota_class() {
    assert_eq!(limit_bit(QuotaType::User), EXT4_MOUNT_USRQUOTA);
    assert_eq!(limit_bit(QuotaType::Group), EXT4_MOUNT_GRPQUOTA);
    assert_eq!(limit_bit(QuotaType::Project), EXT4_MOUNT_PRJQUOTA);
}

#[test]
fn a_token_no_consumer_owns_is_carried_not_rejected() {
    // ext4 is the root filesystem: an option this driver does not model must
    // never turn into a failed mount. An option it DOES model is acted on and
    // must not land here — a token in `other` is a token nothing reads.
    let data = "rw,relatime,errors=remount-ro,data=ordered,discard,usrquota";
    let o = Ext4MountOpts::parse(data).expect("unmodelled options are tolerated");
    assert_eq!(o.vals, EXT4_MOUNT_QUOTA | EXT4_MOUNT_USRQUOTA);
    assert_eq!(o.other, ["rw", "relatime"], "only the two nothing consumes");
    assert_eq!(o.behaviour.errors, crate::mount_opts::ErrorsPolicy::RemountRo);
    assert_eq!(o.behaviour.data, crate::mount_opts::DataMode::Ordered);
    assert!(o.behaviour.discard);
}

#[test]
fn empty_tokens_are_skipped() {
    let o = Ext4MountOpts::parse(",,usrquota,,").expect("empty tokens skipped");
    assert_eq!(o.vals, EXT4_MOUNT_QUOTA | EXT4_MOUNT_USRQUOTA);
    assert!(o.other.is_empty());
}

#[test]
fn a_named_quota_file_drops_that_class_plain_quota_bit() {
    let o = parsed("usrjquota=aquota.user,usrquota,jqfmt=vfsv1")
        .expect("named file supersedes the plain option");
    assert!(!o.test_opt(EXT4_MOUNT_USRQUOTA));
    assert!(o.test_opt(EXT4_MOUNT_QUOTA));
}

#[test]
fn mixing_a_quota_file_with_the_other_class_plain_option_is_einval() {
    assert_eq!(parsed("usrjquota=aquota.user,grpquota").err(), Some(VfsError::Einval));
    assert_eq!(parsed("grpjquota=aquota.group,usrquota").err(), Some(VfsError::Einval));
}

#[test]
fn note_qf_name_is_slot_addressed_by_quota_class() {
    let mut o = Ext4MountOpts::default();
    o.note_qf_name(QuotaType::Group, "aquota.group").expect("group name");
    assert_eq!(o.qf_name(GRP), Some("aquota.group"));
    assert_eq!(o.qf_name(USR), None);
    assert!(o.names_slot(GRP) && !o.names_slot(USR));
}
