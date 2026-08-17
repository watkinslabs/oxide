use crate::flags::*;
use crate::hash::HashAlgo;
use crate::policy::parse::{parse_rule, ParseError};
use crate::policy::rule::{CmpOp, LsmSlot};
use crate::uapi::Hook;

#[test]
fn minimal_rules() {
    let r = parse_rule("measure func=BPRM_CHECK").unwrap();
    assert_eq!(r.action, MEASURE);
    assert_eq!(r.func, Hook::BprmCheck);
    assert!(r.has(C_FUNC));

    let r = parse_rule("dont_measure fsmagic=0x9fa0").unwrap();
    assert_eq!(r.action, DONT_MEASURE);
    assert_eq!(r.fsmagic, 0x9fa0);
    assert!(r.has(C_FSMAGIC));
}

#[test]
fn every_action_keyword() {
    for (text, want) in [
        ("measure", MEASURE), ("dont_measure", DONT_MEASURE),
        ("appraise", APPRAISE), ("dont_appraise", DONT_APPRAISE),
        ("audit", AUDIT), ("dont_audit", DONT_AUDIT),
        ("hash", HASH), ("dont_hash", DONT_HASH),
    ] {
        let r = parse_rule(text).unwrap_or_else(|e| panic!("{text}: {e:?}"));
        assert_eq!(r.action, want, "{text}");
    }
}

#[test]
fn every_hook_token() {
    for tok in ["FILE_CHECK", "MMAP_CHECK", "MMAP_CHECK_REQPROT", "BPRM_CHECK", "CREDS_CHECK",
                "MODULE_CHECK", "FIRMWARE_CHECK", "POLICY_CHECK", "KEXEC_KERNEL_CHECK",
                "KEXEC_INITRAMFS_CHECK"] {
        let line = alloc::format!("measure func={tok}");
        let r = parse_rule(&line).unwrap_or_else(|e| panic!("{tok}: {e:?}"));
        assert_eq!(r.func, Hook::by_token(tok).unwrap());
    }
    assert_eq!(parse_rule("measure func=KEXEC_CMDLINE").unwrap().func, Hook::KexecCmdline);
    assert_eq!(parse_rule("measure func=KEY_CHECK").unwrap().func, Hook::KeyCheck);
    assert_eq!(parse_rule("measure func=CRITICAL_DATA").unwrap().func, Hook::CriticalData);
    assert_eq!(parse_rule("appraise func=SETXATTR_CHECK appraise_algos=sha256").unwrap().func,
               Hook::SetxattrCheck);
    // Historical spellings still resolve.
    assert_eq!(parse_rule("measure func=PATH_CHECK").unwrap().func, Hook::FileCheck);
    assert_eq!(parse_rule("measure func=FILE_MMAP").unwrap().func, Hook::MmapCheck);
}

#[test]
fn mask_exact_and_any_of() {
    let r = parse_rule("measure func=BPRM_CHECK mask=MAY_EXEC").unwrap();
    assert_eq!(r.mask, MAY_EXEC);
    assert!(r.has(C_MASK) && !r.has(C_INMASK));

    let r = parse_rule("measure func=FILE_CHECK mask=^MAY_READ").unwrap();
    assert_eq!(r.mask, MAY_READ);
    assert!(r.has(C_INMASK) && !r.has(C_MASK));

    for (t, want) in [("MAY_EXEC", MAY_EXEC), ("MAY_WRITE", MAY_WRITE),
                      ("MAY_READ", MAY_READ), ("MAY_APPEND", MAY_APPEND)] {
        let line = alloc::format!("measure func=FILE_CHECK mask={t}");
        assert_eq!(parse_rule(&line).unwrap().mask, want);
    }
}

#[test]
fn id_conditions_and_comparators() {
    let r = parse_rule("measure func=FILE_CHECK uid=0").unwrap();
    assert_eq!((r.uid, r.uid_op), (Some(0), CmpOp::Eq));
    assert!(r.has(C_UID));

    let r = parse_rule("measure func=FILE_CHECK uid>500").unwrap();
    assert_eq!((r.uid, r.uid_op), (Some(500), CmpOp::Gt));

    let r = parse_rule("measure func=FILE_CHECK euid<1000").unwrap();
    assert_eq!((r.uid, r.uid_op), (Some(1000), CmpOp::Lt));
    assert!(r.has(C_EUID) && !r.has(C_UID));

    let r = parse_rule("measure func=FILE_CHECK gid>10 fowner<20").unwrap();
    assert_eq!((r.gid, r.gid_op), (Some(10), CmpOp::Gt));
    assert_eq!((r.fowner, r.fowner_op), (Some(20), CmpOp::Lt));

    let r = parse_rule("measure func=FILE_CHECK egid=7 fgroup>3").unwrap();
    assert_eq!(r.gid, Some(7));
    assert!(r.has(C_EGID));
    assert_eq!((r.fgroup, r.fgroup_op), (Some(3), CmpOp::Gt));
}

#[test]
fn lsm_conditions() {
    let r = parse_rule("dont_measure obj_type=var_log_t subj_user=system_u").unwrap();
    assert_eq!(r.lsm_at(LsmSlot::ObjType), Some("var_log_t"));
    assert_eq!(r.lsm_at(LsmSlot::SubjUser), Some("system_u"));
    for key in ["obj_user", "obj_role", "obj_type", "subj_user", "subj_role", "subj_type"] {
        let line = alloc::format!("measure {key}=x");
        assert!(parse_rule(&line).is_ok(), "{key}");
    }
}

#[test]
fn appraise_type_and_digest_type() {
    let r = parse_rule("appraise func=MODULE_CHECK appraise_type=imasig").unwrap();
    assert!(r.flags & IMA_DIGSIG_REQUIRED != 0 && r.flags & IMA_CHECK_BLACKLIST != 0);

    let r = parse_rule("appraise func=MODULE_CHECK appraise_type=imasig|modsig").unwrap();
    assert!(r.flags & IMA_MODSIG_ALLOWED != 0 && r.flags & IMA_DIGSIG_REQUIRED != 0);

    let r = parse_rule("appraise func=FILE_CHECK appraise_type=sigv3").unwrap();
    assert!(r.flags & IMA_SIGV3_REQUIRED != 0 && r.flags & IMA_DIGSIG_REQUIRED != 0);

    let r = parse_rule("appraise func=FILE_CHECK digest_type=verity appraise_type=sigv3").unwrap();
    assert!(r.flags & IMA_VERITY_REQUIRED != 0);

    // An fs-verity digest can only be carried by a signature, so verity
    // without a signature requirement is refused.
    assert!(parse_rule("appraise func=FILE_CHECK digest_type=verity").is_err());
    // And a bare-digest appraisal type contradicts it outright.
    assert_eq!(parse_rule("appraise digest_type=verity appraise_type=imasig"),
               Err(ParseError::BadValue));
}

#[test]
fn pcr_template_and_directio() {
    let r = parse_rule("measure func=FILE_CHECK pcr=11").unwrap();
    assert_eq!(r.pcr, 11);
    assert!(r.has(C_PCR));

    let r = parse_rule("measure func=FILE_CHECK template=ima-sig").unwrap();
    assert_eq!(r.template.as_deref(), Some("ima-sig"));

    let r = parse_rule("appraise func=FILE_CHECK permit_directio").unwrap();
    assert!(r.flags & IMA_PERMIT_DIRECTIO != 0);
}

#[test]
fn appraise_algos_builds_an_allowlist() {
    let r = parse_rule("appraise func=FILE_CHECK appraise_algos=sha256,sha512").unwrap();
    assert!(r.has(C_VALIDATE_ALGOS));
    assert_eq!(r.allowed_algos,
               (1 << HashAlgo::Sha256.id()) | (1 << HashAlgo::Sha512.id()));
    assert!(parse_rule("appraise func=FILE_CHECK appraise_algos=nosuch").is_err());
}

#[test]
fn keyrings_and_labels_are_alternative_lists() {
    let r = parse_rule("measure func=KEY_CHECK keyrings=.builtin_trusted_keys|.ima").unwrap();
    assert_eq!(r.keyrings.as_deref().unwrap().len(), 2);
    let r = parse_rule("measure func=CRITICAL_DATA label=selinux").unwrap();
    assert_eq!(r.label.as_deref().unwrap(), &[alloc::string::String::from("selinux")]);
}

#[test]
fn fsuuid_and_fsname_and_subtype() {
    let r = parse_rule("dont_measure fsuuid=12345678-1234-5678-9abc-def012345678").unwrap();
    assert_eq!(r.fsuuid[0], 0x12);
    assert_eq!(r.fsuuid[15], 0x78);
    assert!(r.has(C_FSUUID));
    assert!(parse_rule("dont_measure fsuuid=not-a-uuid").is_err());

    let r = parse_rule("dont_measure fsname=tmpfs").unwrap();
    assert_eq!(r.fsname.as_deref(), Some("tmpfs"));
    let r = parse_rule("dont_measure fs_subtype=overlay").unwrap();
    assert_eq!(r.fs_subtype.as_deref(), Some("overlay"));
}

#[test]
fn comments_and_whitespace() {
    let r = parse_rule("measure  func=BPRM_CHECK\tmask=MAY_EXEC  # trailing note").unwrap();
    assert_eq!((r.action, r.func, r.mask), (MEASURE, Hook::BprmCheck, MAY_EXEC));
}

// --- refusals ------------------------------------------------------------

#[test]
fn unknown_keyword_is_refused() {
    assert_eq!(parse_rule("measure frobnicate=1"), Err(ParseError::UnknownKeyword));
    assert_eq!(parse_rule("measure nonsense"), Err(ParseError::UnknownKeyword));
}

#[test]
fn a_second_action_is_refused() {
    assert_eq!(parse_rule("measure dont_measure func=FILE_CHECK"),
               Err(ParseError::DuplicateAction));
    assert_eq!(parse_rule("appraise measure"), Err(ParseError::DuplicateAction));
}

#[test]
fn no_action_is_refused() {
    assert_eq!(parse_rule("func=FILE_CHECK"), Err(ParseError::InvalidRule));
    assert_eq!(parse_rule(""), Err(ParseError::InvalidRule));
}

#[test]
fn a_repeated_condition_is_refused() {
    for line in [
        "measure func=FILE_CHECK func=BPRM_CHECK",
        "measure func=FILE_CHECK mask=MAY_READ mask=MAY_EXEC",
        "dont_measure fsmagic=0x9fa0 fsmagic=0x62656572",
        "measure func=FILE_CHECK uid=0 uid=1",
        "measure func=FILE_CHECK uid=0 euid=1",
        "measure func=FILE_CHECK gid=0 egid=1",
        "measure func=FILE_CHECK fowner=0 fowner=1",
        "measure func=FILE_CHECK fgroup=0 fgroup=1",
        "dont_measure obj_type=a obj_type=b",
        "measure func=KEY_CHECK keyrings=a keyrings=b",
        "measure func=CRITICAL_DATA label=a label=b",
        "dont_measure fsuuid=12345678-1234-5678-9abc-def012345678 \
                      fsuuid=12345678-1234-5678-9abc-def012345678",
        "appraise func=FILE_CHECK appraise_algos=sha256 appraise_algos=sha512",
        "measure func=FILE_CHECK template=ima-ng template=ima-sig",
    ] {
        assert!(matches!(parse_rule(line), Err(ParseError::DuplicateCondition)), "{line}");
    }
}

#[test]
fn bad_values_are_refused() {
    for line in [
        "measure func=NO_SUCH_HOOK",
        "measure func=FILE_CHECK mask=MAY_FLY",
        "dont_measure fsmagic=zzz",
        "measure func=FILE_CHECK uid=notanumber",
        "measure func=FILE_CHECK uid=4294967295",
        "measure func=FILE_CHECK pcr=64",
        "measure func=FILE_CHECK pcr=-1",
        "measure func=FILE_CHECK template=no-such-template",
        "appraise func=FILE_CHECK appraise_type=nonsense",
    ] {
        assert!(matches!(parse_rule(line), Err(ParseError::BadValue)), "{line}");
    }
}

#[test]
fn conflicting_combinations_are_refused() {
    // A PCR selection is only meaningful for a measurement.
    assert!(parse_rule("appraise func=FILE_CHECK pcr=11").is_err());
    // A template selection is only meaningful for a measurement.
    assert!(parse_rule("appraise func=FILE_CHECK template=ima-ng").is_err());
    // Signature requirements are only meaningful for an appraisal.
    assert!(parse_rule("measure func=MODULE_CHECK appraise_type=imasig").is_err());
    // The command-line hook has no inode, so it cannot be appraised.
    assert!(parse_rule("appraise func=KEXEC_CMDLINE").is_err());
    // The key hook matches on keyrings, not on inode conditions.
    assert!(parse_rule("measure func=KEY_CHECK fsmagic=0x9fa0").is_err());
    assert!(parse_rule("measure func=KEY_CHECK obj_type=x").is_err());
    // The critical-data hook likewise.
    assert!(parse_rule("measure func=CRITICAL_DATA fowner=0").is_err());
    // The setxattr hook only ever restricts digest algorithms.
    assert!(parse_rule("appraise func=SETXATTR_CHECK").is_err());
    assert!(parse_rule("measure func=SETXATTR_CHECK appraise_algos=sha256").is_err());
    assert!(parse_rule("appraise func=SETXATTR_CHECK appraise_algos=sha256 uid=0").is_err());
}

#[test]
fn a_signature_requirement_carries_blacklist_checking() {
    // Blacklist checking without a signature requirement can never fire, and
    // is refused rather than stored.
    let mut r = parse_rule("appraise func=MODULE_CHECK appraise_type=imasig").unwrap();
    assert!(crate::policy::validate_rule(&r));
    r.flags &= !IMA_DIGSIG_REQUIRED;
    assert!(!crate::policy::validate_rule(&r));
}
