use crate::policy::parse::parse_rule;
use crate::policy::show::{show_rule, uuid_str};

fn round_trip(line: &str) {
    let r = parse_rule(line).unwrap_or_else(|e| panic!("{line}: {e:?}"));
    let shown = show_rule(&r);
    let back = parse_rule(shown.trim_end())
        .unwrap_or_else(|e| panic!("rendered {shown:?} did not parse: {e:?}"));
    assert_eq!(r, back, "rendered as {shown:?}");
}

#[test]
fn rendered_rules_parse_back_to_the_same_rule() {
    for line in [
        "measure func=BPRM_CHECK mask=MAY_EXEC",
        "measure func=FILE_CHECK mask=^MAY_READ uid=0",
        "dont_measure fsmagic=0x9fa0",
        "dont_measure fsname=tmpfs",
        "dont_measure fs_subtype=overlay",
        "dont_measure fsuuid=12345678-1234-5678-9abc-def012345678",
        "measure func=FILE_CHECK euid>1000 fowner<500 fgroup>2",
        "measure func=FILE_CHECK gid=10",
        "measure func=FILE_CHECK egid=10",
        "measure func=KEY_CHECK keyrings=.ima|.evm",
        "measure func=CRITICAL_DATA label=selinux",
        "measure func=BPRM_CHECK mask=MAY_EXEC pcr=11 template=ima-sig",
        "appraise func=MODULE_CHECK appraise_type=imasig",
        "appraise func=MODULE_CHECK appraise_type=imasig|modsig",
        "appraise func=FILE_CHECK appraise_type=sigv3 digest_type=verity",
        "appraise func=FILE_CHECK appraise_algos=sha256,sha512",
        "appraise func=FILE_CHECK permit_directio",
        "dont_measure obj_type=var_log_t subj_user=system_u",
        "appraise func=SETXATTR_CHECK appraise_algos=sha256",
    ] {
        round_trip(line);
    }
}

#[test]
fn a_rendered_rule_reads_as_policy_text() {
    let r = parse_rule("measure func=BPRM_CHECK mask=MAY_EXEC pcr=11").unwrap();
    let s = show_rule(&r);
    assert!(s.starts_with("measure func=BPRM_CHECK mask=MAY_EXEC"), "{s:?}");
    assert!(s.contains("pcr=11"), "{s:?}");
    assert!(s.ends_with('\n'));

    // The any-of form keeps the mark that distinguishes it from exact match.
    let r = parse_rule("measure func=FILE_CHECK mask=^MAY_READ").unwrap();
    assert!(show_rule(&r).contains("mask=^MAY_READ"));
}

#[test]
fn comparators_render_as_they_parsed() {
    assert!(show_rule(&parse_rule("measure func=FILE_CHECK uid>500").unwrap())
            .contains("uid>500"));
    assert!(show_rule(&parse_rule("measure func=FILE_CHECK uid<500").unwrap())
            .contains("uid<500"));
    assert!(show_rule(&parse_rule("measure func=FILE_CHECK uid=500").unwrap())
            .contains("uid=500"));
}

#[test]
fn uuids_render_hyphenated_and_lowercase() {
    let u = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33,
             0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
    assert_eq!(uuid_str(&u), "deadbeef-0011-2233-4455-66778899aabb");
}
