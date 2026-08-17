//! The dummy policy's spellings, its conflict rule, and where encryption
//! happens.

use syscall::errno::Errno;

use crate::opts::crypt::{self, DummyPolicy, PolicyVersion, MODE_AES_256_CTS, MODE_AES_256_XTS};
use crate::opts::{parse, show, Options};

fn p(s: &str) -> Result<Options, Errno> { parse(&Options::defaults(), s) }

#[test]
fn a_bare_request_asks_for_the_current_generation() {
    let got = crypt::parse_dummy_ungated(None, None).unwrap();
    assert_eq!(got.version, PolicyVersion::V2);
}

#[test]
fn both_generations_can_be_named() {
    assert_eq!(crypt::parse_dummy_ungated(None, Some("v1")).unwrap().version, PolicyVersion::V1);
    assert_eq!(crypt::parse_dummy_ungated(None, Some("v2")).unwrap().version, PolicyVersion::V2);
}

#[test]
fn a_generation_that_does_not_exist_is_refused() {
    for arg in ["v0", "v3", "", "1", "V1"] {
        assert_eq!(crypt::parse_dummy_ungated(None, Some(arg)), Err(Errno::Einval), "{arg}");
    }
}

#[test]
fn the_policy_names_the_modes_the_dummy_key_is_used_with() {
    let got = crypt::parse_dummy_ungated(None, Some("v1")).unwrap();
    assert_eq!(got.contents_mode, MODE_AES_256_XTS);
    assert_eq!(got.filenames_mode, MODE_AES_256_CTS);
}

#[test]
fn asking_twice_for_the_same_policy_is_not_a_conflict() {
    let first = crypt::parse_dummy_ungated(None, Some("v2")).unwrap();
    assert_eq!(crypt::parse_dummy_ungated(Some(first), Some("v2")), Ok(first));
    assert_eq!(crypt::parse_dummy_ungated(Some(first), None), Ok(first));
}

#[test]
fn asking_for_two_different_policies_is_refused() {
    // Only one of them can be what the files get, and picking either silently
    // would encrypt a volume under a policy half the line did not ask for.
    let v1 = crypt::parse_dummy_ungated(None, Some("v1")).unwrap();
    assert_eq!(crypt::parse_dummy_ungated(Some(v1), Some("v2")), Err(Errno::Einval));
}

#[test]
fn a_build_that_cannot_encrypt_refuses_the_option_rather_than_dropping_it() {
    // The whole point of the option is that the files it creates are
    // ciphertext. A mount that silently gave plaintext would hand a test a
    // pass it did not earn.
    assert!(!crypt::ENCRYPTION, "flip this test's expectation with the const");
    assert_eq!(crypt::parse_dummy(None, Some("v2")), Err(Errno::Einval));
    assert_eq!(p("test_dummy_encryption"), Err(Errno::Einval));
    assert_eq!(p("test_dummy_encryption=v1"), Err(Errno::Einval));
}

#[test]
fn asking_where_encryption_happens_is_never_an_error() {
    // Unlike the policy, this moves only WHERE the same ciphertext is
    // produced, so a build that cannot do it in the block layer does it in the
    // filesystem and the caller still gets what it asked for.
    let o = p("inlinecrypt").unwrap();
    assert_eq!(o.inlinecrypt, crypt::INLINE_CRYPT);
    assert_eq!(p("inlinecrypt=yes"), Err(Errno::Einval));
}

#[test]
fn a_policy_round_trips_through_the_line_it_is_rendered_as() {
    for v in [PolicyVersion::V1, PolicyVersion::V2] {
        let mut o = Options::defaults();
        o.dummy_policy = Some(DummyPolicy {
            version: v,
            contents_mode: MODE_AES_256_XTS,
            filenames_mode: MODE_AES_256_CTS,
        });
        let line = show(&o, 0);
        assert!(line.contains("test_dummy_encryption="), "{line}");
        // The rendering names the generation explicitly, so a remount cannot
        // land on a different one because the default moved.
        let spelling = match v { PolicyVersion::V1 => "=v1", PolicyVersion::V2 => "=v2" };
        assert!(line.contains(spelling), "{line}");
    }
}
