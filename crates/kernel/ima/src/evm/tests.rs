use alloc::vec;
use alloc::vec::Vec;

use crate::appraise::VerifyResult;
use crate::evm::*;
use crate::flags::EVM_ATTR_FSUUID;
use crate::hash::{hex, HashAlgo};
use crate::uapi::{SigV2Hdr, Status, XattrType, XATTR_NAME_CAPS, XATTR_NAME_EVM, XATTR_NAME_IMA,
                  XATTR_NAME_SELINUX};

fn attrs() -> InodeAttrs {
    InodeAttrs {
        ino: 0x1122334455667788, generation: 0xaabbccdd, uid: 1000, gid: 100, mode: 0o100644,
        fsuuid: [0x11; 16],
    }
}

fn store<'a>(pairs: &'a [(&'a str, &'a [u8])]) -> impl FnMut(&str) -> Option<Vec<u8>> + 'a {
    move |n: &str| pairs.iter().find(|(k, _)| *k == n).map(|(_, v)| v.to_vec())
}

// --- the keyed hash ------------------------------------------------------

#[test]
fn the_keyed_hash_matches_a_published_vector() {
    // Published HMAC-SHA-1 test vector: a twenty-byte key of 0x0b over
    // "Hi There".
    let key = [0x0bu8; 20];
    let got = hmac(HashAlgo::Sha1, &key, b"Hi There").unwrap();
    assert_eq!(hex(&got), "b617318655057264e28bc0b6fb378c8ef146be00");
}

#[test]
fn the_keyed_hash_handles_a_key_longer_than_the_block() {
    // Published vector: an eighty-byte key of 0xaa over the long message.
    let key = [0xaau8; 80];
    let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let got = hmac(HashAlgo::Sha1, &key, msg).unwrap();
    assert_eq!(hex(&got), "aa4ae5e15272d00e95705637ce8a3b55ed402112");
}

#[test]
fn no_engine_means_no_keyed_hash_rather_than_a_substitute() {
    assert!(hmac(HashAlgo::Sm3_256, b"k", b"m").is_none());
}

// --- what the label covers -----------------------------------------------

#[test]
fn the_protected_set_is_exactly_these_names_in_this_order() {
    assert_eq!(PROTECTED.iter().map(|p| p.name).collect::<Vec<_>>(), vec![
        "security.selinux", "security.SMACK64", "security.SMACK64EXEC",
        "security.SMACK64TRANSMUTE", "security.SMACK64MMAP", "security.apparmor",
        "security.ima", "security.capability",
    ]);
    assert!(protected_xattr(XATTR_NAME_IMA));
    assert!(protected_xattr(XATTR_NAME_CAPS));
    assert!(protected_xattr(XATTR_NAME_SELINUX));
    assert!(!protected_xattr(XATTR_NAME_EVM), "the label does not cover itself");
    assert!(!protected_xattr("user.whatever"));
    // A portable label spans the whole set whatever this build enabled.
    assert!(protected_xattr_any("security.apparmor"));
    assert!(!protected_xattr("security.apparmor"));
    assert!(posix_acl_xattr("system.posix_acl_access"));
    assert!(!posix_acl_xattr("system.something"));
}

#[test]
fn the_metadata_block_is_a_fixed_twenty_four_byte_image() {
    let a = attrs();
    let b = misc_block(&a, XattrType::EvmHmac);
    assert_eq!(MISC_LEN, 24);
    assert_eq!(&b[0..8], &a.ino.to_le_bytes());
    assert_eq!(&b[8..12], &a.generation.to_le_bytes());
    assert_eq!(&b[12..16], &1000u32.to_le_bytes());
    assert_eq!(&b[16..20], &100u32.to_le_bytes());
    assert_eq!(&b[20..22], &0o100644u16.to_le_bytes());
    // The block ends with the pad that carries it to its alignment; it is
    // hashed, so it must be zero rather than whatever was on the stack.
    assert_eq!(&b[22..24], &[0, 0]);
}

#[test]
fn a_portable_label_omits_the_inode_identity() {
    let a = attrs();
    let b = misc_block(&a, XattrType::EvmPortableDigsig);
    assert_eq!(&b[0..12], &[0u8; 12], "a portable label must not bind one inode");
    // Ownership and mode are still covered.
    assert_eq!(&b[12..16], &1000u32.to_le_bytes());
    assert_eq!(&b[20..22], &0o100644u16.to_le_bytes());
}

#[test]
fn the_label_input_is_the_values_in_set_order_then_the_metadata() {
    let a = attrs();
    let pairs: &[(&str, &[u8])] = &[(XATTR_NAME_IMA, b"IMA"), (XATTR_NAME_SELINUX, b"SEL"),
                                    (XATTR_NAME_CAPS, b"CAP")];
    let input = label_input(XattrType::EvmHmac, &a, 0, store(pairs)).unwrap();
    let mut want: Vec<u8> = Vec::new();
    // Set order, not the order the caller happened to list them in.
    want.extend_from_slice(b"SEL");
    want.extend_from_slice(b"IMA");
    want.extend_from_slice(b"CAP");
    want.extend_from_slice(&misc_block(&a, XattrType::EvmHmac));
    assert_eq!(input, want);
}

#[test]
fn the_filesystem_identifier_is_appended_only_when_configured_and_not_portable() {
    let a = attrs();
    let pairs: &[(&str, &[u8])] = &[(XATTR_NAME_IMA, b"IMA")];
    let plain = label_input(XattrType::EvmHmac, &a, 0, store(pairs)).unwrap();
    let with_uuid = label_input(XattrType::EvmHmac, &a, EVM_ATTR_FSUUID, store(pairs)).unwrap();
    assert_eq!(with_uuid.len(), plain.len() + 16);
    assert_eq!(&with_uuid[plain.len()..], &[0x11u8; 16]);
    // A portable label must verify on another filesystem, so it never covers
    // this one's identifier.
    let portable = label_input(XattrType::EvmPortableDigsig, &a, EVM_ATTR_FSUUID, store(pairs))
        .unwrap();
    assert_eq!(portable.len(), MISC_LEN + 3);
}

#[test]
fn an_inode_with_no_protected_attributes_has_no_label_input() {
    let a = attrs();
    assert!(label_input(XattrType::EvmHmac, &a, 0, store(&[])).is_none());
}

#[test]
fn a_portable_label_must_cover_a_file_digest() {
    let a = attrs();
    let no_ima: &[(&str, &[u8])] = &[(XATTR_NAME_SELINUX, b"SEL")];
    assert!(label_input(XattrType::EvmPortableDigsig, &a, 0, store(no_ima)).is_none(),
            "a portable label over metadata alone could be moved onto other contents");
    let with_ima: &[(&str, &[u8])] = &[(XATTR_NAME_SELINUX, b"SEL"), (XATTR_NAME_IMA, b"IMA")];
    assert!(label_input(XattrType::EvmPortableDigsig, &a, 0, store(with_ima)).is_some());
}

#[test]
fn a_portable_label_also_covers_attributes_this_build_does_not_enable() {
    let a = attrs();
    let pairs: &[(&str, &[u8])] = &[(XATTR_NAME_IMA, b"IMA"), ("security.apparmor", b"AA")];
    let local = label_input(XattrType::EvmHmac, &a, 0, store(pairs)).unwrap();
    let portable = label_input(XattrType::EvmPortableDigsig, &a, 0, store(pairs)).unwrap();
    assert_eq!(local.len(), 3 + MISC_LEN);
    assert_eq!(portable.len(), 2 + 3 + MISC_LEN);
}

#[test]
fn changing_any_covered_field_changes_the_label() {
    let key = b"a key that is long enough";
    let pairs: &[(&str, &[u8])] = &[(XATTR_NAME_IMA, b"IMA")];
    let base = calc_hmac(key, &attrs(), 0, store(pairs)).unwrap();
    for mutate in [
        |a: &mut InodeAttrs| a.ino += 1,
        |a: &mut InodeAttrs| a.generation += 1,
        |a: &mut InodeAttrs| a.uid += 1,
        |a: &mut InodeAttrs| a.gid += 1,
        |a: &mut InodeAttrs| a.mode ^= 0o200,
    ] {
        let mut a = attrs();
        mutate(&mut a);
        assert_ne!(calc_hmac(key, &a, 0, store(pairs)).unwrap(), base);
    }
    // And so does changing a covered attribute's value.
    let other: &[(&str, &[u8])] = &[(XATTR_NAME_IMA, b"OTHER")];
    assert_ne!(calc_hmac(key, &attrs(), 0, store(other)).unwrap(), base);
    assert_eq!(count_protected(store(pairs)), 1);
}

#[test]
fn a_stored_label_is_the_type_tag_then_the_keyed_hash() {
    let key = b"a key that is long enough";
    let pairs: &[(&str, &[u8])] = &[(XATTR_NAME_IMA, b"IMA")];
    let d = calc_hmac(key, &attrs(), 0, store(pairs)).unwrap();
    let v = encode_hmac_xattr(&d);
    assert_eq!(v[0], XattrType::EvmHmac.tag());
    assert_eq!(v.len(), EVM_HMAC_XATTR_LEN);
    assert_eq!(&v[1..], &d[..]);
}

#[test]
fn a_signed_label_covers_a_plain_digest_of_the_same_input() {
    let a = attrs();
    let pairs: &[(&str, &[u8])] = &[(XATTR_NAME_IMA, b"IMA")];
    let input = label_input(XattrType::EvmPortableDigsig, &a, 0, store(pairs)).unwrap();
    let got = calc_hash(XattrType::EvmPortableDigsig, HashAlgo::Sha256, &a, 0, store(pairs))
        .unwrap();
    assert_eq!(got, HashAlgo::Sha256.digest(&[&input]).unwrap());
}

// --- the status ladder ---------------------------------------------------

struct Ops {
    digest: Vec<u8>,
    sig_ok: bool,
}

impl LabelOps for Ops {
    fn compute(&mut self, _t: XattrType, _a: HashAlgo) -> Option<Vec<u8>> {
        Some(self.digest.clone())
    }
    fn verify_sig(&mut self, _s: &[u8], _d: &[u8], _a: HashAlgo) -> VerifyResult {
        if self.sig_ok { VerifyResult::Ok } else { VerifyResult::Invalid }
    }
}

fn ops(d: Vec<u8>, ok: bool) -> Ops { Ops { digest: d, sig_ok: ok } }

#[test]
fn a_matching_keyed_label_passes_and_a_mismatched_one_fails() {
    let d: Vec<u8> = (0u8..20).collect();
    let label = encode_hmac_xattr(&d);
    assert_eq!(verify_label(Some(&label), false, 1, false, &mut ops(d.clone(), false)),
               Status::Pass);
    let wrong: Vec<u8> = (1u8..21).collect();
    assert_eq!(verify_label(Some(&label), false, 1, false, &mut ops(wrong, false)),
               Status::Fail);
}

#[test]
fn a_keyed_label_of_the_wrong_length_fails_rather_than_matching_a_prefix() {
    let d: Vec<u8> = (0u8..20).collect();
    let mut label = encode_hmac_xattr(&d);
    label.push(0);
    assert_eq!(verify_label(Some(&label), false, 1, false, &mut ops(d, false)), Status::Fail);
}

#[test]
fn a_missing_label_is_distinguished_from_a_file_that_needs_none() {
    let d: Vec<u8> = (0u8..20).collect();
    // Protected attributes present but no label: the label was removed.
    assert_eq!(verify_label(None, false, 2, false, &mut ops(d.clone(), true)), Status::NoLabel);
    // Nothing protected at all: a new file, not a tampered one.
    assert_eq!(verify_label(None, false, 0, false, &mut ops(d.clone(), true)), Status::NoXattrs);
    // A filesystem that cannot store labels cannot be judged.
    assert_eq!(verify_label(None, true, 0, false, &mut ops(d, true)), Status::Unknown);
}

#[test]
fn a_portable_signature_that_verifies_is_immutable_and_one_that_does_not_fails_immutably() {
    let d: Vec<u8> = (0u8..32).collect();
    let hdr = SigV2Hdr { xattr_type: XattrType::EvmPortableDigsig, version: 3,
                         hash_algo: HashAlgo::Sha256.id(), keyid: 1, sig_size: 4 };
    let mut label = hdr.encode().to_vec();
    label.extend_from_slice(&[1, 2, 3, 4]);
    assert_eq!(verify_label(Some(&label), false, 1, false, &mut ops(d.clone(), true)),
               Status::PassImmutable);
    assert_eq!(verify_label(Some(&label), false, 1, false, &mut ops(d.clone(), false)),
               Status::FailImmutable);

    // A non-portable signature passes and fails mutably.
    let hdr = SigV2Hdr { xattr_type: XattrType::EvmImaDigsig, ..hdr };
    let mut label = hdr.encode().to_vec();
    label.extend_from_slice(&[1, 2, 3, 4]);
    assert_eq!(verify_label(Some(&label), false, 1, false, &mut ops(d.clone(), true)),
               Status::Pass);
    assert_eq!(verify_label(Some(&label), false, 1, false, &mut ops(d, false)), Status::Fail);
}

#[test]
fn a_signature_header_with_no_signature_after_it_fails() {
    let d: Vec<u8> = (0u8..32).collect();
    let hdr = SigV2Hdr { xattr_type: XattrType::EvmImaDigsig, version: 2,
                         hash_algo: HashAlgo::Sha256.id(), keyid: 1, sig_size: 0 };
    assert_eq!(verify_label(Some(&hdr.encode()), false, 1, false, &mut ops(d, true)),
               Status::Fail);
}

#[test]
fn a_third_version_requirement_refuses_an_older_signature() {
    let d: Vec<u8> = (0u8..32).collect();
    let hdr = SigV2Hdr { xattr_type: XattrType::EvmPortableDigsig, version: 2,
                         hash_algo: HashAlgo::Sha256.id(), keyid: 1, sig_size: 4 };
    let mut label = hdr.encode().to_vec();
    label.extend_from_slice(&[1, 2, 3, 4]);
    assert_eq!(verify_label(Some(&label), false, 1, true, &mut ops(d.clone(), true)),
               Status::Fail);
    assert_eq!(verify_label(Some(&label), false, 1, false, &mut ops(d, true)),
               Status::PassImmutable);
}

#[test]
fn an_unknown_or_empty_label_fails() {
    let d: Vec<u8> = (0u8..20).collect();
    assert_eq!(verify_label(Some(&[]), false, 1, false, &mut ops(d.clone(), true)), Status::Fail);
    assert_eq!(verify_label(Some(&[0x7f, 1, 2]), false, 1, false, &mut ops(d, true)),
               Status::Fail);
}

// --- mediating attribute writes -----------------------------------------

fn ctx(status: Status) -> ProtectCtx {
    ProtectCtx {
        privileged: true, unsupported_fs: false, hmac_disabled: false, new_file: false,
        pseudo_fs: false, status, value_changes: true,
    }
}

#[test]
fn only_an_administrator_may_write_the_label_itself() {
    let mut c = ctx(Status::Pass);
    assert_eq!(protect_xattr(XATTR_NAME_EVM, &c), XattrDecision::Allow);
    c.privileged = false;
    assert_eq!(protect_xattr(XATTR_NAME_EVM, &c), XattrDecision::DenyNotPrivileged);
}

#[test]
fn an_unprotected_attribute_is_unmediated() {
    let c = ctx(Status::Fail);
    assert_eq!(protect_xattr("user.comment", &c), XattrDecision::Allow);
    assert_eq!(protect_xattr("security.apparmor", &c), XattrDecision::Allow);
}

#[test]
fn a_protected_attribute_cannot_be_written_under_a_broken_label() {
    for bad in [Status::Fail, Status::NoLabel, Status::Unknown] {
        assert_eq!(protect_xattr(XATTR_NAME_IMA, &ctx(bad)), XattrDecision::DenyBadLabel,
                   "{bad:?}");
    }
    assert_eq!(protect_xattr(XATTR_NAME_IMA, &ctx(Status::Pass)), XattrDecision::Allow);
}

#[test]
fn an_access_control_list_is_mediated_because_it_changes_the_mode() {
    // The attribute itself is not protected, but writing it moves the mode,
    // which the label covers.
    assert_eq!(protect_xattr("system.posix_acl_access", &ctx(Status::Fail)),
               XattrDecision::DenyBadLabel);
    assert_eq!(protect_xattr("system.posix_acl_access", &ctx(Status::Pass)),
               XattrDecision::Allow);
    assert_eq!(protect_xattr("system.posix_acl_access", &ctx(Status::NoXattrs)),
               XattrDecision::Allow);
}

#[test]
fn a_file_that_has_no_label_yet_may_acquire_one() {
    let mut c = ctx(Status::NoXattrs);
    c.new_file = true;
    assert_eq!(protect_xattr(XATTR_NAME_IMA, &c), XattrDecision::Allow);
    c.new_file = false;
    c.pseudo_fs = true;
    assert_eq!(protect_xattr(XATTR_NAME_IMA, &c), XattrDecision::Allow);
    c.pseudo_fs = false;
    c.hmac_disabled = true;
    assert_eq!(protect_xattr(XATTR_NAME_IMA, &c), XattrDecision::Allow);
    // With none of those, an unlabelled file with attributes is refused.
    c.hmac_disabled = false;
    assert_eq!(protect_xattr(XATTR_NAME_IMA, &c), XattrDecision::DenyBadLabel);
}

#[test]
fn an_immutable_label_permits_only_a_write_that_changes_nothing() {
    let mut c = ctx(Status::PassImmutable);
    assert_eq!(protect_xattr(XATTR_NAME_IMA, &c), XattrDecision::DenyBadLabel);
    c.value_changes = false;
    assert_eq!(protect_xattr(XATTR_NAME_IMA, &c), XattrDecision::Allow);
    // A portable label that already fails can never be updated, so other
    // attributes moving under it changes nothing.
    assert_eq!(protect_xattr(XATTR_NAME_IMA, &ctx(Status::FailImmutable)), XattrDecision::Allow);
}

#[test]
fn a_filesystem_that_cannot_carry_a_label_mediates_nothing_except_the_label() {
    let mut c = ctx(Status::Fail);
    c.unsupported_fs = true;
    assert_eq!(protect_xattr(XATTR_NAME_IMA, &c), XattrDecision::Allow);
    assert_eq!(protect_xattr("system.posix_acl_access", &c), XattrDecision::Allow);
    assert_eq!(protect_xattr(XATTR_NAME_EVM, &c), XattrDecision::DenyNotPrivileged);
}
