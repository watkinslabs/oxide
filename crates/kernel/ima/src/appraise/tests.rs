// The rule this file exists to hold: an unsigned or unlabelled file does not
// appraise as a pass in enforcing mode. Everything else here is a way that
// could be got wrong.

use alloc::vec;
use alloc::vec::Vec;

use crate::appraise::*;
use crate::flags::*;
use crate::hash::HashAlgo;
use crate::uapi::{Hook, SigV2Hdr, Status, XattrType};

fn digest() -> Vec<u8> { (0u8..32).collect() }
fn other_digest() -> Vec<u8> { (100u8..132).collect() }

/// Accepts every signature. Used to show that a rejection came from the ladder
/// and not from the cryptography being unavailable.
struct AlwaysOk;
impl Verifier for AlwaysOk {
    fn verify(&self, _r: Keyring, _s: &[u8], _d: &[u8], _a: HashAlgo) -> VerifyResult {
        VerifyResult::Ok
    }
    fn verify_modsig(&self, _r: Keyring, _m: &[u8]) -> VerifyResult { VerifyResult::Ok }
}

/// Rejects every signature.
struct AlwaysBad;
impl Verifier for AlwaysBad {
    fn verify(&self, _r: Keyring, _s: &[u8], _d: &[u8], _a: HashAlgo) -> VerifyResult {
        VerifyResult::Invalid
    }
    fn verify_modsig(&self, _r: Keyring, _m: &[u8]) -> VerifyResult { VerifyResult::Invalid }
}

/// Verifies only a signature whose payload equals the digest it is given —
/// the property a real verifier provides, expressed without keys.
struct DigestBound;
impl Verifier for DigestBound {
    fn verify(&self, _r: Keyring, s: &[u8], d: &[u8], _a: HashAlgo) -> VerifyResult {
        if s.len() > 9 && &s[9..] == d { VerifyResult::Ok } else { VerifyResult::Invalid }
    }
}

struct NoKeyThenModsig;
impl Verifier for NoKeyThenModsig {
    fn verify(&self, _r: Keyring, _s: &[u8], _d: &[u8], _a: HashAlgo) -> VerifyResult {
        VerifyResult::NoKey
    }
    fn verify_modsig(&self, _r: Keyring, _m: &[u8]) -> VerifyResult { VerifyResult::Ok }
}

fn digest_label(algo: HashAlgo, d: &[u8]) -> Vec<u8> {
    let mut v = vec![XattrType::ImaDigestNg.tag(), algo.id()];
    v.extend_from_slice(d);
    v
}

fn legacy_label(d: &[u8]) -> Vec<u8> {
    let mut v = vec![XattrType::ImaDigest.tag()];
    v.extend_from_slice(d);
    v
}

fn signature(ty: XattrType, version: u8, algo: HashAlgo, payload: &[u8]) -> Vec<u8> {
    let hdr = SigV2Hdr {
        xattr_type: ty, version, hash_algo: algo.id(), keyid: 0xdeadbeef,
        sig_size: payload.len() as u16,
    };
    let mut v = hdr.encode().to_vec();
    v.extend_from_slice(payload);
    v
}

// --- the headline rule ---------------------------------------------------

#[test]
fn an_unlabelled_file_does_not_pass_in_enforcing_mode() {
    let d = digest();
    let a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    let o = appraise(&a, &AlwaysOk);
    assert_eq!(o.status, Status::NoLabel);
    assert_eq!(o.cause, "missing-hash");
    assert!(!permits_access(IMA_APPRAISE_ENFORCE, &o), "an unlabelled file must be denied");
}

#[test]
fn an_unsigned_file_does_not_pass_a_rule_that_requires_a_signature() {
    let d = digest();
    // A correct bare digest is not a signature.
    let label = digest_label(HashAlgo::Sha256, &d);
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&label);
    a.flags = IMA_DIGSIG_REQUIRED;
    let o = appraise(&a, &AlwaysOk);
    assert_eq!(o.status, Status::Fail);
    assert_eq!(o.cause, "IMA-signature-required");
    assert!(!permits_access(IMA_APPRAISE_ENFORCE, &o));

    // Without the requirement the same label passes, so the refusal above is
    // the requirement doing its job rather than the label being unreadable.
    a.flags = 0;
    assert_eq!(appraise(&a, &AlwaysOk).status, Status::Pass);
}

#[test]
fn a_label_whose_digest_is_not_the_files_digest_fails() {
    let d = digest();
    let label = digest_label(HashAlgo::Sha256, &other_digest());
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&label);
    let o = appraise(&a, &AlwaysOk);
    assert_eq!((o.status, o.cause), (Status::Fail, "invalid-hash"));
    assert!(!permits_access(IMA_APPRAISE_ENFORCE, &o));
}

#[test]
fn a_signature_over_another_digest_fails() {
    // The signature is well formed and its key is known; it just does not
    // cover this file's contents.
    let d = digest();
    let sig = signature(XattrType::EvmImaDigsig, 2, HashAlgo::Sha256, &other_digest());
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&sig);
    a.flags = IMA_DIGSIG_REQUIRED;
    let o = appraise(&a, &DigestBound);
    assert_eq!((o.status, o.cause), (Status::Fail, "invalid-signature"));
    assert!(!permits_access(IMA_APPRAISE_ENFORCE, &o));

    // The same appraisal with a signature over the right digest passes.
    let sig = signature(XattrType::EvmImaDigsig, 2, HashAlgo::Sha256, &d);
    a.xattr = Some(&sig);
    assert_eq!(appraise(&a, &DigestBound).status, Status::Pass);
}

#[test]
fn a_truncated_label_fails_rather_than_matching_a_prefix() {
    let d = digest();
    let mut short = digest_label(HashAlgo::Sha256, &d);
    short.truncate(short.len() - 1);
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&short);
    assert_eq!(appraise(&a, &AlwaysOk).status, Status::Fail);
}

// --- the ladder ----------------------------------------------------------

#[test]
fn a_matching_bare_digest_passes_when_no_signature_is_required() {
    let d = digest();
    let label = digest_label(HashAlgo::Sha256, &d);
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&label);
    let o = appraise(&a, &AlwaysBad);
    assert_eq!(o.status, Status::Pass);
    assert!(!o.digsig, "a bare digest is not a signature");
    assert!(permits_access(IMA_APPRAISE_ENFORCE, &o));
}

#[test]
fn the_legacy_digest_form_carries_no_algorithm_byte() {
    let d: Vec<u8> = (0u8..20).collect();
    let label = legacy_label(&d);
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha1, &d);
    a.xattr = Some(&label);
    assert_eq!(appraise(&a, &AlwaysBad).status, Status::Pass);
    assert_eq!(label.len(), 21);
    assert_eq!(xattr_hash_algo(Some(&label), HashAlgo::Sha256), HashAlgo::Sha1);
}

#[test]
fn a_label_names_the_algorithm_its_digest_is_in() {
    let d = digest();
    assert_eq!(xattr_hash_algo(Some(&digest_label(HashAlgo::Sha512, &d)), HashAlgo::Sha1),
               HashAlgo::Sha512);
    let sig = signature(XattrType::EvmImaDigsig, 2, HashAlgo::Sha384, &d);
    assert_eq!(xattr_hash_algo(Some(&sig), HashAlgo::Sha1), HashAlgo::Sha384);
    let sig = signature(XattrType::ImaVerityDigsig, 3, HashAlgo::Sha256, &d);
    assert_eq!(xattr_hash_algo(Some(&sig), HashAlgo::Sha1), HashAlgo::Sha256);
    // An absent or unreadable label falls back to the measurement algorithm
    // rather than to no algorithm at all.
    assert_eq!(xattr_hash_algo(None, HashAlgo::Sha256), HashAlgo::Sha256);
    assert_eq!(xattr_hash_algo(Some(&[XattrType::ImaDigestNg.tag()]), HashAlgo::Sha256),
               HashAlgo::Sha256);
    // A signature header naming an algorithm this build does not know falls
    // back too, instead of indexing past the table.
    let mut bad = signature(XattrType::EvmImaDigsig, 2, HashAlgo::Sha256, &d);
    bad[2] = 200;
    assert_eq!(xattr_hash_algo(Some(&bad), HashAlgo::Sha1), HashAlgo::Sha1);
}

#[test]
fn a_signature_version_beyond_the_defined_range_fails() {
    let d = digest();
    let sig = signature(XattrType::EvmImaDigsig, 4, HashAlgo::Sha256, &d);
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&sig);
    a.flags = IMA_DIGSIG_REQUIRED;
    let o = appraise(&a, &AlwaysOk);
    assert_eq!((o.status, o.cause), (Status::Fail, "invalid-signature-version"));
}

#[test]
fn a_rule_demanding_the_third_signature_version_refuses_the_second() {
    let d = digest();
    let sig = signature(XattrType::EvmImaDigsig, 2, HashAlgo::Sha256, &d);
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&sig);
    a.flags = IMA_DIGSIG_REQUIRED | IMA_SIGV3_REQUIRED;
    assert_eq!(appraise(&a, &AlwaysOk).cause, "IMA-sigv3-required");
    // Version three satisfies it.
    let sig = signature(XattrType::EvmImaDigsig, 3, HashAlgo::Sha256, &d);
    a.xattr = Some(&sig);
    assert_eq!(appraise(&a, &AlwaysOk).status, Status::Pass);
}

#[test]
fn a_verity_rule_requires_a_verity_signature_and_the_reverse() {
    let d = digest();
    // A file signature does not satisfy a rule that demands an fs-verity one.
    let sig = signature(XattrType::EvmImaDigsig, 3, HashAlgo::Sha256, &d);
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&sig);
    a.flags = IMA_DIGSIG_REQUIRED | IMA_VERITY_REQUIRED;
    assert_eq!(appraise(&a, &AlwaysOk).cause, "verity-signature-required");

    // And an fs-verity signature does not satisfy a plain signature rule.
    let vsig = signature(XattrType::ImaVerityDigsig, 3, HashAlgo::Sha256, &d);
    a.xattr = Some(&vsig);
    a.flags = IMA_DIGSIG_REQUIRED;
    assert_eq!(appraise(&a, &AlwaysOk).cause, "IMA-signature-required");

    // Matched up, it passes.
    a.flags = IMA_DIGSIG_REQUIRED | IMA_VERITY_REQUIRED;
    assert_eq!(appraise(&a, &AlwaysOk).status, Status::Pass);

    // An fs-verity signature is only ever version three.
    let old = signature(XattrType::ImaVerityDigsig, 2, HashAlgo::Sha256, &d);
    a.xattr = Some(&old);
    assert_eq!(appraise(&a, &AlwaysOk).cause, "invalid-signature-version");
}

#[test]
fn an_unrecognised_label_type_is_unknown_not_a_pass() {
    let d = digest();
    let label = vec![0x7f, 1, 2, 3];
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&label);
    let o = appraise(&a, &AlwaysOk);
    assert_eq!((o.status, o.cause), (Status::Unknown, "unknown-ima-data"));
    assert!(!permits_access(IMA_APPRAISE_ENFORCE, &o));
}

#[test]
fn a_broken_metadata_label_stops_the_appraisal_before_the_file_label_is_believed() {
    let d = digest();
    let label = digest_label(HashAlgo::Sha256, &d);
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&label);
    for (evm, cause) in [
        (Status::Fail, "invalid-HMAC"),
        (Status::NoLabel, "missing-HMAC"),
        (Status::NoXattrs, "missing-HMAC"),
        (Status::FailImmutable, "invalid-fail-immutable"),
    ] {
        a.evm_status = evm;
        let o = appraise(&a, &AlwaysOk);
        assert_eq!(o.cause, cause, "{evm:?}");
        assert!(!permits_access(IMA_APPRAISE_ENFORCE, &o), "{evm:?}");
    }
    // A metadata label that verifies, or that cannot be evaluated at all, lets
    // the file label be checked.
    for evm in [Status::Pass, Status::PassImmutable, Status::Unknown] {
        a.evm_status = evm;
        assert_eq!(appraise(&a, &AlwaysOk).status, Status::Pass, "{evm:?}");
    }
}

#[test]
fn a_new_empty_file_may_be_labelled_after_the_fact() {
    let d = digest();
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.created = true;
    a.size = 0;
    // A file just created with no contents and no label is permitted so the
    // label can be written on close.
    assert_eq!(appraise(&a, &AlwaysOk).status, Status::Pass);

    // With a signature required and contents already present, it is not.
    a.flags = IMA_DIGSIG_REQUIRED;
    a.size = 100;
    let o = appraise(&a, &AlwaysOk);
    assert_eq!(o.status, Status::NoLabel);
    assert_eq!(o.cause, "IMA-signature-required");

    // Without a signature requirement, a newly created file is permitted even
    // with contents, because the label is written on close.
    a.flags = 0;
    assert_eq!(appraise(&a, &AlwaysOk).status, Status::Pass);
}

#[test]
fn an_appended_signature_is_tried_when_the_label_is_a_bare_digest() {
    let d = digest();
    let label = digest_label(HashAlgo::Sha256, &d);
    let modsig = vec![9u8; 64];
    let mut a = Appraisal::new(Hook::ModuleCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&label);
    a.modsig = Some(&modsig);
    a.flags = IMA_DIGSIG_REQUIRED | IMA_MODSIG_ALLOWED;
    // The bare digest cannot satisfy the signature requirement, but the
    // appended signature can.
    assert_eq!(appraise(&a, &AlwaysOk).status, Status::Pass);
    // If it does not verify, the appraisal fails.
    let o = appraise(&a, &AlwaysBad);
    assert_eq!((o.status, o.cause), (Status::Fail, "invalid-signature"));
}

#[test]
fn an_appended_signature_is_tried_when_no_key_verifies_the_label() {
    let d = digest();
    let sig = signature(XattrType::EvmImaDigsig, 2, HashAlgo::Sha256, &d);
    let modsig = vec![9u8; 64];
    let mut a = Appraisal::new(Hook::ModuleCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&sig);
    a.modsig = Some(&modsig);
    a.flags = IMA_DIGSIG_REQUIRED | IMA_MODSIG_ALLOWED;
    assert_eq!(appraise(&a, &NoKeyThenModsig).status, Status::Pass);
}

#[test]
fn a_file_with_no_label_and_no_appended_signature_on_a_bare_filesystem_is_unknown() {
    let d = digest();
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.no_xattr_support = true;
    let o = appraise(&a, &AlwaysOk);
    assert_eq!(o.status, Status::Unknown);
    assert!(!permits_access(IMA_APPRAISE_ENFORCE, &o));
}

#[test]
fn an_unverifiable_filesystem_fails_when_the_mounter_is_untrusted() {
    let d = digest();
    let sig = signature(XattrType::EvmImaDigsig, 2, HashAlgo::Sha256, &d);
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&sig);
    a.flags = IMA_DIGSIG_REQUIRED;
    a.unverifiable_sigs_fs = true;
    // Trusted mounter, no fail-securely: the signature stands.
    assert_eq!(appraise(&a, &AlwaysOk).status, Status::Pass);
    // Untrusted mounter: it does not.
    a.untrusted_mounter = true;
    let o = appraise(&a, &AlwaysOk);
    assert_eq!((o.status, o.cause), (Status::Fail, "unverifiable-signature"));
    // Or with fail-securely asked for at boot.
    a.untrusted_mounter = false;
    a.flags |= IMA_FAIL_UNVERIFIABLE_SIGS;
    assert_eq!(appraise(&a, &AlwaysOk).status, Status::Fail);
}

// --- modes ---------------------------------------------------------------

#[test]
fn fix_mode_relabels_a_mismatched_file_but_enforce_mode_does_not() {
    let d = digest();
    let label = digest_label(HashAlgo::Sha256, &other_digest());
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&label);

    let o = appraise(&a, &AlwaysOk);
    assert!(!o.would_fix);
    assert_eq!(o.status, Status::Fail);

    a.mode = IMA_APPRAISE_FIX;
    let o = appraise(&a, &AlwaysOk);
    assert!(o.would_fix);
    assert_eq!(o.status, Status::Pass);
}

#[test]
fn fix_mode_never_rewrites_a_signature() {
    let d = digest();
    let sig = signature(XattrType::EvmImaDigsig, 2, HashAlgo::Sha256, &other_digest());
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&sig);
    a.flags = IMA_DIGSIG_REQUIRED;
    a.mode = IMA_APPRAISE_FIX;
    let o = appraise(&a, &AlwaysBad);
    assert!(!o.would_fix, "a signature must never be replaced by a digest");
    assert_eq!(o.status, Status::Fail);
}

#[test]
fn log_mode_reports_the_failure_but_permits_the_access() {
    let d = digest();
    let label = digest_label(HashAlgo::Sha256, &other_digest());
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&label);
    a.mode = IMA_APPRAISE_LOG;
    let o = appraise(&a, &AlwaysOk);
    assert_eq!(o.status, Status::Fail);
    assert!(permits_access(IMA_APPRAISE_LOG, &o));
    // Only the enforcing mode denies.
    assert!(!permits_access(IMA_APPRAISE_ENFORCE, &o));
}

// --- surrounding decisions ----------------------------------------------

#[test]
fn writing_a_signed_file_is_refused_unless_it_was_just_created() {
    assert!(!permits_write(MAY_WRITE, true, false));
    assert!(permits_write(MAY_WRITE, true, true));
    assert!(permits_write(MAY_WRITE, false, false));
    assert!(permits_write(MAY_READ, true, false));
}

#[test]
fn a_digest_outside_the_rules_allowlist_is_refused() {
    let bits = 1u32 << HashAlgo::Sha256.id();
    assert!(algo_allowed(Some(bits), HashAlgo::Sha256));
    assert!(!algo_allowed(Some(bits), HashAlgo::Sha1));
    // No allowlist means the rule named none.
    assert!(algo_allowed(None, HashAlgo::Sha1));
    assert!(algo_allowed(Some(0), HashAlgo::Sha1));
}

#[test]
fn the_written_label_carries_the_algorithm_for_the_modern_form() {
    let d = digest();
    let v = build_xattr(HashAlgo::Sha256, &d);
    assert_eq!(v[0], XattrType::ImaDigestNg.tag());
    assert_eq!(v[1], HashAlgo::Sha256.id());
    assert_eq!(&v[2..], &d[..]);
    // The legacy form predates the algorithm byte.
    let d1: Vec<u8> = (0u8..20).collect();
    let v = build_xattr(HashAlgo::Sha1, &d1);
    assert_eq!(v[0], XattrType::ImaDigest.tag());
    assert_eq!(&v[1..], &d1[..]);
    // And what is written reads back as a pass.
    let mut a = Appraisal::new(Hook::FileCheck, HashAlgo::Sha256, &d);
    let written = build_xattr(HashAlgo::Sha256, &d);
    a.xattr = Some(&written);
    assert_eq!(appraise(&a, &AlwaysBad).status, Status::Pass);
}

#[test]
fn each_hook_contributes_its_own_appraisal_mode_bit() {
    assert_eq!(appraise_flag(Hook::ModuleCheck), IMA_APPRAISE_MODULES);
    assert_eq!(appraise_flag(Hook::FirmwareCheck), IMA_APPRAISE_FIRMWARE);
    assert_eq!(appraise_flag(Hook::PolicyCheck), IMA_APPRAISE_POLICY);
    assert_eq!(appraise_flag(Hook::KexecKernelCheck), IMA_APPRAISE_KEXEC);
    assert_eq!(appraise_flag(Hook::FileCheck), 0);
}

#[test]
fn a_kernel_image_may_fall_back_to_the_platform_keyring() {
    // Signatures on a kernel being loaded for kexec are also checked against
    // the platform's own keys; other hooks are not.
    struct PlatformOnly;
    impl Verifier for PlatformOnly {
        fn verify(&self, r: Keyring, _s: &[u8], _d: &[u8], _a: HashAlgo) -> VerifyResult {
            if r == Keyring::Platform { VerifyResult::Ok } else { VerifyResult::Invalid }
        }
    }
    let d = digest();
    let sig = signature(XattrType::EvmImaDigsig, 2, HashAlgo::Sha256, &d);
    let mut a = Appraisal::new(Hook::KexecKernelCheck, HashAlgo::Sha256, &d);
    a.xattr = Some(&sig);
    a.flags = IMA_DIGSIG_REQUIRED;
    assert_eq!(appraise(&a, &PlatformOnly).status, Status::Pass);

    a.func = Hook::FileCheck;
    assert_eq!(appraise(&a, &PlatformOnly).status, Status::Fail);
}
