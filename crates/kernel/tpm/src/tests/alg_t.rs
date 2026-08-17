// Algorithm identity: wire numbers and the widths every other module sizes
// its buffers from.

use crate::alg::Alg;
use crate::uapi::{TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512, TPM_ALG_SM3_256};

#[test]
fn identifiers_and_widths() {
    for (a, id, n) in [
        (Alg::Sha1, TPM_ALG_SHA1, 20usize),
        (Alg::Sha256, TPM_ALG_SHA256, 32),
        (Alg::Sha384, TPM_ALG_SHA384, 48),
        (Alg::Sha512, TPM_ALG_SHA512, 64),
        (Alg::Sm3, TPM_ALG_SM3_256, 32),
    ] {
        assert_eq!(a.id(), id);
        assert_eq!(a.digest_size(), n);
        assert_eq!(Alg::from_id(id), Some(a));
        assert_eq!(Alg::digest_size_of(id), Some(n));
    }
}

#[test]
fn an_unknown_identifier_is_absent_not_substituted() {
    for id in [0x0000u16, 0x0006, 0x0008, 0x0010, 0x0023, 0xFFFF] {
        assert_eq!(Alg::from_id(id), None, "0x{id:04X} must not resolve");
        assert_eq!(Alg::digest_size_of(id), None);
    }
}

#[test]
fn an_algorithm_without_an_implementation_reports_it() {
    assert!(Alg::Sm3.digest_impl().is_none());
    assert!(Alg::Sm3.hash(&[b"x"]).is_none());
    assert!(Alg::Sha256.hash(&[b"x"]).is_some());
}
