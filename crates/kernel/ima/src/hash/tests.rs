use super::*;

#[test]
fn ids_are_the_abi_numbering() {
    // The id byte is stored in security.ima digest-NG records; these values
    // are the integrity ABI's, not this enum's declaration convenience.
    assert_eq!(HashAlgo::Md4.id(), 0);
    assert_eq!(HashAlgo::Md5.id(), 1);
    assert_eq!(HashAlgo::Sha1.id(), 2);
    assert_eq!(HashAlgo::Sha256.id(), 4);
    assert_eq!(HashAlgo::Sha384.id(), 5);
    assert_eq!(HashAlgo::Sha512.id(), 6);
    assert_eq!(HashAlgo::Sha224.id(), 7);
    assert_eq!(HashAlgo::Sm3_256.id(), 17);
    assert_eq!(HashAlgo::Sha3_512.id(), 22);
    assert_eq!(HASH_ALGO_LAST, 23);
}

#[test]
fn from_id_rejects_out_of_range() {
    assert_eq!(HashAlgo::from_id(2), Some(HashAlgo::Sha1));
    assert_eq!(HashAlgo::from_id(22), Some(HashAlgo::Sha3_512));
    assert_eq!(HashAlgo::from_id(23), None);
    assert_eq!(HashAlgo::from_id(255), None);
}

#[test]
fn names_and_sizes() {
    assert_eq!(HashAlgo::Sha1.name(), "sha1");
    assert_eq!(HashAlgo::RipeMd160.name(), "rmd160");
    assert_eq!(HashAlgo::Sm3_256.name(), "sm3");
    assert_eq!(HashAlgo::Sha3_256.name(), "sha3-256");
    assert_eq!(HashAlgo::Sha1.size(), 20);
    assert_eq!(HashAlgo::Sha256.size(), 32);
    assert_eq!(HashAlgo::Sha512.size(), 64);
    assert_eq!(HashAlgo::Sha224.size(), 28);
    assert_eq!(HashAlgo::RipeMd320.size(), 40);
    assert_eq!(HashAlgo::Tgr192.size(), 24);
    assert_eq!(HashAlgo::by_name("sha256"), Some(HashAlgo::Sha256));
    assert_eq!(HashAlgo::by_name("nosuch"), None);
}

#[test]
fn unimplemented_algorithms_have_no_engine() {
    assert!(HashAlgo::Sha256.engine().is_some());
    assert!(HashAlgo::Md5.engine().is_none());
    assert!(HashAlgo::Sm3_256.engine().is_none());
    assert!(HashAlgo::Sm3_256.digest(&[b"x"]).is_none());
}

#[test]
fn hex_is_lowercase_two_digits_per_byte() {
    assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    assert_eq!(hex(&[]), "");
}

#[test]
fn sha1_of_empty_matches_published_vector() {
    assert_eq!(hex(&HashAlgo::Sha1.digest(&[b""]).unwrap()),
               "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}
