use super::*;

#[test]
fn xattr_type_tags() {
    assert_eq!(XattrType::ImaDigest.tag(), 0x01);
    assert_eq!(XattrType::EvmHmac.tag(), 0x02);
    assert_eq!(XattrType::EvmImaDigsig.tag(), 0x03);
    assert_eq!(XattrType::ImaDigestNg.tag(), 0x04);
    assert_eq!(XattrType::EvmPortableDigsig.tag(), 0x05);
    assert_eq!(XattrType::ImaVerityDigsig.tag(), 0x06);
    assert_eq!(XattrType::from_tag(0x00), None);
    assert_eq!(XattrType::from_tag(XATTR_TYPE_LAST), None);
}

#[test]
fn status_order_and_names() {
    assert_eq!(Status::Pass as u8, 0);
    assert_eq!(Status::PassImmutable as u8, 1);
    assert_eq!(Status::Fail as u8, 2);
    assert_eq!(Status::FailImmutable as u8, 3);
    assert_eq!(Status::NoLabel as u8, 4);
    assert_eq!(Status::NoXattrs as u8, 5);
    assert_eq!(Status::Unknown as u8, 6);
    assert_eq!(Status::NoXattrs.as_str(), "no_xattrs");
}

#[test]
fn sig_v2_header_is_nine_bytes_big_endian() {
    // type | version | hash_algo | keyid(be32) | sig_size(be16)
    let raw = [0x03u8, 0x02, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x00];
    let h = SigV2Hdr::parse(&raw).unwrap();
    assert_eq!(h.xattr_type, XattrType::EvmImaDigsig);
    assert_eq!(h.version, 2);
    assert_eq!(h.hash_algo, crate::hash::HashAlgo::Sha256.id());
    assert_eq!(h.keyid, 0xdeadbeef);
    assert_eq!(h.sig_size, 256);
    assert_eq!(h.algo(), Some(crate::hash::HashAlgo::Sha256));
    assert_eq!(h.encode(), raw);
    assert_eq!(SIG_V2_HDR_LEN, 9);
}

#[test]
fn sig_v2_header_rejects_short_and_unknown_type() {
    assert!(SigV2Hdr::parse(&[0x03, 0x02, 0x04, 0, 0, 0, 0, 0]).is_none());
    assert!(SigV2Hdr::parse(&[0x7f, 0x02, 0x04, 0, 0, 0, 0, 0, 0]).is_none());
}

#[test]
fn hook_tokens_round_trip_and_accept_legacy_spellings() {
    for h in [Hook::FileCheck, Hook::MmapCheck, Hook::MmapCheckReqprot, Hook::BprmCheck,
              Hook::CredsCheck, Hook::ModuleCheck, Hook::FirmwareCheck, Hook::PolicyCheck,
              Hook::KexecKernelCheck, Hook::KexecInitramfsCheck, Hook::KexecCmdline,
              Hook::KeyCheck, Hook::CriticalData, Hook::SetxattrCheck] {
        assert_eq!(Hook::by_token(h.token()), Some(h), "{}", h.token());
    }
    assert_eq!(Hook::by_token("PATH_CHECK"), Some(Hook::FileCheck));
    assert_eq!(Hook::by_token("FILE_MMAP"), Some(Hook::MmapCheck));
    assert_eq!(Hook::by_token("POST_SETATTR"), None);
    assert_eq!(Hook::by_token("NONE"), None);
    assert_eq!(Hook::by_token("nonsense"), None);
}

#[test]
fn xattr_names() {
    assert_eq!(XATTR_NAME_IMA, "security.ima");
    assert_eq!(XATTR_NAME_EVM, "security.evm");
    assert_eq!(XATTR_NAME_CAPS, "security.capability");
}
