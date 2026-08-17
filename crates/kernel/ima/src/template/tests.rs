// Byte-exact expectations. A wrong length prefix here shifts every following
// field of every record, and a wrong digest prefix changes the value extended
// into the PCR — neither shows up as a crash, only as attestation that no
// verifier can reproduce.

use alloc::vec;
use alloc::vec::Vec;

use crate::hash::{hex, HashAlgo};
use crate::limits::IMA_EVENT_NAME_LEN_MAX;
use crate::template::desc::*;
use crate::template::entry::ascii_field;
use crate::template::event::{Event, InodeMeta};
use crate::template::fields::*;
use crate::template::TemplateEntry;
use crate::uapi::XattrType;

fn d32() -> Vec<u8> { (0u8..32).collect() }
fn d20() -> Vec<u8> { (0u8..20).collect() }

// --- the registry --------------------------------------------------------

#[test]
fn builtin_templates_expand_to_their_documented_fields() {
    let want: [(&str, &[FieldId]); 8] = [
        ("ima", &[FieldId::D, FieldId::N]),
        ("ima-ng", &[FieldId::DNg, FieldId::NNg]),
        ("ima-sig", &[FieldId::DNg, FieldId::NNg, FieldId::Sig]),
        ("ima-ngv2", &[FieldId::DNgV2, FieldId::NNg]),
        ("ima-sigv2", &[FieldId::DNgV2, FieldId::NNg, FieldId::Sig]),
        ("ima-buf", &[FieldId::DNg, FieldId::NNg, FieldId::Buf]),
        ("ima-modsig", &[FieldId::DNg, FieldId::NNg, FieldId::Sig, FieldId::DModsig,
                         FieldId::Modsig]),
        ("evm-sig", &[FieldId::DNg, FieldId::NNg, FieldId::Evmsig, FieldId::Xattrnames,
                      FieldId::Xattrlengths, FieldId::Xattrvalues, FieldId::Iuid, FieldId::Igid,
                      FieldId::Imode]),
    ];
    for (name, fields) in want {
        let d = lookup_desc(name).unwrap_or_else(|| panic!("{name} missing"));
        assert_eq!(d.fields(), fields.to_vec(), "{name}");
    }
    assert_eq!(BUILTIN.len(), 8);
    assert_eq!(TEMPLATE_IMA_NAME, "ima");
    assert_eq!(TEMPLATE_IMA_FMT, "d|n");
}

#[test]
fn a_template_resolves_by_name_or_by_format() {
    assert_eq!(lookup_desc("ima-ng").unwrap().fmt, "d-ng|n-ng");
    assert_eq!(lookup_desc("d-ng|n-ng").unwrap().name, "ima-ng");
    assert!(lookup_desc("no-such").is_none());
    assert!(parse_fmt("d-ng|nonsense").is_none());
    assert!(parse_fmt("").is_none());
    assert_eq!(parse_fmt("d-ng|n-ng|sig").unwrap().len(), 3);
}

#[test]
fn only_the_appended_signature_templates_reference_one() {
    assert!(lookup_desc("ima-modsig").unwrap().has_modsig());
    assert!(!lookup_desc("ima-sig").unwrap().has_modsig());
}

// --- field serialisation -------------------------------------------------

#[test]
fn a_string_field_carries_its_terminating_nul_inside_its_length() {
    let f = write_field_data(b"/bin/sh", DataFmt::Str);
    assert_eq!(f.bytes, b"/bin/sh\0".to_vec());
    assert_eq!(f.len(), 8);
}

#[test]
fn a_string_field_replaces_spaces_so_the_ascii_list_stays_splittable() {
    let f = write_field_data(b"/tmp/a b (deleted)", DataFmt::Str);
    assert_eq!(f.bytes, b"/tmp/a_b_(deleted)\0".to_vec());
    assert_eq!(ascii_field(&f), "/tmp/a_b_(deleted)");
}

#[test]
fn a_bare_digest_field_is_the_digest_and_nothing_else() {
    let f = digest_field(Some(&d20()), None, None);
    assert_eq!(f.bytes, d20());
    assert_eq!(f.len(), 20);
    assert_eq!(f.fmt, DataFmt::Digest);
}

#[test]
fn an_algorithm_prefixed_digest_field_is_name_colon_nul_digest() {
    let f = digest_field(Some(&d32()), None, Some(HashAlgo::Sha256));
    let mut want = b"sha256:\0".to_vec();
    want.extend_from_slice(&d32());
    assert_eq!(f.bytes, want);
    // Seven characters, a colon, a NUL, then the digest.
    assert_eq!(f.len(), 7 + 1 + 32);
    assert_eq!(f.bytes[6], b':');
    assert_eq!(f.bytes[7], 0);
    assert_eq!(f.fmt, DataFmt::DigestWithAlgo);
}

#[test]
fn a_typed_digest_field_names_the_digest_type_first() {
    let f = digest_field(Some(&d32()), Some(DigestType::Verity), Some(HashAlgo::Sha256));
    let mut want = b"verity:sha256:\0".to_vec();
    want.extend_from_slice(&d32());
    assert_eq!(f.bytes, want);
    assert_eq!(f.fmt, DataFmt::DigestWithTypeAndAlgo);

    let f = digest_field(Some(&d32()), Some(DigestType::Ima), Some(HashAlgo::Sha256));
    assert!(f.bytes.starts_with(b"ima:sha256:\0"));
}

#[test]
fn a_violation_digest_field_is_zeroes_of_the_right_width() {
    // No digest was taken, but the field keeps its shape so the record parses.
    let f = digest_field(None, None, None);
    assert_eq!(f.bytes, vec![0u8; 20]);
    let f = digest_field(None, None, Some(HashAlgo::Sha256));
    assert_eq!(f.bytes.len(), 7 + 1 + 32);
    assert!(f.bytes.starts_with(b"sha256:\0"));
    assert!(f.bytes[8..].iter().all(|b| *b == 0));
}

#[test]
fn the_original_templates_name_field_is_capped() {
    let long = alloc::string::String::from_utf8(vec![b'a'; 400]).unwrap();
    let ev = Event::new(&long, HashAlgo::Sha1, None);
    let f = init_field(FieldId::N, &ev);
    assert_eq!(f.len(), IMA_EVENT_NAME_LEN_MAX as u32 + 1);
    // The modern name field is not capped.
    let f = init_field(FieldId::NNg, &ev);
    assert_eq!(f.len(), 401);
}

#[test]
fn a_signature_field_falls_back_to_the_portable_label_then_to_nothing() {
    let d = d32();
    let mut ev = Event::new("/bin/sh", HashAlgo::Sha256, Some(&d));
    // No label at all: the field is present but empty.
    assert!(init_field(FieldId::Sig, &ev).is_empty());

    // A bare digest label is not a signature, so it is not reported as one.
    let digest_label = alloc::vec![XattrType::ImaDigestNg.tag(), HashAlgo::Sha256.id()];
    ev.xattr = Some(&digest_label);
    assert!(init_field(FieldId::Sig, &ev).is_empty());

    // A file signature is reported verbatim.
    let sig = alloc::vec![XattrType::EvmImaDigsig.tag(), 2, 4, 0, 0, 0, 1, 0, 4, 9, 9, 9, 9];
    ev.xattr = Some(&sig);
    assert_eq!(init_field(FieldId::Sig, &ev).bytes, sig);

    // With no file signature, a portable metadata signature stands in.
    let evmsig = alloc::vec![XattrType::EvmPortableDigsig.tag(), 3, 4, 0, 0, 0, 1, 0, 2, 7, 7];
    ev.xattr = Some(&digest_label);
    ev.evm_xattr = Some(&evmsig);
    assert_eq!(init_field(FieldId::Sig, &ev).bytes, evmsig);
    // A locally keyed label is not a signature and is not reported.
    let hmac = alloc::vec![XattrType::EvmHmac.tag(); 21];
    ev.evm_xattr = Some(&hmac);
    assert!(init_field(FieldId::Sig, &ev).is_empty());
}

#[test]
fn inode_fields_are_little_endian_of_their_own_width() {
    let d = d32();
    let mut ev = Event::new("/bin/sh", HashAlgo::Sha256, Some(&d));
    ev.inode = Some(InodeMeta { uid: 1000, gid: 100, mode: 0o100755 });
    assert_eq!(init_field(FieldId::Iuid, &ev).bytes, 1000u32.to_le_bytes().to_vec());
    assert_eq!(init_field(FieldId::Igid, &ev).bytes, 100u32.to_le_bytes().to_vec());
    assert_eq!(init_field(FieldId::Imode, &ev).bytes, 0o100755u16.to_le_bytes().to_vec());
    assert_eq!(ascii_field(&init_field(FieldId::Iuid, &ev)), "1000");
    assert_eq!(ascii_field(&init_field(FieldId::Imode, &ev)), "33261");
    // Without an inode the fields are present and empty.
    ev.inode = None;
    assert!(init_field(FieldId::Iuid, &ev).is_empty());
}

#[test]
fn a_buffer_field_carries_the_measured_bytes() {
    let d = d32();
    let mut ev = Event::new("kexec-cmdline", HashAlgo::Sha256, Some(&d));
    assert!(init_field(FieldId::Buf, &ev).is_empty());
    ev.buf = Some(b"root=/dev/sda1");
    let f = init_field(FieldId::Buf, &ev);
    assert_eq!(f.bytes, b"root=/dev/sda1".to_vec());
    // A buffer is rendered as hexadecimal, never as text, so a crafted buffer
    // cannot forge list structure.
    assert_eq!(ascii_field(&f), hex(b"root=/dev/sda1"));
}

// --- whole records -------------------------------------------------------

fn ng_entry() -> TemplateEntry {
    let d = d32();
    let ev = Event::new("/bin/sh", HashAlgo::Sha256, Some(&d));
    TemplateEntry::build(lookup_desc("ima-ng").unwrap(), &ev, 10)
}

#[test]
fn the_record_data_length_counts_each_fields_own_prefix() {
    let e = ng_entry();
    // 4 + (7+1+32) for the digest, 4 + 8 for "/bin/sh\0".
    assert_eq!(e.data_len(), 4 + 40 + 4 + 8);
}

#[test]
fn the_binary_record_layout_is_exact() {
    let e = ng_entry();
    let td = e.template_digest(HashAlgo::Sha1).unwrap();
    let rec = e.binary_record(&td);

    let mut want: Vec<u8> = Vec::new();
    want.extend_from_slice(&10u32.to_le_bytes());          // PCR index
    want.extend_from_slice(&td);                           // template digest
    want.extend_from_slice(&6u32.to_le_bytes());           // name length
    want.extend_from_slice(b"ima-ng");                     // name
    want.extend_from_slice(&(4 + 40 + 4 + 8u32).to_le_bytes()); // total data length
    want.extend_from_slice(&40u32.to_le_bytes());          // digest field length
    want.extend_from_slice(b"sha256:\0");
    want.extend_from_slice(&d32());
    want.extend_from_slice(&8u32.to_le_bytes());           // name field length
    want.extend_from_slice(b"/bin/sh\0");
    assert_eq!(rec, want);
}

#[test]
fn the_original_template_record_omits_the_data_length_and_the_digest_prefix() {
    let d = d20();
    let ev = Event::new("/bin/sh", HashAlgo::Sha1, Some(&d));
    let e = TemplateEntry::build(lookup_desc("ima").unwrap(), &ev, 10);
    let td = e.template_digest(HashAlgo::Sha1).unwrap();
    let rec = e.binary_record(&td);

    let mut want: Vec<u8> = Vec::new();
    want.extend_from_slice(&10u32.to_le_bytes());
    want.extend_from_slice(&td);
    want.extend_from_slice(&3u32.to_le_bytes());
    want.extend_from_slice(b"ima");
    // No total-length field, and the fixed-width digest carries no prefix.
    want.extend_from_slice(&d20());
    // The name reports the length of its text, without the NUL it stores.
    want.extend_from_slice(&7u32.to_le_bytes());
    want.extend_from_slice(b"/bin/sh");
    assert_eq!(rec, want);
}

#[test]
fn the_template_digest_covers_each_field_with_its_length() {
    let e = ng_entry();
    let mut input: Vec<u8> = Vec::new();
    input.extend_from_slice(&40u32.to_le_bytes());
    input.extend_from_slice(b"sha256:\0");
    input.extend_from_slice(&d32());
    input.extend_from_slice(&8u32.to_le_bytes());
    input.extend_from_slice(b"/bin/sh\0");
    assert_eq!(e.template_digest(HashAlgo::Sha1).unwrap(),
               HashAlgo::Sha1.digest(&[&input]).unwrap());
    assert_eq!(e.template_digest(HashAlgo::Sha256).unwrap(),
               HashAlgo::Sha256.digest(&[&input]).unwrap());
    // The digest is over the fields, not over the file digest alone.
    assert_ne!(e.template_digest(HashAlgo::Sha256).unwrap(), d32());
}

#[test]
fn the_original_templates_digest_pads_the_name_to_a_fixed_width() {
    let d = d20();
    let ev = Event::new("/bin/sh", HashAlgo::Sha1, Some(&d));
    let e = TemplateEntry::build(lookup_desc("ima").unwrap(), &ev, 10);
    let mut input: Vec<u8> = Vec::new();
    input.extend_from_slice(&d20());              // no length prefix
    let mut name = vec![0u8; IMA_EVENT_NAME_LEN_MAX + 1];
    name[..7].copy_from_slice(b"/bin/sh");        // NUL padded to 256
    input.extend_from_slice(&name);
    assert_eq!(input.len(), 20 + 256);
    assert_eq!(e.template_digest(HashAlgo::Sha1).unwrap(),
               HashAlgo::Sha1.digest(&[&input]).unwrap());
}

#[test]
fn the_ascii_record_is_pcr_digest_name_then_fields() {
    let e = ng_entry();
    let td = e.template_digest(HashAlgo::Sha1).unwrap();
    let line = e.ascii_record(&td);
    let want = alloc::format!("10 {} ima-ng sha256:{} /bin/sh\n", hex(&td), hex(&d32()));
    assert_eq!(line, want);
}

#[test]
fn the_ascii_records_pcr_column_is_two_wide() {
    let d = d32();
    let ev = Event::new("/bin/sh", HashAlgo::Sha256, Some(&d));
    let e = TemplateEntry::build(lookup_desc("ima-ng").unwrap(), &ev, 8);
    let line = e.ascii_record(&[0u8; 20]);
    assert!(line.starts_with(" 8 "), "{line:?}");
}

#[test]
fn an_empty_field_still_occupies_its_place_in_both_renderings() {
    let d = d32();
    let ev = Event::new("/bin/sh", HashAlgo::Sha256, Some(&d));
    let e = TemplateEntry::build(lookup_desc("ima-sig").unwrap(), &ev, 10);
    // The signature field is empty: a zero length in the binary record...
    let rec = e.binary_record(&[0u8; 20]);
    assert_eq!(rec[rec.len() - 4..], 0u32.to_le_bytes());
    // ...and a bare separator in the ASCII one.
    let line = e.ascii_record(&[0u8; 20]);
    assert!(line.ends_with("/bin/sh \n"), "{line:?}");
}

#[test]
fn a_typed_digest_renders_its_prefix_as_text_and_its_digest_as_hex() {
    let f = digest_field(Some(&d32()), Some(DigestType::Verity), Some(HashAlgo::Sha256));
    assert_eq!(ascii_field(&f), alloc::format!("verity:sha256:{}", hex(&d32())));
    let f = digest_field(Some(&d20()), None, None);
    assert_eq!(ascii_field(&f), hex(&d20()));
}
