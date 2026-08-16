use super::*;
use crate::record::Reference;

fn sample(name: &str, namespace: u8) -> FileName {
    FileName {
        parent: Reference { number: 5, sequence: 1 },
        create_time: 1,
        modify_time: 2,
        change_time: 3,
        access_time: 4,
        alloc_size: 4096,
        data_size: 100,
        attributes: FILE_ATTRIBUTE_ARCHIVE,
        namespace,
        units: name.encode_utf16().collect(),
    }
}

#[test]
fn a_filename_record_round_trips() {
    let f = sample("readme.txt", FILE_NAME_POSIX);
    let bytes = write_filename(&f);
    assert_eq!(parse_filename(&bytes).unwrap(), f);
    assert_eq!(parse_filename(&bytes).unwrap().name(), "readme.txt");
}

#[test]
fn a_directorys_record_says_so() {
    let mut f = sample("dir", FILE_NAME_POSIX);
    f.attributes = FILE_ATTRIBUTE_DIRECTORY;
    assert!(parse_filename(&write_filename(&f)).unwrap().is_dir());
    assert!(!parse_filename(&write_filename(&sample("f", FILE_NAME_POSIX))).unwrap().is_dir());
}

#[test]
fn a_record_shorter_than_the_minimum_is_refused() {
    assert!(parse_filename(&[0u8; 16]).is_none());
}

#[test]
fn a_declared_length_past_the_bytes_is_refused() {
    let mut bytes = write_filename(&sample("ab", FILE_NAME_POSIX));
    bytes[FN_OFF_NAME_LEN] = 200;
    assert!(parse_filename(&bytes).is_none());
}

#[test]
fn the_dos_alias_is_suppressed_only_when_a_long_name_exists() {
    // Listing both shows one file twice; listing neither hides a file whose
    // only name is an alias.
    let alias = sample("READ~1.TXT", FILE_NAME_DOS);
    assert!(!should_list(&alias, true));
    assert!(should_list(&alias, false));
    assert!(should_list(&sample("readme.txt", FILE_NAME_UNICODE), true));
}

#[test]
fn the_preferred_name_is_the_long_one() {
    let names = alloc::vec![sample("READ~1.TXT", FILE_NAME_DOS),
                            sample("readme.txt", FILE_NAME_UNICODE)];
    assert_eq!(preferred(&names).unwrap().name(), "readme.txt");
    // A combined-namespace name is both, so it wins outright.
    let names = alloc::vec![sample("BOTH.TXT", FILE_NAME_UNICODE_AND_DOS)];
    assert_eq!(preferred(&names).unwrap().name(), "BOTH.TXT");
    // With only an alias, the alias is the name.
    let names = alloc::vec![sample("ONLY~1.TXT", FILE_NAME_DOS)];
    assert_eq!(preferred(&names).unwrap().name(), "ONLY~1.TXT");
}

#[test]
fn the_paired_namespace_is_the_other_half_of_a_name_pair() {
    assert_eq!(paired_namespace(FILE_NAME_UNICODE), FILE_NAME_DOS);
    assert_eq!(paired_namespace(FILE_NAME_DOS), FILE_NAME_UNICODE);
    assert_eq!(paired_namespace(FILE_NAME_POSIX), FILE_NAME_POSIX);
}

#[test]
fn a_name_encodes_and_decodes() {
    assert_eq!(encode("abc").unwrap(), alloc::vec![0x61, 0x62, 0x63]);
    assert_eq!(decode(&[0x48, 0x69]), "Hi");
    assert_eq!(decode(&[0xD800]), "\u{FFFD}");
}

#[test]
fn a_name_of_nothing_or_past_the_ceiling_is_refused() {
    assert!(encode("").is_none());
    let long: alloc::string::String = core::iter::repeat('x').take(256).collect();
    assert!(encode(&long).is_none());
    let at_limit: alloc::string::String = core::iter::repeat('x').take(255).collect();
    assert!(encode(&at_limit).is_some());
}
