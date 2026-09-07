use super::*;

fn utf16(text: &str) -> Vec<u8> { text.encode_utf16().flat_map(u16::to_le_bytes).collect() }

#[test]
fn the_pin_is_one_wine_version() {
    assert_eq!(version_of_stamp(EXPECTED).as_deref(), Some(EXPECTED.trim()));
}

#[test]
fn a_stamp_is_a_version_and_nothing_else() {
    assert_eq!(version_of_stamp("11.16\n").as_deref(), Some("11.16"));
    assert_eq!(version_of_stamp(""), None);
    assert_eq!(version_of_stamp("wine-11.16"), None);
    assert_eq!(version_of_stamp("11"), None);
}

#[test]
fn a_module_answers_with_the_wine_release_its_resource_names() {
    let mut blob = vec![0u8; 64];
    blob.extend(utf16("Wine 11.16"));
    blob.extend([0, 0]);
    assert_eq!(module_version(&blob).as_deref(), Some("11.16"));
}

#[test]
fn a_module_with_no_version_resource_answers_nothing() {
    assert_eq!(module_version(b"MZ\x90\x00 no version resource here"), None);
    assert_eq!(module_version(&utf16("Wine kernel DLL")), None);
}

/// A blended catalog is exactly two answers to one question: the older module
/// must still be recognisable, not silently read as the newer one.
#[test]
fn an_older_module_answers_with_its_own_release() {
    let mut blob = utf16("Wine advapi32");
    blob.extend(utf16("Wine 10.20"));
    assert_eq!(module_version(&blob).as_deref(), Some("10.20"));
}

#[test]
fn a_directory_listing_drops_the_dot_entries() {
    let listing = "/16/040755/0/0/.//\n/23/040755/0/0/..//\n/21/100644/0/0/user32.dll/585/\n/22/100644/0/0/notepad.exe/585/\n";
    assert_eq!(parse_listing(listing), ["user32.dll", "notepad.exe"]);
}
