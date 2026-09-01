use super::*;

#[test]
fn directory_of_returns_the_parent_in_utf16_bytes() {
    let path = utf16_bytes_const(b"C:\\Games\\notepad.exe");
    assert_eq!(directory_of(&path), utf16_bytes_const(b"C:\\Games"));
    assert!(directory_of(&utf16_bytes_const(b"notepad.exe")).is_empty());
}

#[test]
fn append_directory_builds_a_deduplicated_search_list() {
    let system = utf16_bytes_const(b"C:\\Windows\\System32");
    let mut path = Vec::new();
    append_directory(&mut path, &system);
    append_directory(&mut path, &system);
    append_directory(&mut path, &utf16_bytes_const(b"C:\\Windows"));
    assert_eq!(path, {
        let mut expected = system.clone();
        expected.extend_from_slice(&[b';', 0]);
        expected.extend_from_slice(&utf16_bytes_const(b"C:\\Windows"));
        expected
    });
}
