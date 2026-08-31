use super::*;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn arbitrary_file_bytes_never_panic(raw in proptest::collection::vec(any::<u8>(), 0..8192)) {
        if let Ok(parsed) = parse(&raw) {
            if let Ok(mut flat) = parsed.materialize() {
                let _ = parsed.imports();
                let _ = parsed.exports();
                let _ = parsed.tls();
                let _ = parsed.exception_functions();
                let _ = apply_relocations(&mut flat, &parsed, parsed.image_base.wrapping_add(0x1000));
            }
        }
    }
}

#[test]
fn every_truncated_valid_image_is_rejected_without_panic() {
    let raw = super::image();
    // The section's last referenced byte is 0x600; bytes after it are fixture
    // capacity, not part of the PE file's required payload.
    for end in 0..0x600 { assert!(parse(&raw[..end]).is_err(), "truncation at {end} was accepted"); }
    for end in 0x600..=raw.len() { assert!(parse(&raw[..end]).is_ok(), "valid suffix at {end} was rejected"); }
}

#[test]
fn every_directory_query_handles_valid_header_with_unbacked_directory() {
    let mut raw = super::image();
    for index in [IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT,
                  IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_TLS] {
        let at = OPT + 112 + index * 8;
        raw[at..at + 4].copy_from_slice(&0x2f00u32.to_le_bytes());
        raw[at + 4..at + 8].copy_from_slice(&0x100u32.to_le_bytes());
        let Ok(parsed) = parse(&raw) else { continue };
        let _ = parsed.imports(); let _ = parsed.exports(); let _ = parsed.tls();
        let _ = parsed.exception_functions();
    }
}

#[test]
fn every_single_bit_fixture_mutation_is_panic_free() {
    for byte in 0..super::image().len() {
        for bit in 0..8 {
            let mut raw = super::image(); raw[byte] ^= 1 << bit;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if let Ok(parsed) = parse(&raw) {
                    let _ = parsed.materialize(); let _ = parsed.imports(); let _ = parsed.exports();
                    let _ = parsed.tls(); let _ = parsed.exception_functions();
                }
            }));
            assert!(result.is_ok(), "parser panicked after mutating byte {byte}, bit {bit}");
        }
    }
}
