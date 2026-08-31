/// Executable format selected before a personality-specific loader runs.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BinaryFormat { Elf, Pe, Unknown }

/// Identify a binary without parsing it through the wrong personality.
/// # C: O(1)
pub fn identify(blob: &[u8]) -> BinaryFormat {
    if blob.starts_with(b"\x7fELF") { BinaryFormat::Elf }
    else if blob.starts_with(b"MZ") { BinaryFormat::Pe }
    else { BinaryFormat::Unknown }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn selects_personality_from_magic() {
        assert_eq!(identify(b"\x7fELF\x02"), BinaryFormat::Elf);
        assert_eq!(identify(b"MZ\0\0"), BinaryFormat::Pe);
        assert_eq!(identify(b"#!/bin/sh\n"), BinaryFormat::Unknown);
    }
}
