//! Strict Windows console text conversion at the native terminal boundary.
//!
//! The console handle, buffering, and ownership remain with the native
//! terminal owner. This crate only converts explicit byte/code-unit spans;
//! it never adds a terminator, consumes a handle, or substitutes a character.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleCodePage { Utf8, Oem437, Ansi1252 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversionError {
    UnsupportedCodePage(u32), InvalidUtf8, OddUtf16Length, UnpairedUtf16,
    InvalidCodePageByte(u8), UnmappableCharacter(u32),
}

impl ConsoleCodePage {
    /// Admit only code pages with a canonical, lossless table in this owner.
    /// # C: O(1)
    pub const fn from_id(id: u32) -> Result<Self, ConversionError> {
        match id { 65001 => Ok(Self::Utf8), 437 => Ok(Self::Oem437), 1252 => Ok(Self::Ansi1252), _ => Err(ConversionError::UnsupportedCodePage(id)) }
    }
}

/// Convert a console input byte span to UTF-16 code units without ownership transfer.
/// # C: O(input length)
pub fn input_to_utf16(page: ConsoleCodePage, input: &[u8]) -> Result<Vec<u16>, ConversionError> {
    match page {
        ConsoleCodePage::Utf8 => core::str::from_utf8(input).map(|text| text.encode_utf16().collect()).map_err(|_| ConversionError::InvalidUtf8),
        ConsoleCodePage::Oem437 | ConsoleCodePage::Ansi1252 => input.iter().map(|&byte| decode_byte(page, byte)).collect(),
    }
}

/// Convert a UTF-16 console output span to the selected code page strictly.
/// # C: O(code-unit length)
pub fn output_from_utf16(page: ConsoleCodePage, input: &[u16]) -> Result<Vec<u8>, ConversionError> {
    let text = decode_utf16(input)?;
    match page {
        ConsoleCodePage::Utf8 => Ok(text.into_bytes()),
        ConsoleCodePage::Oem437 => text.chars().map(encode_437).collect(),
        ConsoleCodePage::Ansi1252 => text.chars().map(encode_1252).collect(),
    }
}

/// Decode an explicit little-endian UTF-16 byte span, rejecting odd lengths.
/// # C: O(input length)
pub fn utf16le_to_utf16(input: &[u8]) -> Result<Vec<u16>, ConversionError> {
    if input.len() % 2 != 0 { return Err(ConversionError::OddUtf16Length); }
    Ok(input.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect())
}

fn decode_utf16(input: &[u16]) -> Result<String, ConversionError> {
    char::decode_utf16(input.iter().copied()).map(|item| item.map_err(|_| ConversionError::UnpairedUtf16)).collect()
}

fn decode_byte(page: ConsoleCodePage, byte: u8) -> Result<u16, ConversionError> {
    if byte.is_ascii() { return Ok(byte as u16); }
    let ch = match page { ConsoleCodePage::Oem437 => OEM437[(byte - 0x80) as usize], ConsoleCodePage::Ansi1252 => ANSI1252[(byte - 0x80) as usize], ConsoleCodePage::Utf8 => unreachable!() };
    if ch == '\u{fffd}' { Err(ConversionError::InvalidCodePageByte(byte)) } else { Ok(ch as u16) }
}

fn encode_437(ch: char) -> Result<u8, ConversionError> {
    if ch as u32 <= 0x7f { return Ok(ch as u8); }
    OEM437.iter().position(|&value| value == ch).map(|index| index as u8 + 0x80).ok_or(ConversionError::UnmappableCharacter(ch as u32))
}

fn encode_1252(ch: char) -> Result<u8, ConversionError> {
    if ch as u32 <= 0x7f { return Ok(ch as u8); }
    if ch as u32 >= 0xa0 && ch as u32 <= 0xff { return Ok(ch as u8); }
    ANSI1252.iter().position(|&value| value == ch).map(|index| index as u8 + 0x80).ok_or(ConversionError::UnmappableCharacter(ch as u32))
}

const OEM437: [char; 128] = [
 'Ç','ü','é','â','ä','à','å','ç','ê','ë','è','ï','î','ì','Ä','Å','É','æ','Æ','ô','ö','ò','û','ù','ÿ','Ö','Ü','¢','£','¥','₧','ƒ',
 'á','í','ó','ú','ñ','Ñ','ª','º','¿','⌐','¬','½','¼','¡','«','»','░','▒','▓','│','┤','╡','╢','╖','╕','╣','║','╗','╝','╜','╛','┐',
 '└','┴','┬','├','─','┼','╞','╟','╚','╔','╩','╦','╠','═','╬','¤','ð','Ð','Ê','Ë','È','ı','Í','Î','Ï','┘','┌','█','▄','¦','Ì','▀',
 'Ó','ß','Ô','Ò','õ','Õ','µ','þ','Þ','Ú','Û','Ù','ý','Ý','¯','´','\u{ad}','±','‗','¾','¶','§','÷','¸','°','¨','·','¹','³','²','■','\u{a0}',
];

const ANSI1252: [char; 128] = [
 '€','�','‚','ƒ','„','…','†','‡','ˆ','‰','Š','‹','Œ','�','Ž','�','�','‘','’','“','”','•','–','—','˜','™','š','›','œ','�','ž','Ÿ',
 '\u{a0}','¡','¢','£','¤','¥','¦','§','¨','©','ª','«','¬','\u{ad}','®','¯','°','±','²','³','´','µ','¶','·','¸','¹','º','»','¼','½','¾','¿',
 'À','Á','Â','Ã','Ä','Å','Æ','Ç','È','É','Ê','Ë','Ì','Í','Î','Ï','Ð','Ñ','Ò','Ó','Ô','Õ','Ö','×','Ø','Ù','Ú','Û','Ü','Ý','Þ','ß',
 'à','á','â','ã','ä','å','æ','ç','è','é','ê','ë','ì','í','î','ï','ð','ñ','ò','ó','ô','õ','ö','÷','ø','ù','ú','û','ü','ý','þ','ÿ',
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn code_page_admission_is_explicit_and_fail_closed() { assert_eq!(ConsoleCodePage::from_id(65001), Ok(ConsoleCodePage::Utf8)); assert_eq!(ConsoleCodePage::from_id(0), Err(ConversionError::UnsupportedCodePage(0))); assert_eq!(ConsoleCodePage::from_id(932), Err(ConversionError::UnsupportedCodePage(932))); }
    #[test] fn utf8_input_preserves_ascii_multibyte_and_embedded_nul() { assert_eq!(input_to_utf16(ConsoleCodePage::Utf8, "AΩ😀\0".as_bytes()).unwrap(), ['A' as u16, 0x03a9, 0xd83d, 0xde00, 0]); }
    #[test] fn utf8_input_rejects_truncated_and_overlong_sequences() { assert_eq!(input_to_utf16(ConsoleCodePage::Utf8, &[0xf0, 0x9f, 0x98]), Err(ConversionError::InvalidUtf8)); assert_eq!(input_to_utf16(ConsoleCodePage::Utf8, &[0xc0, 0x80]), Err(ConversionError::InvalidUtf8)); }
    #[test] fn oem_and_ansi_decode_the_same_byte_differently() { assert_eq!(input_to_utf16(ConsoleCodePage::Oem437, &[0x82]).unwrap(), ['é' as u16]); assert_eq!(input_to_utf16(ConsoleCodePage::Ansi1252, &[0x82]).unwrap(), ['‚' as u16]); }
    #[test] fn output_utf16_is_strict_and_does_not_add_a_terminator() { assert_eq!(output_from_utf16(ConsoleCodePage::Utf8, &['A' as u16, 0]).unwrap(), b"A\0"); assert_eq!(output_from_utf16(ConsoleCodePage::Utf8, &[0xd83d]), Err(ConversionError::UnpairedUtf16)); }
    #[test] fn output_rejects_unmappable_legacy_characters_instead_of_question_mark() { assert_eq!(output_from_utf16(ConsoleCodePage::Oem437, &[0x20ac]), Err(ConversionError::UnmappableCharacter(0x20ac))); assert_eq!(output_from_utf16(ConsoleCodePage::Ansi1252, &[0x20ac]), Ok(vec![0x80])); }
    #[test] fn utf16le_boundary_rejects_odd_bytes_and_preserves_units() { assert_eq!(utf16le_to_utf16(&[0x41, 0, 0xa9]), Err(ConversionError::OddUtf16Length)); assert_eq!(utf16le_to_utf16(&[0x3d, 0xd8, 0x00, 0xde]).unwrap(), [0xd83d, 0xde00]); }
    #[test] fn every_defined_oem_entry_round_trips() { for byte in 0x80..=0xff { let unit = input_to_utf16(ConsoleCodePage::Oem437, &[byte]).unwrap(); assert_eq!(output_from_utf16(ConsoleCodePage::Oem437, &unit).unwrap(), [byte]); } }
}
