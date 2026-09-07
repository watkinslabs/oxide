//! Enumeration charset list. The ANSI codepage's charset is enumerated first,
//! then one entry per valid signature bit, then a catch-all for the rest.

/// Charset, codepage and the signature bit that selects them.
const CHARSETS: &[(u32, u32, u32)] = &[
    (0, 1252, 0x0000_0001), (238, 1250, 0x0000_0002), (204, 1251, 0x0000_0004),
    (161, 1253, 0x0000_0008), (162, 1254, 0x0000_0010), (177, 1255, 0x0000_0020),
    (178, 1256, 0x0000_0040), (186, 1257, 0x0000_0080), (163, 1258, 0x0000_0100),
    (222, 874, 0x0001_0000), (128, 932, 0x0002_0000), (134, 936, 0x0004_0000),
    (129, 949, 0x0008_0000), (136, 950, 0x0010_0000), (130, 1361, 0x0020_0000),
    (254, 65001, 0x0400_0000), (2, 42, 0x8000_0000),
];

/// Codepages whose script needs shaping do not take enumeration precedence.
const COMPLEX_CODEPAGES: [u32; 3] = [874, 1255, 1256];
const ANSI_CODEPAGE: u32 = 1252;
pub(super) const DEFAULT_CHARSET: u32 = 1;
pub(super) const OEM_CHARSET: u32 = 255;
pub(super) const OEM_SCRIPT: u32 = 32;
const OTHER_SCRIPT: u32 = 33;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct EnumCharset { pub mask: u32, pub charset: u32, pub script: u32 }

fn by_charset(charset: u32) -> Option<&'static (u32, u32, u32)> {
    CHARSETS.iter().find(|entry| entry.0 == charset)
}

fn by_codepage(codepage: u32) -> Option<&'static (u32, u32, u32)> {
    CHARSETS.iter().find(|entry| entry.1 == codepage)
}

fn by_signature(mask: u32) -> Option<&'static (u32, u32, u32)> {
    CHARSETS.iter().find(|entry| entry.2 & mask != 0)
}

fn highest_bit(mask: u32) -> u32 { (0..32).filter(|bit| mask & (1 << bit) != 0).last().unwrap_or(0) }

/// Build the enumeration list for one requested charset. # C: O(signature bits)
pub(super) fn list(charset: u32) -> Vec<EnumCharset> {
    let mut list = Vec::new();
    if let Some(entry) = by_charset(charset).filter(|entry| entry.2 != 0) {
        list.push(EnumCharset { mask: entry.2, charset: entry.0, script: highest_bit(entry.2) });
        return list;
    }
    let mut covered = 0u32;
    if !COMPLEX_CODEPAGES.contains(&ANSI_CODEPAGE) {
        if let Some(entry) = by_codepage(ANSI_CODEPAGE).filter(|entry| entry.2 != 0) {
            list.push(EnumCharset { mask: entry.2, charset: entry.0, script: highest_bit(entry.2) });
            covered |= entry.2;
        }
    }
    for bit in 0..32 {
        let mask = 1u32 << bit;
        if mask & covered != 0 { continue; }
        let Some(entry) = by_signature(mask) else { continue; };
        list.push(EnumCharset { mask, charset: entry.0, script: bit });
        covered |= mask;
    }
    if covered != u32::MAX { list.push(EnumCharset { mask: !covered, charset: DEFAULT_CHARSET, script: OTHER_SCRIPT }); }
    list
}
