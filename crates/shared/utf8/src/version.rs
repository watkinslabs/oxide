/// Charset-name prefix a casefolding mount option carries: `utf8-12.1.0`.
/// A bare `utf8` (no version) means the table's own version.
pub const CHARSET_UTF8_PREFIX: &str = "utf8";

const MAJ_SHIFT: u32 = 16;
const MIN_SHIFT: u32 = 8;
const FIELD_MASK: u32 = 0xff;
const VERSION_FIELDS: usize = 3;

/// A Unicode version as one packed `maj<<16 | min<<8 | rev` word — the form
/// both the mount option and the on-disk superblock field carry.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct UnicodeVersion(u32);

impl UnicodeVersion {
    /// # C: O(1)
    pub const fn new(maj: u8, min: u8, rev: u8) -> Self {
        UnicodeVersion(((maj as u32) << MAJ_SHIFT) | ((min as u32) << MIN_SHIFT) | rev as u32)
    }
    /// # C: O(1)
    pub const fn from_packed(v: u32) -> Self { UnicodeVersion(v) }
    /// Packed word, as stored in a superblock field. # C: O(1)
    pub const fn packed(self) -> u32 { self.0 }
    /// # C: O(1)
    pub const fn major(self) -> u8 { ((self.0 >> MAJ_SHIFT) & FIELD_MASK) as u8 }
    /// # C: O(1)
    pub const fn minor(self) -> u8 { ((self.0 >> MIN_SHIFT) & FIELD_MASK) as u8 }
    /// # C: O(1)
    pub const fn revision(self) -> u8 { (self.0 & FIELD_MASK) as u8 }

    /// Parse `<maj>.<min>.<rev>`; `None` on any other shape. # C: O(s.len())
    pub fn parse(s: &str) -> Option<Self> {
        let mut field = [0u32; VERSION_FIELDS];
        let mut n = 0usize;
        let mut digits = 0usize;
        for b in s.bytes() {
            if b == b'.' {
                if digits == 0 || n + 1 == VERSION_FIELDS { return None; }
                n += 1;
                digits = 0;
                continue;
            }
            if !b.is_ascii_digit() { return None; }
            let v = field[n] * 10 + (b - b'0') as u32;
            if v > FIELD_MASK { return None; }
            field[n] = v;
            digits += 1;
        }
        if digits == 0 || n + 1 != VERSION_FIELDS { return None; }
        Some(UnicodeVersion::new(field[0] as u8, field[1] as u8, field[2] as u8))
    }

    /// Parse a charset name: `utf8` (table version) or `utf8-<maj>.<min>.<rev>`.
    /// `None` for any other charset — the caller refuses the mount, which is
    /// what a filesystem asking for an encoding this kernel cannot supply must
    /// get. # C: O(s.len())
    pub fn parse_charset(s: &str, table: UnicodeVersion) -> Option<Self> {
        if s.eq_ignore_ascii_case(CHARSET_UTF8_PREFIX) { return Some(table); }
        let rest = s.get(..CHARSET_UTF8_PREFIX.len())
            .filter(|p| p.eq_ignore_ascii_case(CHARSET_UTF8_PREFIX))
            .and_then(|_| s.get(CHARSET_UTF8_PREFIX.len()..))?;
        let rest = rest.strip_prefix('-')?;
        Self::parse(rest)
    }
}
