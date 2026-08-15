//! Directory entries: the 32-byte records, and the long name spread across
//! several of them.
//!
//! The long-name encoding is the densest correctness surface in this
//! filesystem. Its slots are stored in REVERSE order, each carries an ordinal
//! and a checksum of the short name it belongs to, and a mismatch anywhere
//! does not fail the directory — it makes the reader fall back to the short
//! name, or restart the assembly at the offending slot. A reader that instead
//! errors, or that trusts a partial run, shows a user the wrong filename.

use alloc::string::String;
use alloc::vec::Vec;

/// One directory record, in bytes.
pub const ENTRY_BYTES: usize = 32;

pub const ATTR_RO: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYS: u8 = 0x04;
pub const ATTR_VOLUME: u8 = 0x08;
pub const ATTR_DIR: u8 = 0x10;
pub const ATTR_ARCH: u8 = 0x20;
/// The attribute combination that marks a long-name slot rather than a file.
pub const ATTR_EXT: u8 = ATTR_RO | ATTR_HIDDEN | ATTR_SYS | ATTR_VOLUME;

/// First name byte of a deleted entry.
pub const DELETED_FLAG: u8 = 0xe5;
/// Bit set on the ordinal of the slot that is LAST on disk and FIRST in the
/// name, since slots are stored in reverse.
pub const LAST_LONG_ENTRY: u8 = 0x40;
/// Most slots one name may span: 255 characters at 13 per slot.
pub const MAX_LONG_SLOTS: u8 = 20;
/// Characters one slot carries.
pub const CHARS_PER_SLOT: usize = 13;

/// Byte offsets within a short entry.
mod short {
    pub const NAME: usize = 0;
    pub const NAME_LEN: usize = 11;
    pub const ATTR: usize = 11;
    pub const CLUSTER_HI: usize = 20;
    pub const CLUSTER_LO: usize = 26;
    pub const SIZE: usize = 28;
}

/// Byte offsets within a long-name slot. The three character runs are not
/// contiguous: the attribute, checksum and cluster fields sit between them, at
/// the same offsets a short entry uses, so an old reader sees a harmless
/// read-only volume label rather than a file.
mod long {
    pub const ORDINAL: usize = 0;
    pub const CHARS_0: usize = 1;
    pub const CHARS_0_LEN: usize = 10;
    pub const ATTR: usize = 11;
    pub const CHECKSUM: usize = 13;
    pub const CHARS_1: usize = 14;
    pub const CHARS_1_LEN: usize = 12;
    pub const CHARS_2: usize = 28;
    pub const CHARS_2_LEN: usize = 4;
}

/// What one 32-byte record is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Entry {
    /// No entry has ever been used from here on; a scan may stop.
    EndOfDirectory,
    /// This slot was used and freed.
    Deleted,
    /// Part of a long name.
    LongSlot { ordinal: u8, last: bool, checksum: u8, chars: [u16; CHARS_PER_SLOT] },
    /// A file, directory or volume label.
    Short(ShortEntry),
}

/// A short directory entry.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ShortEntry {
    /// The raw 11 bytes, which are what the checksum is taken over — not the
    /// formatted name.
    pub raw_name: [u8; short::NAME_LEN],
    pub attr: u8,
    pub cluster: u32,
    pub size: u32,
}

impl ShortEntry {
    /// Whether this entry names a directory. # C: O(1)
    pub fn is_dir(&self) -> bool { self.attr & ATTR_DIR != 0 }
    /// Whether this entry is a volume label rather than a file. # C: O(1)
    pub fn is_volume_label(&self) -> bool { self.attr & ATTR_VOLUME != 0 }
}

fn le16(b: &[u8], at: usize) -> u16 { u16::from_le_bytes([b[at], b[at + 1]]) }
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Checksum of a short name, over its raw 11 bytes.
///
/// A right-rotate-then-add over each byte in order. Every long-name slot
/// carries it, and it is the only thing tying a run of slots to the entry it
/// names. # C: O(1)
pub fn checksum(raw_name: &[u8; short::NAME_LEN]) -> u8 {
    let mut s: u8 = 0;
    for byte in raw_name.iter() {
        s = s.rotate_right(1).wrapping_add(*byte);
    }
    s
}

/// Decode one 32-byte record. # C: O(1)
pub fn parse(record: &[u8]) -> Option<Entry> {
    if record.len() < ENTRY_BYTES { return None; }
    match record[short::NAME] {
        0x00 => return Some(Entry::EndOfDirectory),
        DELETED_FLAG => return Some(Entry::Deleted),
        _ => {}
    }
    if record[long::ATTR] == ATTR_EXT {
        let mut chars = [0u16; CHARS_PER_SLOT];
        let mut at = 0;
        for (start, len) in [(long::CHARS_0, long::CHARS_0_LEN),
                             (long::CHARS_1, long::CHARS_1_LEN),
                             (long::CHARS_2, long::CHARS_2_LEN)] {
            for i in (0..len).step_by(2) {
                chars[at] = le16(record, start + i);
                at += 1;
            }
        }
        let ordinal = record[long::ORDINAL];
        return Some(Entry::LongSlot {
            ordinal: ordinal & !LAST_LONG_ENTRY,
            last: ordinal & LAST_LONG_ENTRY != 0,
            checksum: record[long::CHECKSUM],
            chars,
        });
    }
    let mut raw_name = [0u8; short::NAME_LEN];
    raw_name.copy_from_slice(&record[short::NAME..short::NAME + short::NAME_LEN]);
    Some(Entry::Short(ShortEntry {
        raw_name,
        attr: record[short::ATTR],
        cluster: (u32::from(le16(record, short::CLUSTER_HI)) << 16)
            | u32::from(le16(record, short::CLUSTER_LO)),
        size: le32(record, short::SIZE),
    }))
}

/// The 8.3 name a short entry carries, as text.
///
/// The bytes are NOT UTF-8. They are a code page, so each is mapped as a
/// single character rather than decoded — decoding would fail outright on the
/// first byte above 0x7F and lose the whole name, which is exactly what a
/// name beginning with the escaped deleted-marker byte produces.
///
/// That first byte's `0x05` escape stands for a real `0xE5`, which would
/// otherwise read as the deleted marker. Padding spaces are dropped, and the
/// extension is joined with a dot only when there is one.
///
/// Deviation: the reference maps these bytes through the mount's configured
/// code page. Without one, each byte maps to the character of the same value,
/// which is correct for ASCII and for the Latin-1 range and wrong for a name
/// written under a different code page. Recorded in the issue ledger.
/// # C: O(1)
pub fn short_name(entry: &ShortEntry) -> String {
    let mut raw = entry.raw_name;
    if raw[0] == 0x05 { raw[0] = DELETED_FLAG; }
    let field = |bytes: &[u8]| -> String {
        let end = bytes.iter().rposition(|b| *b != b' ').map_or(0, |i| i + 1);
        bytes[..end].iter().map(|b| char::from(*b)).collect()
    };
    let base = field(&raw[..8]);
    let ext = field(&raw[8..11]);
    let mut out = base;
    if !ext.is_empty() { out.push('.'); out.push_str(&ext); }
    out
}

/// Encode a short entry back into its 32-byte record.
///
/// Only the fields this filesystem owns are written: the name, attribute,
/// cluster halves and size. Everything else in the record — the creation and
/// access timestamps, the reserved byte — is left as it was, because it
/// belongs to whoever wrote it and this filesystem has no better value for it.
/// # C: O(1)
pub fn encode_short(entry: &ShortEntry) -> [u8; ENTRY_BYTES] {
    let mut r = [0u8; ENTRY_BYTES];
    r[short::NAME..short::NAME + short::NAME_LEN].copy_from_slice(&entry.raw_name);
    r[short::ATTR] = entry.attr;
    r[short::CLUSTER_HI..short::CLUSTER_HI + 2]
        .copy_from_slice(&((entry.cluster >> 16) as u16).to_le_bytes());
    r[short::CLUSTER_LO..short::CLUSTER_LO + 2]
        .copy_from_slice(&(entry.cluster as u16).to_le_bytes());
    r[short::SIZE..short::SIZE + 4].copy_from_slice(&entry.size.to_le_bytes());
    r
}

/// Assembles long names from the slots preceding each short entry.
///
/// Fed records in on-disk order. The rules it enforces are the reference's,
/// and each exists because a directory can contain a partial or damaged run
/// that another system left behind:
///
/// - a run must begin with the slot marked LAST, since slots are reversed;
/// - ordinals must count down without a gap, and the checksum must not change
///   mid-run — a violation RESTARTS the assembly at that slot rather than
///   discarding it, because the offending slot may itself begin a valid run;
/// - a short entry whose checksum does not match the run's is not an error:
///   the long name is dropped and the short name stands.
#[derive(Default)]
pub struct LongName {
    chars: Vec<u16>,
    expected: u8,
    checksum: u8,
    active: bool,
}

impl LongName {
    /// # C: O(1)
    pub fn new() -> Self { Self::default() }

    /// Discard any partial run. # C: O(1)
    pub fn reset(&mut self) { self.chars.clear(); self.active = false; }

    /// Feed one long slot. # C: O(CHARS_PER_SLOT)
    pub fn push(&mut self, ordinal: u8, last: bool, checksum: u8, chars: &[u16; CHARS_PER_SLOT]) {
        if last {
            // A LAST slot always begins a run, whatever preceded it.
            if ordinal == 0 || ordinal > MAX_LONG_SLOTS { self.reset(); return; }
            self.chars.clear();
            self.chars.resize(usize::from(ordinal) * CHARS_PER_SLOT, 0);
            self.expected = ordinal;
            self.checksum = checksum;
            self.active = true;
        } else if !self.active || ordinal != self.expected || checksum != self.checksum {
            // Out of order, or from a different name. The reference restarts
            // here rather than dropping the slot, and so does this.
            self.reset();
            return;
        }
        let slot = usize::from(self.expected) - 1;
        let at = slot * CHARS_PER_SLOT;
        if at + CHARS_PER_SLOT > self.chars.len() { self.reset(); return; }
        self.chars[at..at + CHARS_PER_SLOT].copy_from_slice(chars);
        self.expected = self.expected.saturating_sub(1);
    }

    /// Take the assembled name for the short entry that follows.
    ///
    /// `None` when there was no complete run, or when its checksum does not
    /// name this entry — in both cases the caller uses the short name.
    /// # C: O(name length)
    pub fn take(&mut self, entry: &ShortEntry) -> Option<String> {
        let complete = self.active && self.expected == 0;
        let matches = complete && self.checksum == checksum(&entry.raw_name);
        let out = if matches { decode(&self.chars) } else { None };
        self.reset();
        out
    }
}

/// Decode a run's UCS-2 characters into text, stopping at the first
/// terminator. Unpaired surrogates and unconvertible values become the
/// replacement character rather than failing the whole directory.
/// # C: O(chars)
fn decode(chars: &[u16]) -> Option<String> {
    let end = chars.iter().position(|c| *c == 0 || *c == 0xFFFF).unwrap_or(chars.len());
    if end == 0 { return None; }
    Some(char::decode_utf16(chars[..end].iter().copied())
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect())
}

#[cfg(test)]
#[path = "dirent/tests.rs"]
mod tests;
