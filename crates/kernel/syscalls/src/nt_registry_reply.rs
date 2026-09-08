//! Reply records and buffer ladders for the NT registry query services.
//!
//! Every one of these services answers with a fixed header, optionally
//! followed by a name and then the value data, and reports the length the
//! caller would have needed. The header size, what counts toward the reported
//! length, and which of the two buffer statuses a short buffer earns differ
//! per service and per information class, so the whole table lives here where
//! it is testable rather than being spelled out at each call site.

use alloc::vec::Vec;

/// Longest value name any of these services accepts, in bytes.
pub const MAX_VALUE_NAME_BYTES: usize = 16383 * 2;

const STATUS_SUCCESS: u64 = 0;
const STATUS_BUFFER_OVERFLOW: u64 = 0x8000_0005;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;

const VALUE_BASIC_HEADER: usize = 12;
const VALUE_FULL_HEADER: usize = 20;
const VALUE_PARTIAL_HEADER: usize = 12;
const VALUE_PARTIAL_ALIGN64_HEADER: usize = 8;
const KEY_BASIC_HEADER: usize = 16;
const KEY_NODE_HEADER: usize = 24;
/// Nine 32-bit counters after the write time; the class text follows.
pub const KEY_FULL_HEADER: usize = 44;
const KEY_NAME_HEADER: usize = 4;
/// Seven 32-bit counters after the write time, padded to the record's own
/// eight-byte alignment: this class reports its whole size, not a field offset.
const KEY_CACHED_HEADER: usize = 40;
/// Absent class text is reported as this offset rather than as zero.
const NO_CLASS_OFFSET: u32 = u32::MAX;

/// Information class of a value query or enumeration.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ValueClass { Basic, Full, Partial, PartialAlign64 }

/// Information class of a key query or subkey enumeration.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyClass { Basic, Node, Full, Name, Cached }

impl ValueClass {
    /// # C: O(1)
    pub fn from_raw(raw: u64) -> Option<Self> {
        match raw { 0 => Some(Self::Basic), 1 => Some(Self::Full), 2 => Some(Self::Partial), 3 => Some(Self::PartialAlign64), _ => None }
    }
    /// # C: O(1)
    pub fn header_bytes(self) -> usize {
        match self { Self::Basic => VALUE_BASIC_HEADER, Self::Full => VALUE_FULL_HEADER, Self::Partial => VALUE_PARTIAL_HEADER, Self::PartialAlign64 => VALUE_PARTIAL_ALIGN64_HEADER }
    }
}

impl KeyClass {
    /// # C: O(1)
    pub fn from_raw(raw: u64) -> Option<Self> {
        match raw { 0 => Some(Self::Basic), 1 => Some(Self::Node), 2 => Some(Self::Full), 3 => Some(Self::Name), 4 => Some(Self::Cached), _ => None }
    }
    /// # C: O(1)
    pub fn header_bytes(self) -> usize {
        match self { Self::Basic => KEY_BASIC_HEADER, Self::Node => KEY_NODE_HEADER, Self::Full => KEY_FULL_HEADER, Self::Name => KEY_NAME_HEADER, Self::Cached => KEY_CACHED_HEADER }
    }
    /// Whether the record carries the key name after its header.
    /// # C: O(1)
    pub fn carries_name(self) -> bool { matches!(self, Self::Basic | Self::Node | Self::Name) }
}

/// One complete reply record: the header the caller always gets first, and
/// the whole record whose length is what the caller must be told it needed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record { header: usize, bytes: Vec<u8> }

impl Record {
    /// Length the caller is told it needed.
    /// # C: O(1)
    pub fn result_len(&self) -> usize { self.bytes.len() }
    /// # C: O(1)
    pub fn bytes(&self) -> &[u8] { &self.bytes }
}

/// Which buffer ladder a service applies to a short reply buffer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Ladder {
    /// A buffer shorter than the header is refused as too small.
    HeaderIsMandatory,
    /// Any short buffer only overflows; value enumeration has no floor.
    OverflowOnly,
}

/// What a caller must write, and the status it must return, for one record
/// against one caller buffer length. The prefix is written whichever status
/// results: a caller that asked for less than the header still gets what fits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delivery { pub prefix: usize, pub status: u64 }

/// Apply one service's buffer ladder to a completed record.
/// # C: O(1)
pub fn deliver(record: &Record, length: usize, ladder: Ladder) -> Delivery {
    let prefix = core::cmp::min(length, record.bytes.len());
    let status = if length < record.header && ladder == Ladder::HeaderIsMandatory { STATUS_BUFFER_TOO_SMALL }
        else if length < record.bytes.len() { STATUS_BUFFER_OVERFLOW }
        else { STATUS_SUCCESS };
    Delivery { prefix, status }
}

fn put_u32(out: &mut Vec<u8>, value: u32) { out.extend_from_slice(&value.to_le_bytes()); }
fn put_utf16(out: &mut Vec<u8>, text: &[u16]) { for unit in text { out.extend_from_slice(&unit.to_le_bytes()); } }

/// Build the reply to a value query. The name is the one the caller supplied,
/// so it is echoed back for the two classes that carry a name.
/// # C: O(name.len() + data.len())
pub fn value_query_record(class: ValueClass, name: &[u16], kind: u32, data: &[u8]) -> Record {
    let name_bytes = name.len() * 2;
    let mut bytes = Vec::new();
    match class {
        ValueClass::Basic => {
            put_u32(&mut bytes, 0); put_u32(&mut bytes, kind); put_u32(&mut bytes, name_bytes as u32);
            put_utf16(&mut bytes, name);
        }
        ValueClass::Full => {
            put_u32(&mut bytes, 0); put_u32(&mut bytes, kind);
            put_u32(&mut bytes, (VALUE_FULL_HEADER + name_bytes) as u32);
            put_u32(&mut bytes, data.len() as u32); put_u32(&mut bytes, name_bytes as u32);
            put_utf16(&mut bytes, name); bytes.extend_from_slice(data);
        }
        ValueClass::Partial => {
            put_u32(&mut bytes, 0); put_u32(&mut bytes, kind); put_u32(&mut bytes, data.len() as u32);
            bytes.extend_from_slice(data);
        }
        ValueClass::PartialAlign64 => {
            put_u32(&mut bytes, kind); put_u32(&mut bytes, data.len() as u32);
            bytes.extend_from_slice(data);
        }
    }
    Record { header: class.header_bytes(), bytes }
}

/// Build the reply to a value enumeration. The basic class reports only the
/// name it returns, never the data length, so its record stops at the name.
/// The 64-bit-aligned partial class is not an enumeration class at all.
/// # C: O(name.len() + data.len())
pub fn value_enum_record(class: ValueClass, name: &[u16], kind: u32, data: &[u8]) -> Option<Record> {
    if class == ValueClass::PartialAlign64 { return None; }
    Some(value_query_record(class, name, kind, data))
}

/// Counts a key query answers with; absent ones are reported as zero.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct KeyFacts { pub subkeys: u32, pub max_subkey: u32, pub values: u32, pub max_value_name: u32, pub max_value_data: u32 }

/// Build the reply to a key query or a subkey enumeration. Only the three
/// name-carrying classes return the name; the counting classes report the name
/// length alone, and no class of ours carries key class text.
/// # C: O(name.len())
pub fn key_record(class: KeyClass, name: &[u16], facts: KeyFacts) -> Record {
    let name_bytes = (name.len() * 2) as u32;
    let mut bytes = Vec::new();
    match class {
        KeyClass::Basic => {
            bytes.extend_from_slice(&[0; 8]); put_u32(&mut bytes, 0); put_u32(&mut bytes, name_bytes);
            put_utf16(&mut bytes, name);
        }
        KeyClass::Node => {
            bytes.extend_from_slice(&[0; 8]); put_u32(&mut bytes, 0);
            put_u32(&mut bytes, NO_CLASS_OFFSET); put_u32(&mut bytes, 0); put_u32(&mut bytes, name_bytes);
            put_utf16(&mut bytes, name);
        }
        KeyClass::Full => {
            bytes.extend_from_slice(&[0; 8]); put_u32(&mut bytes, 0);
            put_u32(&mut bytes, NO_CLASS_OFFSET); put_u32(&mut bytes, 0);
            put_u32(&mut bytes, facts.subkeys); put_u32(&mut bytes, facts.max_subkey); put_u32(&mut bytes, 0);
            put_u32(&mut bytes, facts.values); put_u32(&mut bytes, facts.max_value_name); put_u32(&mut bytes, facts.max_value_data);
        }
        KeyClass::Name => { put_u32(&mut bytes, name_bytes); put_utf16(&mut bytes, name); }
        KeyClass::Cached => {
            bytes.extend_from_slice(&[0; 8]); put_u32(&mut bytes, 0);
            put_u32(&mut bytes, facts.subkeys); put_u32(&mut bytes, facts.max_subkey);
            put_u32(&mut bytes, facts.values); put_u32(&mut bytes, facts.max_value_name);
            put_u32(&mut bytes, facts.max_value_data); put_u32(&mut bytes, name_bytes);
            bytes.extend_from_slice(&[0; KEY_CACHED_HEADER - 36]);
        }
    }
    Record { header: class.header_bytes(), bytes }
}

#[cfg(test)]
#[path = "tests/nt_registry_reply.rs"]
mod tests;
