// Connection-list decode. A widget's input list is packed several entries to
// a response word, in 8- or 16-bit slots, and a slot's top bit marks it as
// the end of a run of consecutive node ids rather than a single entry.

use alloc::vec::Vec;

/// `PAR_CONNLIST_LEN` fields.
pub const CLIST_LENGTH_MASK: u32 = 0x7f;
pub const CLIST_LONG: u32 = 1 << 7;

/// Slot geometry a connection list uses.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Layout {
    /// Bits per packed slot.
    pub shift: u32,
    /// Slots per 32-bit response word.
    pub per_word: usize,
    /// Node-id bits within a slot; the bit above is the range marker.
    pub mask: u32,
    /// Declared entry count.
    pub len: usize,
}

/// Decode `PAR_CONNLIST_LEN`. # C: O(1)
pub fn layout(param: u32) -> Layout {
    let long = param & CLIST_LONG != 0;
    let shift = if long { 16 } else { 8 };
    Layout {
        shift,
        per_word: if long { 2 } else { 4 },
        mask: (1u32 << (shift - 1)) - 1,
        len: (param & CLIST_LENGTH_MASK) as usize,
    }
}

/// Expand packed slots into node ids. `words[i]` is the response to
/// `GET_CONNECT_LIST` with payload `i * per_word`. A range marker expands the
/// span from the previous entry; a second zero entry ends the list, which is
/// how the reference tolerates one placeholder without running off the end.
/// # C: O(len + expanded entries)
pub fn expand(layout: &Layout, words: &[u32]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut previous: Option<u8> = None;
    let mut nulls = 0;
    for index in 0..layout.len {
        let Some(word) = words.get(index / layout.per_word) else { break; };
        let slot = (word >> (layout.shift * (index % layout.per_word) as u32)) & ((1u64 << layout.shift) - 1) as u32;
        let is_range = slot & (1 << (layout.shift - 1)) != 0;
        let value = (slot & layout.mask) as u8;
        if value == 0 {
            nulls += 1;
            if nulls > 1 { break; }
            continue;
        }
        if is_range {
            match previous {
                Some(start) if start < value => {
                    for nid in (start + 1)..=value { out.push(nid); }
                }
                // A range with no predecessor, or one running backwards, is
                // malformed: skip it rather than fabricating node ids.
                _ => {}
            }
        } else {
            out.push(value);
        }
        previous = Some(value);
    }
    out
}

/// Response payloads needed to read a list of `len` entries. # C: O(1)
pub fn word_count(layout: &Layout) -> usize {
    if layout.len <= 1 { usize::from(layout.len == 1) } else { layout.len.div_ceil(layout.per_word) }
}

#[cfg(test)]
#[path = "tests/connlist.rs"]
mod tests;
