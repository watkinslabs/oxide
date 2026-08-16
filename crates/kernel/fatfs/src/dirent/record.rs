//! The whole 32-byte short record, every field of it.
//!
//! [`ShortEntry`] is the part a reader needs to open a file: the name, the
//! attribute, the first cluster and the size. A record holds four more fields
//! that a WRITER cannot do without — the case bits, and three timestamps at
//! three different granularities — and rebuilding a record from the smaller
//! view alone destroys them.
//!
//! Composition rather than a second record type: a `Record` IS a
//! `ShortEntry` plus what the entry does not carry, so the two can never
//! disagree about the fields they share.

use crate::name::flags::{CASE_LOWER_BASE, CASE_LOWER_EXT};
use crate::time::FatTime;

use super::{parse, Entry, ShortEntry, ENTRY_BYTES};

/// Byte offsets of the fields a [`ShortEntry`] does not carry.
mod at {
    pub const LCASE: usize = 12;
    pub const CTIME_CS: usize = 13;
    pub const CTIME: usize = 14;
    pub const CDATE: usize = 16;
    pub const ADATE: usize = 18;
    pub const MTIME: usize = 22;
    pub const MDATE: usize = 24;
}

/// Where the parts of the record live that [`super::encode_short`] writes.
mod short_at {
    pub const NAME: usize = 0;
    pub const NAME_LEN: usize = 11;
    pub const ATTR: usize = 11;
    pub const CLUSTER_HI: usize = 20;
    pub const CLUSTER_LO: usize = 26;
    pub const SIZE: usize = 28;
}

/// The three readings one record carries.
///
/// They are not three copies of one clock: modification has two-second
/// granularity, creation adds a centisecond byte that reaches ten
/// milliseconds, and access has a date and no time at all. A field this
/// filesystem has no value for stays zero, which every reader takes as
/// "never".
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct RecordTimes {
    /// Creation, to ten milliseconds.
    pub create: FatTime,
    /// Access, as a date alone.
    pub access_date: u16,
    /// Modification, to two seconds. Its centisecond field is not stored and
    /// is always zero.
    pub modify: FatTime,
}

/// One short record, complete.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Record {
    pub short: ShortEntry,
    /// Which of the base and the extension were lowercase when written. The
    /// only record of a mixed-case 8.3 name that needs no long-name slots.
    pub lcase: u8,
    pub times: RecordTimes,
}

impl Record {
    /// Decode a record that a short entry occupies.
    ///
    /// `None` for anything that is not one — a free slot, the end of the
    /// directory, a long-name slot — so a caller cannot read timestamps out
    /// of thirteen characters of somebody's filename.
    /// # C: O(1)
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let Some(Entry::Short(short)) = parse(bytes) else { return None };
        Some(Self {
            lcase: bytes[at::LCASE],
            times: RecordTimes {
                create: FatTime {
                    time: le16(bytes, at::CTIME),
                    date: le16(bytes, at::CDATE),
                    cs: bytes[at::CTIME_CS],
                },
                access_date: le16(bytes, at::ADATE),
                modify: FatTime { time: le16(bytes, at::MTIME), date: le16(bytes, at::MDATE), cs: 0 },
            },
            short,
        })
    }

    /// Encode the record, all thirty-two bytes.
    ///
    /// Unlike [`super::encode_short`] this writes every field, so it is the
    /// only encoder safe to use on an entry that already exists: the other
    /// one leaves the timestamps and the case bits at zero, which reads back
    /// as a file created at the start of 1980 with an all-uppercase name.
    /// # C: O(1)
    pub fn encode(&self) -> [u8; ENTRY_BYTES] {
        let mut r = [0u8; ENTRY_BYTES];
        r[short_at::NAME..short_at::NAME + short_at::NAME_LEN]
            .copy_from_slice(&self.short.raw_name);
        r[short_at::ATTR] = self.short.attr;
        r[at::LCASE] = self.lcase;
        r[at::CTIME_CS] = self.times.create.cs;
        put16(&mut r, at::CTIME, self.times.create.time);
        put16(&mut r, at::CDATE, self.times.create.date);
        put16(&mut r, at::ADATE, self.times.access_date);
        put16(&mut r, at::MTIME, self.times.modify.time);
        put16(&mut r, at::MDATE, self.times.modify.date);
        put16(&mut r, short_at::CLUSTER_HI, (self.short.cluster >> 16) as u16);
        put16(&mut r, short_at::CLUSTER_LO, self.short.cluster as u16);
        r[short_at::SIZE..short_at::SIZE + 4].copy_from_slice(&self.short.size.to_le_bytes());
        r
    }

    /// Whether the base was written lowercase. # C: O(1)
    pub fn base_is_lower(&self) -> bool { self.lcase & CASE_LOWER_BASE != 0 }
    /// Whether the extension was written lowercase. # C: O(1)
    pub fn ext_is_lower(&self) -> bool { self.lcase & CASE_LOWER_EXT != 0 }
}

fn le16(b: &[u8], at: usize) -> u16 { u16::from_le_bytes([b[at], b[at + 1]]) }
fn put16(b: &mut [u8], at: usize, v: u16) { b[at..at + 2].copy_from_slice(&v.to_le_bytes()); }
