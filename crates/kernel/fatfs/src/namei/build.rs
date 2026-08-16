//! The records one new name occupies, in the order they are written.
//!
//! A name becomes between one and twenty-one records. The last of them is the
//! short entry, which is the file; the ones before it carry the long name in
//! reverse and exist only to be found again. They are returned as one group
//! because they must be WRITTEN as one: a short entry published before its
//! slots is a file under its alias, and slots published before their short
//! entry are a run pointing at whatever occupied that slot last.
//!
//! Which of the two shapes a name gets is not this module's decision — it is
//! `name::shortgen`'s, and it depends on the directory's existing names, which
//! is why a predicate over them is a parameter here.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::dirent::{checksum, Record, RecordTimes, ShortEntry, ATTR_ARCH, ATTR_DIR, ATTR_HIDDEN,
                    ENTRY_BYTES};
use crate::name::compare::{striptail, validate};
use crate::name::flags::SHORT_NAME_LEN;
use crate::name::{lfn, msdos, shortgen};
use crate::opts::Options;
use crate::time::FatTime;

/// The records one name occupies, together with what the short one turned out
/// to be.
pub struct Group {
    /// Long-name slots first, short entry last. Always at least one.
    pub records: Vec<[u8; ENTRY_BYTES]>,
    /// The eleven bytes the short entry carries, which the checksum in every
    /// slot is taken over.
    pub raw_name: [u8; SHORT_NAME_LEN],
    /// The case bits the short entry carries.
    pub lcase: u8,
}

impl Group {
    /// Records this group occupies. # C: O(1)
    pub fn slots(&self) -> usize { self.records.len() }

    /// Offset of the SHORT record when the group begins at `at`. # C: O(1)
    pub fn short_offset(&self, at: u64) -> u64 {
        at + ((self.slots() - 1) * ENTRY_BYTES) as u64
    }

    /// The short record, still encoded. # C: O(1)
    pub fn short_record(&self) -> &[u8; ENTRY_BYTES] { &self.records[self.slots() - 1] }
}

/// Build the group for `name`.
///
/// `exists` answers whether the directory already holds an entry with a given
/// eleven bytes; `seed` starts the hashed-tail search, and any value works.
/// `when` is the instant every timestamp on the new entry is taken from — one
/// reading, not three, so a file's creation and modification times agree.
/// # C: O(name length + tail attempts)
pub fn build_group(name: &str, is_dir: bool, cluster: u32, when: FatTime, o: &Options, seed: u32,
                   exists: &mut dyn FnMut(&[u8; SHORT_NAME_LEN]) -> bool)
                   -> Result<Group, Errno> {
    if o.long_names { long(name, is_dir, cluster, when, o, seed, exists) }
    else { short_only(name, is_dir, cluster, when, o) }
}

/// A name on a mount that stores long names. # C: O(name length)
fn long(name: &str, is_dir: bool, cluster: u32, when: FatTime, o: &Options, seed: u32,
        exists: &mut dyn FnMut(&[u8; SHORT_NAME_LEN]) -> bool) -> Result<Group, Errno> {
    // Trailing dots are not part of a name here, and a name that is nothing
    // but dots is no name at all.
    let name = striptail(name);
    validate(name)?;
    let units: Vec<u16> = name.encode_utf16().collect();
    let generated = shortgen::create(&units, o.codepage, o.shortname, o.numtail, seed, exists)?;
    let raw_name = *generated.bytes();
    let (lcase, aliased) = match generated {
        shortgen::ShortName::Alone { lcase, .. } => (lcase, false),
        shortgen::ShortName::Aliased { .. } => (0, true),
    };

    let mut records = Vec::new();
    if aliased {
        let encoded = lfn::encode(name)?;
        records = lfn::build_slots(&encoded, checksum(&raw_name));
    }
    records.push(entry(raw_name, lcase, is_dir, cluster, times(when, true)));
    Ok(Group { records, raw_name, lcase })
}

/// A name on a mount that stores nothing but the eleven bytes.
///
/// A leading dot is not stored as a character: it becomes the HIDDEN
/// attribute, which is the convention this filesystem type predates POSIX
/// with. The attribute is set only when the dot actually disappeared, so a
/// mount that refuses leading dots never produces a hidden entry by accident.
/// # C: O(name length)
fn short_only(name: &str, is_dir: bool, cluster: u32, when: FatTime, o: &Options)
    -> Result<Group, Errno> {
    let raw_name = msdos::format_name(name.as_bytes(), &o.short_rules())?;
    let hidden = name.starts_with('.') && raw_name[0] != b'.';
    let mut record = entry(raw_name, 0, is_dir, cluster, times(when, false));
    if hidden { record[ATTR_AT] |= ATTR_HIDDEN; }
    Ok(Group { records: alloc::vec![record], raw_name, lcase: 0 })
}

/// Where the attribute byte sits in a record.
const ATTR_AT: usize = 11;

/// The three readings a new entry carries.
///
/// An 8.3-only mount writes NONE of the extra fields: creation and access
/// belong to the long-name format, and a machine that reads only 8.3 names
/// treats those bytes as reserved. Writing them would put values in a field
/// such a reader may use for something else.
/// # C: O(1)
fn times(when: FatTime, extras: bool) -> RecordTimes {
    let modify = FatTime { time: when.time, date: when.date, cs: 0 };
    if !extras { return RecordTimes { create: FatTime::default(), access_date: 0, modify }; }
    RecordTimes { create: when, access_date: when.date, modify }
}

/// One short entry, encoded. A new entry has no bytes, whatever it names.
/// # C: O(1)
fn entry(raw_name: [u8; SHORT_NAME_LEN], lcase: u8, is_dir: bool, cluster: u32,
         times: RecordTimes) -> [u8; ENTRY_BYTES] {
    Record {
        short: ShortEntry {
            raw_name,
            attr: if is_dir { ATTR_DIR } else { ATTR_ARCH },
            cluster,
            size: 0,
        },
        lcase,
        times,
    }.encode()
}
