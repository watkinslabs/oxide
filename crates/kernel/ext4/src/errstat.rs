//! The volume's error history — what `errors_count`, `first_error_*` and
//! `last_error_*` answer from.
//!
//! The record is part of the on-disk superblock, not something a mount
//! invents: a volume carries the count and the first/last event across mounts
//! so a check, or an administrator reading the reports, sees a history rather
//! than what happened since the last boot. So a mount SEEDS its live record
//! from the superblock it just read, and every filesystem error this mount
//! finds is added to that seeded state.
//!
//! `first` is written once per volume and never overwritten while it holds an
//! event: the point of it is the FIRST thing that went wrong, which is what
//! names the cause. `last` is overwritten every time.
//!
//! The stored code is not an errno. It is a small enumeration of the error
//! kinds a filesystem reports, so a reader decodes one meaning per number
//! whatever the platform's errno values are.
//!
//! Deliberately free of any target gate: the record, its seeding and its
//! update rules are decisions, and they are answered here under `cargo test`.

use crate::dir::DirError;
use crate::{InodeError, MountError};

/// `s_error_count` byte offset in the superblock.
pub const SB_OFF_ERROR_COUNT:        usize = 0x194;
/// `s_first_error_time` (low 32 bits of a 40-bit seconds count).
pub const SB_OFF_FIRST_ERROR_TIME:   usize = 0x198;
pub const SB_OFF_FIRST_ERROR_INO:    usize = 0x19C;
pub const SB_OFF_FIRST_ERROR_BLOCK:  usize = 0x1A0;
pub const SB_OFF_LAST_ERROR_TIME:    usize = 0x1CC;
pub const SB_OFF_LAST_ERROR_INO:     usize = 0x1D0;
pub const SB_OFF_LAST_ERROR_BLOCK:   usize = 0x1D8;
/// High byte of the first/last error timestamps — seconds past 2106 live here.
pub const SB_OFF_FIRST_ERROR_TIME_HI: usize = 0x278;
pub const SB_OFF_LAST_ERROR_TIME_HI:  usize = 0x279;
pub const SB_OFF_FIRST_ERROR_ERRCODE: usize = 0x27A;
pub const SB_OFF_LAST_ERROR_ERRCODE:  usize = 0x27B;

/// The error kinds the on-disk record can name.
pub mod code {
    /// Something the reader has no name for.
    pub const UNKNOWN: u8 = 1;
    /// The device did not answer.
    pub const EIO: u8 = 2;
    pub const ENOMEM: u8 = 3;
    /// A stored checksum did not match the bytes it covers.
    pub const EFSBADCRC: u8 = 4;
    /// On-disk structure that cannot be what it claims to be.
    pub const EFSCORRUPTED: u8 = 5;
    pub const ENOSPC: u8 = 6;
    pub const ENOKEY: u8 = 7;
    pub const EROFS: u8 = 8;
    pub const EFBIG: u8 = 9;
    pub const EEXIST: u8 = 10;
    pub const ERANGE: u8 = 11;
    pub const EOVERFLOW: u8 = 12;
    pub const EBUSY: u8 = 13;
    pub const ENOTDIR: u8 = 14;
    pub const ENOTEMPTY: u8 = 15;
    pub const ESHUTDOWN: u8 = 16;
    pub const EFAULT: u8 = 17;
}

/// Which stored code names this error.
///
/// Only the errors that ARE filesystem errors reach the record, so anything
/// else answers with the code a reader reads as "the filesystem said its own
/// state was wrong" — the same default the record takes for an unnamed error.
/// # C: O(1)
pub fn code_for(e: &MountError) -> u8 {
    match e {
        MountError::BadChecksum => code::EFSBADCRC,
        MountError::BlockIo => code::EIO,
        MountError::CorruptExtentTree
        | MountError::Inode(InodeError::BadExtentMagic)
        | MountError::Inode(InodeError::TooManyExtents)
        | MountError::Superblock(_)
        | MountError::Gdt(_)
        | MountError::Dir(DirError::Short)
        | MountError::Dir(DirError::BadRecLen)
        | MountError::Dir(DirError::Overrun)
        | MountError::Dir(DirError::BadNameLen)
        | MountError::DoubleFree
        | MountError::BadBlock => code::EFSCORRUPTED,
        MountError::NoSpace => code::ENOSPC,
        _ => code::EFSCORRUPTED,
    }
}

/// One recorded error.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ErrEvent {
    /// Seconds since the epoch. Zero means no event: a filesystem error at
    /// second zero is not a case anything can distinguish, and the on-disk
    /// record uses the same test.
    pub time_secs: u64,
    /// The inode the error was found on, zero when the site did not name one.
    pub ino: u32,
    /// The block the error was found on, zero when the site did not name one.
    pub block: u64,
    /// One of [`code`].
    pub errcode: u8,
}

impl ErrEvent {
    /// Whether this slot holds an event at all. # C: O(1)
    pub fn is_set(&self) -> bool { self.time_secs != 0 }
}

/// A volume's whole error history.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ErrRecord {
    pub count: u32,
    pub first: ErrEvent,
    pub last:  ErrEvent,
}

#[inline] fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
#[inline] fn rd_u64(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}
/// A stored timestamp: 32 low bits beside a high byte, so the record does not
/// stop being readable in 2106. # C: O(1)
#[inline] fn rd_time(b: &[u8], lo: usize, hi: usize) -> u64 {
    (rd_u32(b, lo) as u64) | ((b[hi] as u64) << 32)
}

impl ErrRecord {
    /// Seed from the superblock bytes a mount just read.
    ///
    /// A slice too short to hold the record yields an empty history rather
    /// than a partial one: a count with no event beside it would report a
    /// volume as damaged with nothing to say about it.
    /// # C: O(1)
    pub fn parse(sb: &[u8]) -> ErrRecord {
        if sb.len() < SB_OFF_LAST_ERROR_ERRCODE + 1 { return ErrRecord::default(); }
        ErrRecord {
            count: rd_u32(sb, SB_OFF_ERROR_COUNT),
            first: ErrEvent {
                time_secs: rd_time(sb, SB_OFF_FIRST_ERROR_TIME, SB_OFF_FIRST_ERROR_TIME_HI),
                ino:       rd_u32(sb, SB_OFF_FIRST_ERROR_INO),
                block:     rd_u64(sb, SB_OFF_FIRST_ERROR_BLOCK),
                errcode:   sb[SB_OFF_FIRST_ERROR_ERRCODE],
            },
            last: ErrEvent {
                time_secs: rd_time(sb, SB_OFF_LAST_ERROR_TIME, SB_OFF_LAST_ERROR_TIME_HI),
                ino:       rd_u32(sb, SB_OFF_LAST_ERROR_INO),
                block:     rd_u64(sb, SB_OFF_LAST_ERROR_BLOCK),
                errcode:   sb[SB_OFF_LAST_ERROR_ERRCODE],
            },
        }
    }

    /// Add one filesystem error.
    ///
    /// `first` is filled only while it is empty — the volume's first error is
    /// the one that explains the rest, and overwriting it with the newest
    /// would lose exactly the event worth keeping.
    /// # C: O(1)
    pub fn record(&mut self, e: ErrEvent) {
        self.count = self.count.saturating_add(1);
        self.last = e;
        if !self.first.is_set() { self.first = e; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mount of a volume that has been damaged before must report that
    /// history, not a clean slate — the count and both events are on the disk
    /// precisely so they outlive the mount that recorded them.
    #[test]
    fn the_record_is_seeded_from_the_superblock() {
        let mut sb = alloc::vec![0u8; 1024];
        sb[SB_OFF_ERROR_COUNT..SB_OFF_ERROR_COUNT + 4].copy_from_slice(&7u32.to_le_bytes());
        sb[SB_OFF_FIRST_ERROR_TIME..SB_OFF_FIRST_ERROR_TIME + 4]
            .copy_from_slice(&1000u32.to_le_bytes());
        sb[SB_OFF_FIRST_ERROR_INO..SB_OFF_FIRST_ERROR_INO + 4].copy_from_slice(&12u32.to_le_bytes());
        sb[SB_OFF_FIRST_ERROR_BLOCK..SB_OFF_FIRST_ERROR_BLOCK + 8]
            .copy_from_slice(&99u64.to_le_bytes());
        sb[SB_OFF_FIRST_ERROR_ERRCODE] = code::EFSBADCRC;
        sb[SB_OFF_LAST_ERROR_TIME..SB_OFF_LAST_ERROR_TIME + 4]
            .copy_from_slice(&2000u32.to_le_bytes());
        sb[SB_OFF_LAST_ERROR_ERRCODE] = code::EIO;
        let r = ErrRecord::parse(&sb);
        assert_eq!(r.count, 7);
        assert_eq!(r.first, ErrEvent { time_secs: 1000, ino: 12, block: 99,
                                       errcode: code::EFSBADCRC });
        assert_eq!(r.last.time_secs, 2000);
        assert_eq!(r.last.errcode, code::EIO);
    }

    /// The timestamps are wider than 32 bits on disk, and a report that
    /// dropped the high byte would put an error in 2106 back in 1970.
    #[test]
    fn a_timestamp_carries_its_high_byte() {
        let mut sb = alloc::vec![0u8; 1024];
        sb[SB_OFF_LAST_ERROR_TIME..SB_OFF_LAST_ERROR_TIME + 4].copy_from_slice(&5u32.to_le_bytes());
        sb[SB_OFF_LAST_ERROR_TIME_HI] = 1;
        assert_eq!(ErrRecord::parse(&sb).last.time_secs, (1u64 << 32) + 5);
    }

    /// A volume with no history reports none — a zero timestamp is the record
    /// saying the slot is empty, and a reader tests exactly that.
    #[test]
    fn an_unrecorded_event_is_not_set() {
        let r = ErrRecord::parse(&alloc::vec![0u8; 1024]);
        assert_eq!(r.count, 0);
        assert!(!r.first.is_set());
        assert!(!r.last.is_set());
    }

    #[test]
    fn a_short_slice_yields_an_empty_history() {
        assert_eq!(ErrRecord::parse(&[0u8; 16]), ErrRecord::default());
    }

    /// The first event names the cause; the last names what is happening now.
    /// Overwriting the first would leave only the symptom.
    #[test]
    fn the_first_event_survives_later_ones() {
        let mut r = ErrRecord::default();
        let a = ErrEvent { time_secs: 10, ino: 0, block: 0, errcode: code::EFSCORRUPTED };
        let b = ErrEvent { time_secs: 20, ino: 0, block: 0, errcode: code::EIO };
        r.record(a);
        r.record(b);
        assert_eq!(r.count, 2);
        assert_eq!(r.first, a);
        assert_eq!(r.last, b);
    }

    /// A record seeded from a damaged volume already holds a first event, so
    /// this mount's own errors extend the history instead of restarting it.
    #[test]
    fn a_seeded_first_event_is_not_replaced() {
        let mut sb = alloc::vec![0u8; 1024];
        sb[SB_OFF_ERROR_COUNT..SB_OFF_ERROR_COUNT + 4].copy_from_slice(&3u32.to_le_bytes());
        sb[SB_OFF_FIRST_ERROR_TIME..SB_OFF_FIRST_ERROR_TIME + 4]
            .copy_from_slice(&500u32.to_le_bytes());
        let mut r = ErrRecord::parse(&sb);
        r.record(ErrEvent { time_secs: 900, ino: 0, block: 0, errcode: code::EIO });
        assert_eq!(r.count, 4);
        assert_eq!(r.first.time_secs, 500);
        assert_eq!(r.last.time_secs, 900);
    }

    /// The stored code is an enumeration of error KINDS. A checksum failure
    /// and a device that will not answer are different things to whoever reads
    /// the report, and collapsing them loses the distinction that decides
    /// whether the disk or the metadata is the suspect.
    #[test]
    fn each_error_kind_has_its_own_code() {
        assert_eq!(code_for(&MountError::BadChecksum), code::EFSBADCRC);
        assert_eq!(code_for(&MountError::BlockIo), code::EIO);
        assert_eq!(code_for(&MountError::CorruptExtentTree), code::EFSCORRUPTED);
        assert_eq!(code_for(&MountError::Dir(DirError::BadRecLen)), code::EFSCORRUPTED);
        assert_eq!(code_for(&MountError::DoubleFree), code::EFSCORRUPTED);
        assert_eq!(code_for(&MountError::NoSpace), code::ENOSPC);
    }
}
