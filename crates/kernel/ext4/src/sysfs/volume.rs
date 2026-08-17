//! What one mount reports about the writing done to its volume.
//!
//! Two numbers, and the difference between them is the span they cover. The
//! session number is what THIS mount has written; the lifetime number is what
//! the volume has taken since it was made, which is why it starts from a count
//! the superblock carries and adds this mount's own.
//!
//! Both are counted at the device, not at the filesystem: a kilobyte of file
//! data can become several kilobytes on the medium once the journal, the
//! bitmaps and the inode table have had their share, and what a wear-watching
//! tool wants is what the medium took.
//!
//! A mount not on a registered disk has no counter behind it and reports its
//! own writes as zero. That is not a placeholder: there is no device object
//! accumulating them, so zero is what is known.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fsattr::{line_u64, Attr};
use crate::rootfs::RootfsState;

/// Two 512-byte sectors to the kilobyte the reports are counted in.
const SECTOR_TO_KB_SHIFT: u32 = 1;

/// Kilobytes written since the mount started, from the device's sector count
/// then and now.
///
/// Saturating: the counters are monotonic, but a device unregistered and
/// re-registered under this mount would restart its count, and a report that
/// wrapped to near 2^64 would be read as a catastrophic write volume.
/// # C: O(1)
pub fn session_kbytes(now_sectors: u64, start_sectors: u64) -> u64 {
    now_sectors.saturating_sub(start_sectors) >> SECTOR_TO_KB_SHIFT
}

/// Kilobytes written to the volume over its whole life: what the superblock
/// recorded when it was last updated, plus this mount's own. # C: O(1)
pub fn lifetime_kbytes(sb_kbytes: u64, session_kbytes: u64) -> u64 {
    sb_kbytes.saturating_add(session_kbytes)
}

/// This mount's write reports. # C: O(1)
pub fn attrs(st: &Arc<RootfsState>, dev: &str) -> Vec<Attr> {
    let session_st = Arc::clone(st);
    let lifetime_st = Arc::clone(st);
    alloc::vec![
        Attr::ro(dev, "session_write_kbytes",
                 Arc::new(move || Ok(line_u64(session_of(&session_st))))),
        Attr::ro(dev, "lifetime_write_kbytes", Arc::new(move || {
            Ok(line_u64(lifetime_kbytes(lifetime_st.mount.sb.kbytes_written,
                                        session_of(&lifetime_st))))
        })),
    ]
}

/// What this mount has written, now. # C: O(N disks)
fn session_of(st: &Arc<RootfsState>) -> u64 {
    session_kbytes(super::disk::sectors_written(&st.mount), st.wr_start)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sector is half a kilobyte, and the report is in kilobytes: a
    /// conversion the wrong way round reports twice or half the writing done.
    #[test]
    fn two_sectors_are_one_kilobyte() {
        assert_eq!(session_kbytes(2, 0), 1);
        assert_eq!(session_kbytes(2048, 1024), 512);
        assert_eq!(session_kbytes(1, 0), 0);
    }

    /// The session covers this mount only, so the count the device had when
    /// the mount started is not part of it.
    #[test]
    fn the_session_starts_where_the_mount_did() {
        assert_eq!(session_kbytes(5000, 5000), 0);
        assert_eq!(session_kbytes(5100, 5000), 50);
    }

    /// A device whose count restarted under a live mount must not report a
    /// write volume near the width of the counter.
    #[test]
    fn a_restarted_counter_reports_nothing_rather_than_everything() {
        assert_eq!(session_kbytes(10, 1_000_000), 0);
    }

    /// The lifetime number is the volume's, not the mount's: it begins from
    /// what the volume already carried.
    #[test]
    fn the_lifetime_includes_what_the_volume_already_carried() {
        assert_eq!(lifetime_kbytes(4096, 0), 4096);
        assert_eq!(lifetime_kbytes(4096, 100), 4196);
        assert_eq!(lifetime_kbytes(u64::MAX, 10), u64::MAX);
    }
}
