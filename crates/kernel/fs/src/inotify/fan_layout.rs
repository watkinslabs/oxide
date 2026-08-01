// fanotify READ-SIDE wire layout: `struct fanotify_event_metadata` and the
// variable `fanotify_event_info_*` records a FID-mode group reports after it.
//
// Deliberately free of any target gate so the record sizes, padding, and
// info-type selection are hosted-testable; `group.rs` only sequences these.

/// `FAN_EVENT_METADATA_LEN` — `struct fanotify_event_metadata`:
/// `{event_len u32, vers u8, reserved u8, metadata_len u16, mask u64, fd i32, pid i32}`.
pub(crate) const FAN_EVENT_METADATA_LEN: usize = 24;
/// `FANOTIFY_METADATA_VERSION`.
pub(crate) const FANOTIFY_METADATA_VERSION: u8 = 3;
/// `FAN_NOFD` — no descriptor accompanies this event.
pub(crate) const FAN_NOFD: i32 = -1;
/// `FAN_NOPIDFD` — the group asked for a pidfd but the process is already gone.
pub(crate) const FAN_NOPIDFD: i32 = FAN_NOFD;
/// `FAN_EPIDFD` — the group asked for a pidfd and minting one failed. Distinct
/// from `FAN_NOPIDFD`, which means the process itself is gone.
pub(crate) const FAN_EPIDFD: i32 = -2;

/// `FAN_EVENT_INFO_TYPE_FID` — the fid of the object the event happened to.
pub(crate) const FAN_EVENT_INFO_TYPE_FID: u8 = 1;
/// `FAN_EVENT_INFO_TYPE_DFID_NAME` — a directory fid plus the entry's name.
pub(crate) const FAN_EVENT_INFO_TYPE_DFID_NAME: u8 = 2;
/// `FAN_EVENT_INFO_TYPE_DFID` — a directory fid alone.
pub(crate) const FAN_EVENT_INFO_TYPE_DFID: u8 = 3;

/// `FAN_EVENT_INFO_TYPE_PIDFD` — a descriptor for the process the event is
/// reported for.
pub(crate) const FAN_EVENT_INFO_TYPE_PIDFD: u8 = 4;

/// `FANOTIFY_EVENT_ALIGN` — every info record is padded out to this.
const FAN_EVENT_ALIGN: usize = 4;
/// `sizeof(struct fanotify_event_info_header)`: `{info_type u8, pad u8, len u16}`.
const INFO_HDR_LEN: usize = 4;
/// `sizeof(struct fanotify_event_info_pidfd)`: the shared header plus one
/// `__s32 pidfd`. Already a multiple of the record alignment.
pub(crate) const PIDFD_INFO_LEN: usize = INFO_HDR_LEN + 4;
/// `sizeof(struct fanotify_event_info_fid)`: a 4-byte
/// `fanotify_event_info_header {info_type u8, pad u8, len u16}` followed by the
/// 8-byte `__kernel_fsid_t`.
const FID_INFO_FIXED: usize = 12;
/// `sizeof(struct file_handle)` without its trailing `f_handle[]`:
/// `{handle_bytes u32, handle_type i32}`.
const FILE_HANDLE_HDR: usize = 8;
/// `FANOTIFY_FID_INFO_HDR_LEN`.
const FID_INFO_HDR_LEN: usize = FID_INFO_FIXED + FILE_HANDLE_HDR;

/// The `handle_type` a fid info record carries. It MUST be the type
/// `open_by_handle_at` decodes: a `FAN_REPORT_FID` watcher's whole use for the
/// record is to open the object it names, and a second private encoding here
/// would hand it a handle this kernel cannot decode.
pub(crate) const FANOTIFY_FID_TYPE: i32 = vfs::export::fid::HANDLE_TYPE_INO_GEN;
/// Bytes such a handle occupies.
pub(crate) const FANOTIFY_FID_LEN: usize = vfs::export::fid::FID_LEN as usize;

/// Linux `fanotify_fid_info_len`: the fixed header, the file handle, the name
/// with its terminating NUL when one is present, rounded up to the record
/// alignment. # C: O(1)
pub(crate) fn fid_info_len(fh_len: usize, name_len: usize) -> usize {
    let mut n = fh_len;
    if name_len != 0 { n += name_len + 1; }
    (FID_INFO_HDR_LEN + n).div_ceil(FAN_EVENT_ALIGN) * FAN_EVENT_ALIGN
}

/// Which info record — if any — a group reports for one event, given the
/// group's `FAN_REPORT_*` flag set and whether the event names a directory
/// entry.
///
/// Linux threads three independent choices together here:
///   * a group with NO fid bits is a legacy fd-reporting group and emits bare
///     metadata;
///   * a NAMED event (one reported on a watched directory about an entry inside
///     it) carries the DIRECTORY's fid, as `DFID_NAME` when the group also asked
///     for `FAN_REPORT_NAME` and plain `DFID` otherwise;
///   * an unnamed event carries the affected object's own fid as `FID`, or
///     falls back to `DFID` for a `FAN_REPORT_DIR_FID`-only group, which never
///     asked for object fids at all.
/// # C: O(1)
pub(crate) fn info_type_for(report_fid: bool, report_dir_fid: bool, report_name: bool,
                            named: bool) -> Option<u8> {
    if !report_fid && !report_dir_fid { return None; }
    if named && report_dir_fid {
        return Some(if report_name { FAN_EVENT_INFO_TYPE_DFID_NAME } else { FAN_EVENT_INFO_TYPE_DFID });
    }
    if report_fid { return Some(FAN_EVENT_INFO_TYPE_FID); }
    Some(FAN_EVENT_INFO_TYPE_DFID)
}

/// Name bytes that ride along with `info_type`. Only the two `*_NAME` types
/// carry one; `copy_fid_info_to_user` rejects a name on any other type.
/// # C: O(1)
pub(crate) fn name_len_for(info_type: u8, name_len: usize) -> usize {
    if info_type == FAN_EVENT_INFO_TYPE_DFID_NAME { name_len } else { 0 }
}

/// `metadata.event_len` — the fixed metadata plus whatever info record follows.
/// # C: O(1)
pub(crate) fn event_len(info_type: Option<u8>, fh_len: usize, name_len: usize) -> usize {
    match info_type {
        None => FAN_EVENT_METADATA_LEN,
        Some(t) => FAN_EVENT_METADATA_LEN + fid_info_len(fh_len, name_len_for(t, name_len)),
    }
}

/// Encode `struct fanotify_event_metadata`. `mask` is written as the 64-bit
/// field it is; `fd` and `pid` are signed. # C: O(1)
pub(crate) fn encode_metadata(dst: &mut [u8], event_len: usize, mask: u32, fd: i32, pid: u32) {
    dst[0..4].copy_from_slice(&(event_len as u32).to_le_bytes());
    dst[4] = FANOTIFY_METADATA_VERSION;
    dst[5] = 0;
    dst[6..8].copy_from_slice(&(FAN_EVENT_METADATA_LEN as u16).to_le_bytes());
    dst[8..16].copy_from_slice(&(mask as u64).to_le_bytes());
    dst[16..20].copy_from_slice(&fd.to_le_bytes());
    dst[20..24].copy_from_slice(&(pid as i32).to_le_bytes());
}

/// `__kernel_fsid_t` for a superblock's `s_dev`: the two halves of the device
/// number, as the two `int`s the type is defined as. # C: O(1)
pub(crate) fn fsid_words(s_dev: u64) -> [u32; 2] { [s_dev as u32, (s_dev >> 32) as u32] }

/// Encode one `fanotify_event_info_fid` — header, fsid, `struct file_handle`,
/// the handle bytes, an optional NUL-terminated name — zero-filling the tail
/// out to the record's aligned length. Returns the bytes written, or 0 when
/// `dst` cannot hold the whole record (a reader never sees a partial record).
/// # C: O(name.len())
pub(crate) fn encode_fid_info(dst: &mut [u8], info_type: u8, s_dev: u64,
                              fh_type: i32, fh: &[u8], name: &[u8]) -> usize {
    let name_len = name_len_for(info_type, name.len());
    let total = fid_info_len(fh.len(), name_len);
    if dst.len() < total { return 0; }
    let f = fsid_words(s_dev);
    dst[0] = info_type;
    dst[1] = 0;
    dst[2..4].copy_from_slice(&(total as u16).to_le_bytes());
    dst[4..8].copy_from_slice(&f[0].to_le_bytes());
    dst[8..12].copy_from_slice(&f[1].to_le_bytes());
    dst[12..16].copy_from_slice(&(fh.len() as u32).to_le_bytes());
    dst[16..20].copy_from_slice(&fh_type.to_le_bytes());
    let mut off = FID_INFO_HDR_LEN;
    dst[off..off + fh.len()].copy_from_slice(fh);
    off += fh.len();
    if name_len != 0 {
        dst[off..off + name_len].copy_from_slice(&name[..name_len]);
        off += name_len;
        dst[off] = 0;
        off += 1;
    }
    for b in dst[off..total].iter_mut() { *b = 0; }
    total
}

/// Encode one `fanotify_event_info_pidfd`. Returns the bytes written, or 0
/// when `dst` cannot hold the whole record. # C: O(1)
pub(crate) fn encode_pidfd_info(dst: &mut [u8], pidfd: i32) -> usize {
    if dst.len() < PIDFD_INFO_LEN { return 0; }
    dst[0] = FAN_EVENT_INFO_TYPE_PIDFD;
    dst[1] = 0;
    dst[2..4].copy_from_slice(&(PIDFD_INFO_LEN as u16).to_le_bytes());
    dst[4..8].copy_from_slice(&pidfd.to_le_bytes());
    PIDFD_INFO_LEN
}

/// The handle bytes for an inode, produced by the SAME codec
/// `name_to_handle_at` uses, so a reported fid round-trips through
/// `open_by_handle_at`. # C: O(1)
pub(crate) fn fid_handle(ino: u64, generation: u32) -> [u8; FANOTIFY_FID_LEN] {
    let mut buf = [0u8; vfs::export::fid::FID_LEN_PARENT as usize];
    let fid = vfs::export::fid::Fid { ino, generation, parent: None };
    let (len, _) = vfs::export::fid::encode_fid(&fid, &mut buf);
    debug_assert!(len as usize == FANOTIFY_FID_LEN);
    let mut h = [0u8; FANOTIFY_FID_LEN];
    h.copy_from_slice(&buf[..FANOTIFY_FID_LEN]);
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_legacy_group_reports_bare_metadata() {
        assert_eq!(info_type_for(false, false, false, false), None);
        assert_eq!(info_type_for(false, false, true, true), None, "NAME alone is not a fid mode");
        assert_eq!(event_len(None, 8, 5), FAN_EVENT_METADATA_LEN);
    }

    #[test]
    fn info_type_selection_matches_the_report_flag_matrix() {
        // FAN_REPORT_FID alone: object fid, even for a named event — the group
        // never asked for directory fids.
        assert_eq!(info_type_for(true, false, false, false), Some(FAN_EVENT_INFO_TYPE_FID));
        assert_eq!(info_type_for(true, false, false, true), Some(FAN_EVENT_INFO_TYPE_FID));
        // FAN_REPORT_DIR_FID: named events become directory fids.
        assert_eq!(info_type_for(false, true, false, true), Some(FAN_EVENT_INFO_TYPE_DFID));
        assert_eq!(info_type_for(false, true, true, true), Some(FAN_EVENT_INFO_TYPE_DFID_NAME));
        // ... and an unnamed event under DIR_FID-only still reports a dir fid.
        assert_eq!(info_type_for(false, true, true, false), Some(FAN_EVENT_INFO_TYPE_DFID));
        // Both bits: the named event prefers the directory record.
        assert_eq!(info_type_for(true, true, true, true), Some(FAN_EVENT_INFO_TYPE_DFID_NAME));
        assert_eq!(info_type_for(true, true, true, false), Some(FAN_EVENT_INFO_TYPE_FID));
    }

    #[test]
    fn only_the_name_types_carry_a_name() {
        assert_eq!(name_len_for(FAN_EVENT_INFO_TYPE_DFID_NAME, 4), 4);
        assert_eq!(name_len_for(FAN_EVENT_INFO_TYPE_DFID, 4), 0);
        assert_eq!(name_len_for(FAN_EVENT_INFO_TYPE_FID, 4), 0);
    }

    #[test]
    fn fid_info_len_rounds_the_whole_record_to_the_alignment() {
        // 12-byte fixed part + 8-byte file_handle header = 20, already aligned.
        assert_eq!(fid_info_len(0, 0), 20);
        assert_eq!(fid_info_len(8, 0), 28, "a FANOTIFY_FID_TYPE handle stays aligned");
        // name + NUL is included BEFORE the rounding.
        assert_eq!(fid_info_len(8, 1), 32, "20+8+2 = 30 rounds to 32");
        assert_eq!(fid_info_len(8, 3), 32, "20+8+4 = 32 exactly");
        assert_eq!(fid_info_len(8, 4), 36, "20+8+5 = 33 rounds to 36");
    }

    #[test]
    fn encoded_fid_record_lays_out_header_fsid_handle_then_name() {
        let mut buf = [0xAAu8; 64];
        let fh = fid_handle(0x1234_5678, 9);
        let n = encode_fid_info(&mut buf, FAN_EVENT_INFO_TYPE_DFID_NAME,
                                0x0000_0007_0000_0035, FANOTIFY_FID_TYPE, &fh, b"abc");
        let want = fid_info_len(FANOTIFY_FID_LEN, 3);
        assert_eq!(n, want);
        assert_eq!(buf[0], FAN_EVENT_INFO_TYPE_DFID_NAME);
        assert_eq!(buf[1], 0, "pad byte is zero");
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), want as u16, "hdr.len is the PADDED record length");
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 0x35);
        assert_eq!(u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]), 7);
        assert_eq!(u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
                   FANOTIFY_FID_LEN as u32, "handle_bytes");
        assert_eq!(i32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]), FANOTIFY_FID_TYPE);
        let nm = 20 + FANOTIFY_FID_LEN;
        assert_eq!(&buf[20..nm], &fh);
        assert_eq!(&buf[nm..nm + 3], b"abc");
        assert_eq!(buf[nm + 3], 0, "name is NUL-terminated inside the padding");
    }

    #[test]
    fn a_nameless_type_drops_the_name_it_was_handed() {
        let mut buf = [0xAAu8; 64];
        let fh = fid_handle(1, 0);
        let n = encode_fid_info(&mut buf, FAN_EVENT_INFO_TYPE_FID, 1, FANOTIFY_FID_TYPE, &fh, b"ignored");
        assert_eq!(n, fid_info_len(FANOTIFY_FID_LEN, 0), "no name tail");
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), n as u16);
    }

    #[test]
    fn encode_refuses_to_write_a_partial_record() {
        let mut buf = [0xAAu8; 20];
        let fh = fid_handle(1, 0);
        assert_eq!(encode_fid_info(&mut buf, FAN_EVENT_INFO_TYPE_FID, 1, FANOTIFY_FID_TYPE, &fh, b""), 0);
        assert_eq!(buf, [0xAAu8; 20], "nothing written");
    }

    #[test]
    fn metadata_header_fields_are_at_the_linux_offsets() {
        let mut buf = [0xAAu8; FAN_EVENT_METADATA_LEN];
        encode_metadata(&mut buf, 52, 0x20, FAN_NOFD, 4242);
        assert_eq!(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 52);
        assert_eq!(buf[4], FANOTIFY_METADATA_VERSION);
        assert_eq!(buf[5], 0);
        assert_eq!(u16::from_le_bytes([buf[6], buf[7]]), FAN_EVENT_METADATA_LEN as u16);
        assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), 0x20);
        assert_eq!(i32::from_le_bytes(buf[16..20].try_into().unwrap()), FAN_NOFD);
        assert_eq!(i32::from_le_bytes(buf[20..24].try_into().unwrap()), 4242);
    }

    /// The pidfd record is a bare header plus the descriptor, and its two
    /// failure descriptors are distinct values userspace can tell apart.
    /// # C: O(1)
    #[test]
    fn pidfd_record_carries_the_descriptor_after_the_header() {
        let mut buf = [0xAAu8; 16];
        assert_eq!(encode_pidfd_info(&mut buf, 9), PIDFD_INFO_LEN);
        assert_eq!(buf[0], FAN_EVENT_INFO_TYPE_PIDFD);
        assert_eq!(buf[1], 0);
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), PIDFD_INFO_LEN as u16);
        assert_eq!(i32::from_le_bytes(buf[4..8].try_into().unwrap()), 9);
        assert_ne!(FAN_EPIDFD, FAN_NOPIDFD, "a failed mint is not a dead process");
        assert_eq!(encode_pidfd_info(&mut buf[..7], 1), 0, "no partial record");
    }

    #[test]
    fn event_len_adds_exactly_one_info_record() {
        assert_eq!(event_len(Some(FAN_EVENT_INFO_TYPE_FID), 8, 0), 24 + 28);
        assert_eq!(event_len(Some(FAN_EVENT_INFO_TYPE_DFID_NAME), 8, 3), 24 + 32);
        assert_eq!(event_len(Some(FAN_EVENT_INFO_TYPE_DFID), 8, 3), 24 + 28,
                   "a nameless type does not pay for the name");
    }
}
