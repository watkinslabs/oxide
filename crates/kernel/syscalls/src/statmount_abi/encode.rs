// `struct statmount` writer: the fixed 512-byte record plus the variable
// string area that follows it.
//
// Two properties are the whole point and both are silent ABI breaks when wrong:
// a field is written ONLY if the caller asked for it, and a written field ALWAYS
// raises its mask bit. A field written without its bit is invisible to the
// caller; a bit raised without the field makes it read uninitialised memory.

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use syscall::errno::Errno;

use super::*;

/// Size of the fixed part of `struct statmount`; the string area starts here.
pub const SM_SIZE: usize = 512;

// Field byte-offsets within the fixed part.
const OFF_SIZE:              usize = 0;
const OFF_MNT_OPTS:          usize = 4;
const OFF_MASK:              usize = 8;
const OFF_SB_DEV_MAJOR:      usize = 16;
const OFF_SB_DEV_MINOR:      usize = 20;
const OFF_SB_MAGIC:          usize = 24;
const OFF_SB_FLAGS:          usize = 32;
const OFF_FS_TYPE:           usize = 36;
const OFF_MNT_ID:            usize = 40;
const OFF_MNT_PARENT_ID:     usize = 48;
const OFF_MNT_ID_OLD:        usize = 56;
const OFF_MNT_PARENT_ID_OLD: usize = 60;
const OFF_MNT_ATTR:          usize = 64;
const OFF_MNT_PROPAGATION:   usize = 72;
const OFF_MNT_PEER_GROUP:    usize = 80;
const OFF_MNT_MASTER:        usize = 88;
const OFF_PROPAGATE_FROM:    usize = 96;
const OFF_MNT_ROOT:          usize = 104;
const OFF_MNT_POINT:         usize = 108;
const OFF_MNT_NS_ID:         usize = 112;
const OFF_FS_SUBTYPE:        usize = 120;
const OFF_SB_SOURCE:         usize = 124;
const OFF_OPT_NUM:           usize = 128;
const OFF_OPT_ARRAY:         usize = 132;
const OFF_OPT_SEC_NUM:       usize = 136;
const OFF_OPT_SEC_ARRAY:     usize = 140;
const OFF_SUPPORTED_MASK:    usize = 144;
const OFF_MNT_UIDMAP_NUM:    usize = 152;
const OFF_MNT_UIDMAP:        usize = 156;
const OFF_MNT_GIDMAP_NUM:    usize = 160;
const OFF_MNT_GIDMAP:        usize = 164;

const U32: usize = 4;
const U64: usize = 8;

/// One id-mapping row as `statmount` reports it: the id inside the mount, the
/// same id resolved in the CALLER's user namespace, and the range length.
pub type IdMapRow = (u32, u32, u32);

/// Everything one `statmount` reply can contain, already resolved into the
/// caller's frame of reference. Plain data so the encoder is a pure function of
/// it and the requested mask.
#[derive(Default, Clone)]
pub struct StatmountRecord {
    pub mnt_id: u64,
    pub mnt_parent_id: u64,
    pub mnt_id_old: u32,
    pub mnt_parent_id_old: u32,
    pub mnt_attr: u64,
    pub mnt_propagation: u64,
    pub mnt_peer_group: u64,
    pub mnt_master: u64,
    /// Dominating peer group; meaningful only for a slave mount.
    pub propagate_from: u64,
    pub sb_dev_major: u32,
    pub sb_dev_minor: u32,
    pub sb_magic: u64,
    pub sb_flags: u32,
    pub mnt_ns_id: u64,
    pub fs_type: String,
    pub mnt_root: String,
    /// `None` when the mount is not under the caller's root, which makes the
    /// field ABSENT rather than empty.
    pub mnt_point: Option<String>,
    pub mnt_opts: String,
    pub sb_source: String,
    pub fs_subtype: String,
    pub opt_array: Vec<String>,
    pub opt_sec_array: Vec<String>,
    /// The mount carries a non-identity idmap. The uid/gid map fields are
    /// reported only then — and are reported even if no row survives
    /// translation, so a caller can tell "not idmapped" from "idmapped, but
    /// nothing visible from here".
    pub idmapped: bool,
    pub uid_map: Vec<IdMapRow>,
    pub gid_map: Vec<IdMapRow>,
}

/// Accumulates the string area and the offsets into it.
struct Strings { buf: Vec<u8>, bufsize: usize }

impl Strings {
    fn new(bufsize: usize) -> Self { Strings { buf: Vec::new(), bufsize } }

    /// Append one NUL-terminated string and return its offset, or `None` when
    /// the content was empty (an empty field is ABSENT, not an empty string —
    /// its mask bit stays clear and its offset stays `0`). # C: O(len)
    fn put(&mut self, content: &[u8]) -> Result<Option<u32>, Errno> {
        // A leading empty string so every unset offset (`0`) reads as "".
        if self.buf.is_empty() { self.buf.push(0); }
        let start = self.buf.len();
        self.buf.extend_from_slice(content);
        if self.buf.len() == start { return Ok(None); }
        if SM_SIZE + self.buf.len() >= self.bufsize { return Err(Errno::Eoverflow); }
        self.buf.push(0);
        Ok(Some(start as u32))
    }
}

/// NUL-separated option blob plus its element count — the `opt_array` /
/// `opt_sec_array` shape. # C: O(total len)
fn opt_blob(opts: &[String]) -> (Vec<u8>, u32) {
    let mut out = Vec::new();
    for (i, o) in opts.iter().enumerate() {
        if i != 0 { out.push(0); }
        out.extend_from_slice(o.as_bytes());
    }
    (out, opts.len() as u32)
}

/// `"<first> <lower> <count>"` rows, each NUL-terminated (so the blob ends in a
/// NUL of its own, before the terminator the string area adds). # C: O(rows)
fn idmap_blob(rows: &[IdMapRow]) -> Vec<u8> {
    let mut out = Vec::new();
    for (first, lower, count) in rows {
        out.extend_from_slice(format!("{} {} {}", first, lower, count).as_bytes());
        out.push(0);
    }
    out
}

/// Encode a `statmount` reply for the requested mask. Returns the bytes to
/// copy to the caller's buffer, starting at its base: the fixed part (truncated
/// to `bufsize` when the caller asked for no strings and passed a short buffer)
/// followed by the string area at offset [`SM_SIZE`].
/// # C: O(fields + total string len)
pub fn encode_statmount(r: &StatmountRecord, want: u64, bufsize: usize) -> Result<Vec<u8>, Errno> {
    // A string request needs room BEYOND the fixed part; a buffer exactly that
    // size can never hold one. A SHORTER buffer is not rejected here — a
    // requested field that turns out to be empty emits nothing, and that call
    // still succeeds with a truncated fixed part.
    if want & STATMOUNT_STRING_REQ != 0 && bufsize == SM_SIZE { return Err(Errno::Eoverflow); }

    let mut h = [0u8; SM_SIZE];
    let mut mask = 0u64;
    let mut s = Strings::new(bufsize);
    let put_u32 = |h: &mut [u8; SM_SIZE], off: usize, v: u32| {
        h[off..off + U32].copy_from_slice(&v.to_le_bytes());
    };
    let put_u64 = |h: &mut [u8; SM_SIZE], off: usize, v: u64| {
        h[off..off + U64].copy_from_slice(&v.to_le_bytes());
    };

    if want & STATMOUNT_MNT_BASIC != 0 {
        mask |= STATMOUNT_MNT_BASIC;
        put_u64(&mut h, OFF_MNT_ID, r.mnt_id);
        put_u64(&mut h, OFF_MNT_PARENT_ID, r.mnt_parent_id);
        put_u32(&mut h, OFF_MNT_ID_OLD, r.mnt_id_old);
        put_u32(&mut h, OFF_MNT_PARENT_ID_OLD, r.mnt_parent_id_old);
        put_u64(&mut h, OFF_MNT_ATTR, r.mnt_attr);
        put_u64(&mut h, OFF_MNT_PROPAGATION, r.mnt_propagation);
        put_u64(&mut h, OFF_MNT_PEER_GROUP, r.mnt_peer_group);
        put_u64(&mut h, OFF_MNT_MASTER, r.mnt_master);
    }
    if want & STATMOUNT_SB_BASIC != 0 {
        mask |= STATMOUNT_SB_BASIC;
        put_u32(&mut h, OFF_SB_DEV_MAJOR, r.sb_dev_major);
        put_u32(&mut h, OFF_SB_DEV_MINOR, r.sb_dev_minor);
        put_u64(&mut h, OFF_SB_MAGIC, r.sb_magic);
        put_u32(&mut h, OFF_SB_FLAGS, r.sb_flags);
    }
    if want & STATMOUNT_PROPAGATE_FROM != 0 {
        mask |= STATMOUNT_PROPAGATE_FROM;
        put_u64(&mut h, OFF_PROPAGATE_FROM, r.propagate_from);
    }

    // String fields, in the order the reply's string area lays them out.
    let emit = |h: &mut [u8; SM_SIZE], s: &mut Strings, mask: &mut u64,
                    flag: u64, off: usize, content: &[u8]| -> Result<(), Errno> {
        if let Some(at) = s.put(content)? {
            *mask |= flag;
            h[off..off + U32].copy_from_slice(&at.to_le_bytes());
        }
        Ok(())
    };
    if want & STATMOUNT_FS_TYPE != 0 {
        emit(&mut h, &mut s, &mut mask, STATMOUNT_FS_TYPE, OFF_FS_TYPE, r.fs_type.as_bytes())?;
    }
    if want & STATMOUNT_MNT_ROOT != 0 {
        emit(&mut h, &mut s, &mut mask, STATMOUNT_MNT_ROOT, OFF_MNT_ROOT, r.mnt_root.as_bytes())?;
    }
    if want & STATMOUNT_MNT_POINT != 0 {
        let p = r.mnt_point.as_deref().unwrap_or("");
        emit(&mut h, &mut s, &mut mask, STATMOUNT_MNT_POINT, OFF_MNT_POINT, p.as_bytes())?;
    }
    if want & STATMOUNT_MNT_OPTS != 0 {
        emit(&mut h, &mut s, &mut mask, STATMOUNT_MNT_OPTS, OFF_MNT_OPTS, r.mnt_opts.as_bytes())?;
    }
    if want & STATMOUNT_OPT_ARRAY != 0 {
        let (blob, n) = opt_blob(&r.opt_array);
        put_u32(&mut h, OFF_OPT_NUM, n);
        emit(&mut h, &mut s, &mut mask, STATMOUNT_OPT_ARRAY, OFF_OPT_ARRAY, &blob)?;
    }
    if want & STATMOUNT_OPT_SEC_ARRAY != 0 {
        let (blob, n) = opt_blob(&r.opt_sec_array);
        put_u32(&mut h, OFF_OPT_SEC_NUM, n);
        emit(&mut h, &mut s, &mut mask, STATMOUNT_OPT_SEC_ARRAY, OFF_OPT_SEC_ARRAY, &blob)?;
    }
    if want & STATMOUNT_FS_SUBTYPE != 0 {
        emit(&mut h, &mut s, &mut mask, STATMOUNT_FS_SUBTYPE, OFF_FS_SUBTYPE,
             r.fs_subtype.as_bytes())?;
    }
    if want & STATMOUNT_SB_SOURCE != 0 {
        emit(&mut h, &mut s, &mut mask, STATMOUNT_SB_SOURCE, OFF_SB_SOURCE,
             r.sb_source.as_bytes())?;
    }
    if want & STATMOUNT_MNT_UIDMAP != 0 && r.idmapped {
        put_u32(&mut h, OFF_MNT_UIDMAP_NUM, r.uid_map.len() as u32);
        // Raised even when no row survived translation into the caller's user
        // namespace: that is how a caller distinguishes a non-idmapped mount
        // from an idmapped one whose mappings it cannot see.
        mask |= STATMOUNT_MNT_UIDMAP;
        emit(&mut h, &mut s, &mut mask, STATMOUNT_MNT_UIDMAP, OFF_MNT_UIDMAP,
             &idmap_blob(&r.uid_map))?;
    }
    if want & STATMOUNT_MNT_GIDMAP != 0 && r.idmapped {
        put_u32(&mut h, OFF_MNT_GIDMAP_NUM, r.gid_map.len() as u32);
        mask |= STATMOUNT_MNT_GIDMAP;
        emit(&mut h, &mut s, &mut mask, STATMOUNT_MNT_GIDMAP, OFF_MNT_GIDMAP,
             &idmap_blob(&r.gid_map))?;
    }

    if want & STATMOUNT_MNT_NS_ID != 0 {
        mask |= STATMOUNT_MNT_NS_ID;
        put_u64(&mut h, OFF_MNT_NS_ID, r.mnt_ns_id);
    }
    if want & STATMOUNT_SUPPORTED_MASK != 0 {
        mask |= STATMOUNT_SUPPORTED_MASK;
        put_u64(&mut h, OFF_SUPPORTED_MASK, STATMOUNT_SUPPORTED);
    }

    // The reserved leading empty string only exists to give unset offsets
    // something to point at. If no field emitted anything there are no offsets
    // to satisfy, so it is dropped rather than written past a buffer the caller
    // sized for the fixed part alone.
    if s.buf.len() == 1 { s.buf.clear(); }
    let copysize = core::cmp::min(bufsize, SM_SIZE);
    put_u64(&mut h, OFF_MASK, mask);
    put_u32(&mut h, OFF_SIZE, (copysize + s.buf.len()) as u32);
    let mut out = Vec::with_capacity(copysize + s.buf.len());
    out.extend_from_slice(&h[..copysize]);
    out.extend_from_slice(&s.buf);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> StatmountRecord {
        StatmountRecord {
            mnt_id: vfs::mount::MNT_UNIQUE_ID_OFFSET + 7,
            mnt_parent_id: vfs::mount::MNT_UNIQUE_ID_OFFSET + 1,
            mnt_id_old: 7, mnt_parent_id_old: 1,
            sb_magic: 0xEF53, sb_dev_major: 8, sb_dev_minor: 3,
            fs_type: String::from("ext4"),
            mnt_root: String::from("/"),
            mnt_point: Some(String::from("/mnt")),
            mnt_opts: String::from("errors=remount-ro"),
            sb_source: String::from("/dev/vda1"),
            ..Default::default()
        }
    }
    fn u64_at(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }
    fn u32_at(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
    fn str_at(b: &[u8], off: u32) -> &str {
        let s = &b[SM_SIZE + off as usize..];
        let end = s.iter().position(|c| *c == 0).unwrap();
        core::str::from_utf8(&s[..end]).unwrap()
    }

    #[test]
    fn an_unrequested_field_is_neither_written_nor_flagged() {
        let out = encode_statmount(&rec(), STATMOUNT_MNT_BASIC, 4096).unwrap();
        assert_eq!(u64_at(&out, OFF_MASK), STATMOUNT_MNT_BASIC);
        // sb_basic was not asked for, so its bytes stay zero even though the
        // record carries real values for them.
        assert_eq!(u64_at(&out, OFF_SB_MAGIC), 0);
        assert_eq!(u32_at(&out, OFF_SB_DEV_MAJOR), 0);
        // ...and the requested field IS written.
        assert_eq!(u64_at(&out, OFF_MNT_ID), vfs::mount::MNT_UNIQUE_ID_OFFSET + 7);
    }

    #[test]
    fn every_written_field_raises_its_own_bit() {
        let want = STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC | STATMOUNT_FS_TYPE
            | STATMOUNT_MNT_ROOT | STATMOUNT_MNT_POINT | STATMOUNT_MNT_NS_ID;
        let out = encode_statmount(&rec(), want, 4096).unwrap();
        assert_eq!(u64_at(&out, OFF_MASK), want);
        assert_eq!(u64_at(&out, OFF_SB_MAGIC), 0xEF53);
        assert_eq!(str_at(&out, u32_at(&out, OFF_FS_TYPE)), "ext4");
        assert_eq!(str_at(&out, u32_at(&out, OFF_MNT_ROOT)), "/");
        assert_eq!(str_at(&out, u32_at(&out, OFF_MNT_POINT)), "/mnt");
    }

    #[test]
    fn a_mount_outside_the_callers_root_reports_no_mount_point() {
        let mut r = rec();
        r.mnt_point = None;
        let out = encode_statmount(&r, STATMOUNT_MNT_POINT | STATMOUNT_FS_TYPE, 4096).unwrap();
        // Absent, not empty: the bit stays clear so the caller does not read a
        // bogus "" as the real mount point.
        assert_eq!(u64_at(&out, OFF_MASK) & STATMOUNT_MNT_POINT, 0);
        assert_eq!(u32_at(&out, OFF_MNT_POINT), 0);
        assert_eq!(u64_at(&out, OFF_MASK) & STATMOUNT_FS_TYPE, STATMOUNT_FS_TYPE);
    }

    #[test]
    fn offset_zero_always_reads_as_the_empty_string() {
        let out = encode_statmount(&rec(), STATMOUNT_FS_TYPE, 4096).unwrap();
        assert_eq!(out[SM_SIZE], 0);
        assert!(u32_at(&out, OFF_FS_TYPE) > 0);
    }

    #[test]
    fn asking_for_a_string_with_no_room_beyond_the_fixed_part_is_eoverflow() {
        assert_eq!(encode_statmount(&rec(), STATMOUNT_FS_TYPE, SM_SIZE), Err(Errno::Eoverflow));
        assert_eq!(encode_statmount(&rec(), STATMOUNT_FS_TYPE, SM_SIZE - 1), Err(Errno::Eoverflow));
        assert!(encode_statmount(&rec(), STATMOUNT_MNT_BASIC, SM_SIZE).is_ok());
        // A requested string field that is EMPTY emits nothing, so a short
        // buffer is fine: the call succeeds with the field simply absent.
        let out = encode_statmount(&rec(), STATMOUNT_FS_SUBTYPE, 64).unwrap();
        assert_eq!(out.len(), 64);
        assert_eq!(u64_at(&out, OFF_MASK) & STATMOUNT_FS_SUBTYPE, 0);
    }

    #[test]
    fn a_string_area_that_does_not_fit_is_eoverflow() {
        // "ext4" + its NUL + the leading empty string needs 6 bytes past the
        // fixed part.
        assert_eq!(encode_statmount(&rec(), STATMOUNT_FS_TYPE, SM_SIZE + 5), Err(Errno::Eoverflow));
        assert!(encode_statmount(&rec(), STATMOUNT_FS_TYPE, SM_SIZE + 6).is_ok());
    }

    #[test]
    fn size_reports_the_bytes_actually_produced() {
        let out = encode_statmount(&rec(), STATMOUNT_FS_TYPE, 4096).unwrap();
        assert_eq!(u32_at(&out, OFF_SIZE) as usize, out.len());
        assert_eq!(out.len(), SM_SIZE + 6);
        // A short buffer with no string request truncates the fixed part and
        // still reports what it produced.
        let out = encode_statmount(&rec(), STATMOUNT_MNT_BASIC, 64).unwrap();
        assert_eq!(out.len(), 64);
        assert_eq!(u32_at(&out, OFF_SIZE), 64);
    }

    #[test]
    fn option_arrays_are_nul_separated_and_counted() {
        let mut r = rec();
        r.opt_array = alloc::vec![String::from("rw"), String::from("errors=remount-ro")];
        let out = encode_statmount(&r, STATMOUNT_OPT_ARRAY, 4096).unwrap();
        assert_eq!(u32_at(&out, OFF_OPT_NUM), 2);
        let at = u32_at(&out, OFF_OPT_ARRAY);
        assert_eq!(str_at(&out, at), "rw");
        assert_eq!(str_at(&out, at + 3), "errors=remount-ro");
        assert_eq!(u64_at(&out, OFF_MASK), STATMOUNT_OPT_ARRAY);
    }

    #[test]
    fn an_empty_option_array_is_counted_but_not_flagged() {
        let out = encode_statmount(&rec(), STATMOUNT_OPT_ARRAY, 4096).unwrap();
        assert_eq!(u32_at(&out, OFF_OPT_NUM), 0);
        assert_eq!(u64_at(&out, OFF_MASK) & STATMOUNT_OPT_ARRAY, 0);
    }

    #[test]
    fn a_non_idmapped_mount_reports_no_id_maps_at_all() {
        let out = encode_statmount(&rec(), STATMOUNT_MNT_UIDMAP | STATMOUNT_MNT_GIDMAP, 4096);
        // No string was emitted, so the buffer-size rung never fired either.
        let out = out.unwrap();
        assert_eq!(u64_at(&out, OFF_MASK), 0);
        assert_eq!(u32_at(&out, OFF_MNT_UIDMAP_NUM), 0);
    }

    #[test]
    fn an_idmapped_mount_with_no_visible_rows_still_raises_its_bit() {
        let mut r = rec();
        r.idmapped = true;
        let out = encode_statmount(&r, STATMOUNT_MNT_UIDMAP, 4096).unwrap();
        // The distinction the flag exists to draw: idmapped-but-invisible is
        // NOT the same answer as not-idmapped.
        assert_eq!(u64_at(&out, OFF_MASK), STATMOUNT_MNT_UIDMAP);
        assert_eq!(u32_at(&out, OFF_MNT_UIDMAP_NUM), 0);
        assert_eq!(u32_at(&out, OFF_MNT_UIDMAP), 0);
    }

    #[test]
    fn id_map_rows_are_first_lower_count_each_nul_terminated() {
        let mut r = rec();
        r.idmapped = true;
        r.uid_map = alloc::vec![(0, 100_000, 65_536), (70_000, 5, 1)];
        let out = encode_statmount(&r, STATMOUNT_MNT_UIDMAP, 4096).unwrap();
        assert_eq!(u32_at(&out, OFF_MNT_UIDMAP_NUM), 2);
        let at = u32_at(&out, OFF_MNT_UIDMAP);
        assert_eq!(str_at(&out, at), "0 100000 65536");
        assert_eq!(str_at(&out, at + 15), "70000 5 1");
    }

    #[test]
    fn the_supported_mask_is_reported_only_on_request() {
        let out = encode_statmount(&rec(), STATMOUNT_SUPPORTED_MASK, 4096).unwrap();
        assert_eq!(u64_at(&out, OFF_SUPPORTED_MASK), STATMOUNT_SUPPORTED);
        let out = encode_statmount(&rec(), STATMOUNT_MNT_BASIC, 4096).unwrap();
        assert_eq!(u64_at(&out, OFF_SUPPORTED_MASK), 0);
    }

    #[test]
    fn a_reply_never_raises_a_bit_outside_the_supported_set() {
        let out = encode_statmount(&rec(), u64::MAX, 4096).unwrap();
        assert_eq!(u64_at(&out, OFF_MASK) & !STATMOUNT_SUPPORTED, 0);
    }

    #[test]
    fn the_fixed_part_is_512_bytes_and_strings_follow_it() {
        let out = encode_statmount(&rec(), STATMOUNT_FS_TYPE, 4096).unwrap();
        assert_eq!(SM_SIZE, 512);
        assert_eq!(u32_at(&out, OFF_FS_TYPE), 1);
        assert_eq!(&out[SM_SIZE..SM_SIZE + 6], b"\0ext4\0");
    }
}
