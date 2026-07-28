// `struct inotify_event` wire layout — Linux `fs/notify/inotify/inotify_user.c`
// (`round_event_name_len`, `copy_event_to_user`).
//
// Deliberately free of any target gate so the padding/short-buffer rules are
// hosted-testable: the read path in `group.rs` only sequences these helpers.

use alloc::vec::Vec;

/// `sizeof(struct inotify_event)`. Doubles as the name-padding granularity —
/// Linux rounds the name up to a multiple of the header size, not to 4.
pub(crate) const INOTIFY_EVENT_HDR: usize = 16;

/// Linux `round_event_name_len`: `roundup(name_len + 1, sizeof(struct
/// inotify_event))`, i.e. the name plus its terminating NUL rounded up to a
/// whole header. A nameless event has no tail at all (`len == 0`), which is
/// why the `+1` may not be applied unconditionally.
/// # C: O(1)
pub(crate) fn round_event_name_len(name_len: usize) -> usize {
    if name_len == 0 { return 0; }
    (name_len + 1).div_ceil(INOTIFY_EVENT_HDR) * INOTIFY_EVENT_HDR
}

/// Bytes one event occupies in a reader's buffer: fixed header plus the padded
/// name tail. Linux `get_one_event` compares exactly this against the caller's
/// remaining `count`. # C: O(1)
pub(crate) fn event_record_len(name_len: usize) -> usize {
    INOTIFY_EVENT_HDR + round_event_name_len(name_len)
}

/// Encode `{wd, mask, cookie, len}` + the NUL-padded name into `dst`, returning
/// the bytes written. `len` is the PADDED tail length (Linux
/// `inotify_event.len = pad_name_len`), never the raw name length. Writes
/// nothing and returns 0 when `dst` cannot hold the whole record — a reader
/// must never see a partial event. # C: O(name_len)
pub(crate) fn encode_event(dst: &mut [u8], wd: i32, mask: u32, cookie: u32, name: &[u8]) -> usize {
    let pad = round_event_name_len(name.len());
    let total = INOTIFY_EVENT_HDR + pad;
    if dst.len() < total { return 0; }
    dst[0..4].copy_from_slice(&wd.to_le_bytes());
    dst[4..8].copy_from_slice(&mask.to_le_bytes());
    dst[8..12].copy_from_slice(&cookie.to_le_bytes());
    dst[12..16].copy_from_slice(&(pad as u32).to_le_bytes());
    if pad != 0 {
        let end = INOTIFY_EVENT_HDR + name.len();
        dst[INOTIFY_EVENT_HDR..end].copy_from_slice(name);
        for b in dst[end..total].iter_mut() { *b = 0; }
    }
    total
}

/// The stored dir-entry leaf for a dirent event. Held as raw bytes because
/// `inotify_event.name` is a byte string, and the path layer's `&str` carries
/// non-UTF-8 leaf bytes in an escape encoding that must be undone once, here,
/// rather than at every reader. # C: O(name.len())
pub(crate) fn encode_name(name: Option<&str>) -> Vec<u8> {
    match name {
        Some(n) => vfs::path_into_bytes(n),
        None    => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nameless_event_has_no_tail() {
        assert_eq!(round_event_name_len(0), 0);
        assert_eq!(event_record_len(0), 16);
    }

    #[test]
    fn name_pads_to_a_whole_header_including_the_nul() {
        // Linux roundup(name_len + 1, 16): the NUL is part of what gets rounded.
        assert_eq!(round_event_name_len(1), 16, "1+NUL fits one header");
        assert_eq!(round_event_name_len(15), 16, "15+NUL exactly fills one header");
        assert_eq!(round_event_name_len(16), 32, "16+NUL spills into a second");
        assert_eq!(round_event_name_len(31), 32);
        assert_eq!(round_event_name_len(32), 48);
    }

    #[test]
    fn encoded_len_field_is_the_padded_length_not_the_name_length() {
        let mut buf = [0xAAu8; 64];
        let n = encode_event(&mut buf, 3, 0x100, 7, b"abc");
        assert_eq!(n, 32, "16 header + 16 padded name");
        assert_eq!(i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 3);
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 0x100);
        assert_eq!(u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]), 7);
        assert_eq!(u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]), 16,
                   "len is the PADDED tail, not 3");
        assert_eq!(&buf[16..19], b"abc");
        assert_eq!(&buf[19..32], &[0u8; 13], "tail NUL-filled through the padding");
    }

    #[test]
    fn a_name_that_exactly_fills_the_padding_still_gets_a_nul() {
        let mut buf = [0xAAu8; 64];
        let name = [b'x'; 15];
        let n = encode_event(&mut buf, 1, 1, 0, &name);
        assert_eq!(n, 32);
        assert_eq!(buf[31], 0, "terminating NUL is inside the 16-byte pad");
    }

    #[test]
    fn encode_refuses_to_write_a_partial_record() {
        let mut buf = [0xAAu8; 20];
        assert_eq!(encode_event(&mut buf, 1, 1, 0, b"abcd"), 0, "needs 32, has 20");
        assert_eq!(buf, [0xAAu8; 20], "nothing written");
    }

    #[test]
    fn non_utf8_leaf_bytes_survive_the_round_trip() {
        let s = vfs::path_from_bytes(b"raw-\xff-name");
        assert_eq!(encode_name(Some(&s)), b"raw-\xff-name");
        assert!(encode_name(None).is_empty());
    }
}
