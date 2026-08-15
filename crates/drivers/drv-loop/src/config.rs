//! What a status or configure request is allowed to change, and in which
//! order it refuses.
//!
//! Error ORDER is contract, not taste: a request that is wrong in two ways
//! must report the same one the reference reports, or a caller that probes by
//! trying gets a different answer here.

use syscall::errno::Errno;

use crate::uapi::{LoopInfo, LoopInfo64, LO_CRYPT_NONE, LO_KEY_SIZE, LO_NAME_SIZE,
                  LOOP_SET_STATUS_CLEARABLE_FLAGS, LOOP_SET_STATUS_SETTABLE_FLAGS,
                  LO_FLAGS_READ_ONLY};

/// The window and name a bound device carries. Split from the device so the
/// rules that produce it are testable on their own.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Window {
    pub offset: u64,
    pub sizelimit: u64,
    pub file_name: [u8; LO_NAME_SIZE],
}

impl Default for Window {
    fn default() -> Self { Self { offset: 0, sizelimit: 0, file_name: [0; LO_NAME_SIZE] } }
}

/// Largest value the window fields accept. The reference stores them in a
/// signed 64-bit type, so a value above its maximum is refused rather than
/// wrapped into a negative offset.
pub const WINDOW_MAX: u64 = i64::MAX as u64;

/// Validate an incoming `loop_info64` and produce the window it asks for.
///
/// The refusal order is: key size, then encryption type, then overflow. The
/// two removed transformations are refused by name rather than falling into
/// the default arm, because they are the values a caller is most likely to
/// still send.
/// # C: O(1)
pub fn window_from_info(info: &LoopInfo64) -> Result<Window, Errno> {
    if info.lo_encrypt_key_size as usize > LO_KEY_SIZE { return Err(Errno::Einval); }
    if info.lo_encrypt_type != LO_CRYPT_NONE { return Err(Errno::Einval); }
    if info.lo_offset > WINDOW_MAX || info.lo_sizelimit > WINDOW_MAX { return Err(Errno::Eoverflow); }
    let mut file_name = info.lo_file_name;
    file_name[LO_NAME_SIZE - 1] = 0;
    Ok(Window { offset: info.lo_offset, sizelimit: info.lo_sizelimit, file_name })
}

/// Flags after a `SET_STATUS` request: only the settable bits may be turned
/// on, only the clearable ones off, and every other bit keeps its current
/// value. A caller cannot make a read-only device writable this way.
/// # C: O(1)
pub fn flags_after_set_status(current: u32, requested: u32) -> u32 {
    let mut out = current;
    out |= requested & LOOP_SET_STATUS_SETTABLE_FLAGS;
    out &= !(!requested & LOOP_SET_STATUS_CLEARABLE_FLAGS);
    out
}

/// Whether a `SET_STATUS` request changes the window. The reference only
/// re-reads the device's size when it does, so this decides that too.
/// # C: O(1)
pub fn window_changed(current: &Window, next: &Window) -> bool {
    current.offset != next.offset || current.sizelimit != next.sizelimit
}

/// Widen the pre-64-bit `loop_info` into the current one.
///
/// Its `lo_offset` is a signed 32-bit field, so a negative value is a request
/// for an offset that cannot exist and is refused rather than sign-extended
/// into an enormous one. # C: O(1)
pub fn info64_from_old(old: &LoopInfo) -> Result<LoopInfo64, Errno> {
    if old.lo_offset < 0 || old.lo_encrypt_key_size < 0 { return Err(Errno::Einval); }
    let mut out = LoopInfo64 {
        lo_number: old.lo_number as u32,
        lo_device: old.lo_device,
        lo_inode: old.lo_inode,
        lo_rdevice: old.lo_rdevice,
        lo_offset: old.lo_offset as u64,
        lo_sizelimit: 0,
        lo_encrypt_type: old.lo_encrypt_type as u32,
        lo_encrypt_key_size: old.lo_encrypt_key_size as u32,
        lo_flags: old.lo_flags as u32,
        ..LoopInfo64::default()
    };
    out.lo_file_name = old.lo_name;
    out.lo_encrypt_key = old.lo_encrypt_key;
    out.lo_init = old.lo_init;
    Ok(out)
}

/// Narrow the current `loop_info64` into the pre-64-bit layout a
/// `GET_STATUS` caller reads.
///
/// A field that does not fit is `EOVERFLOW` — the reference refuses rather
/// than reporting a truncated offset, because a caller acting on a truncated
/// window would read the wrong bytes. # C: O(1)
pub fn old_from_info64(info: &LoopInfo64) -> Result<LoopInfo, Errno> {
    if info.lo_offset > i32::MAX as u64 || info.lo_sizelimit != 0 { return Err(Errno::Eoverflow); }
    Ok(LoopInfo {
        lo_number: info.lo_number as i32,
        lo_device: info.lo_device,
        lo_inode: info.lo_inode,
        lo_rdevice: info.lo_rdevice,
        lo_offset: info.lo_offset as i32,
        lo_encrypt_type: info.lo_encrypt_type as i32,
        lo_encrypt_key_size: info.lo_encrypt_key_size as i32,
        lo_flags: info.lo_flags as i32,
        lo_name: info.lo_file_name,
        lo_encrypt_key: info.lo_encrypt_key,
        lo_init: info.lo_init,
        reserved: [0; 4],
    })
}

/// Flags a freshly configured device carries: what the caller asked for,
/// masked to the configurable set, plus read-only forced on when the backing
/// description cannot be written. A writable loop device over a read-only
/// file would fail every write at the backing store instead of at `open`.
/// # C: O(1)
pub fn flags_after_configure(requested: u32, backing_writable: bool) -> Result<u32, Errno> {
    if requested & !crate::uapi::LOOP_CONFIGURE_SETTABLE_FLAGS != 0 { return Err(Errno::Einval); }
    Ok(if backing_writable { requested } else { requested | LO_FLAGS_READ_ONLY })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uapi::{LO_CRYPT_CRYPTOAPI, LO_CRYPT_XOR, LO_FLAGS_AUTOCLEAR, LO_FLAGS_DIRECT_IO,
                      LO_FLAGS_PARTSCAN};

    fn info(f: impl FnOnce(&mut LoopInfo64)) -> LoopInfo64 {
        let mut i = LoopInfo64::default();
        f(&mut i);
        i
    }

    /// Refusal ORDER is the contract. A request that is wrong in two ways
    /// reports the first refusal, so a caller probing by trial gets the same
    /// answer it would elsewhere.
    #[test]
    fn the_refusal_order_is_key_size_then_crypt_then_overflow() {
        let both = info(|i| { i.lo_encrypt_key_size = 999; i.lo_encrypt_type = LO_CRYPT_XOR; i.lo_offset = u64::MAX; });
        assert_eq!(window_from_info(&both), Err(Errno::Einval), "key size is checked first");
        let crypt_and_overflow = info(|i| { i.lo_encrypt_type = LO_CRYPT_XOR; i.lo_offset = u64::MAX; });
        assert_eq!(window_from_info(&crypt_and_overflow), Err(Errno::Einval), "crypt before overflow");
        let overflow = info(|i| i.lo_offset = u64::MAX);
        assert_eq!(window_from_info(&overflow), Err(Errno::Eoverflow));
    }

    /// The removed transformations are refused, not silently treated as none.
    #[test]
    fn the_removed_transformations_are_refused() {
        for ty in [LO_CRYPT_XOR, LO_CRYPT_CRYPTOAPI, 2, 7, u32::MAX] {
            assert_eq!(window_from_info(&info(|i| i.lo_encrypt_type = ty)), Err(Errno::Einval), "{ty}");
        }
        assert!(window_from_info(&info(|i| i.lo_encrypt_type = LO_CRYPT_NONE)).is_ok());
    }

    /// A window at the signed maximum is accepted; one byte past it is not.
    #[test]
    fn the_window_fields_stop_at_the_signed_maximum() {
        assert!(window_from_info(&info(|i| i.lo_offset = WINDOW_MAX)).is_ok());
        assert_eq!(window_from_info(&info(|i| i.lo_offset = WINDOW_MAX + 1)), Err(Errno::Eoverflow));
        assert_eq!(window_from_info(&info(|i| i.lo_sizelimit = WINDOW_MAX + 1)), Err(Errno::Eoverflow));
    }

    /// The name is always terminated, whatever the caller sent.
    #[test]
    fn the_backing_name_is_always_terminated() {
        let w = window_from_info(&info(|i| i.lo_file_name = [b'x'; LO_NAME_SIZE])).unwrap();
        assert_eq!(w.file_name[LO_NAME_SIZE - 1], 0);
    }

    /// `SET_STATUS` may set autoclear and partscan, may clear only autoclear,
    /// and may not touch read-only or direct-I/O in either direction.
    #[test]
    fn set_status_moves_only_the_flags_it_owns() {
        // Turn on what it may.
        assert_eq!(flags_after_set_status(0, LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN),
                   LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN);
        // Clearing partscan is not offered: it stays.
        assert_eq!(flags_after_set_status(LO_FLAGS_PARTSCAN, 0), LO_FLAGS_PARTSCAN);
        // Clearing autoclear is.
        assert_eq!(flags_after_set_status(LO_FLAGS_AUTOCLEAR, 0), 0);
        // Read-only and direct I/O survive a request that names neither...
        assert_eq!(flags_after_set_status(LO_FLAGS_READ_ONLY | LO_FLAGS_DIRECT_IO, 0),
                   LO_FLAGS_READ_ONLY | LO_FLAGS_DIRECT_IO);
        // ...and a request that names both cannot set them.
        assert_eq!(flags_after_set_status(0, LO_FLAGS_READ_ONLY | LO_FLAGS_DIRECT_IO), 0);
    }

    #[test]
    fn only_a_moved_window_counts_as_changed() {
        let a = Window { offset: 512, sizelimit: 4096, file_name: [0; LO_NAME_SIZE] };
        assert!(!window_changed(&a, &a));
        assert!(window_changed(&a, &Window { offset: 0, ..a }));
        assert!(window_changed(&a, &Window { sizelimit: 8192, ..a }));
        // The name is not part of the window: renaming does not resize.
        assert!(!window_changed(&a, &Window { file_name: [b'z'; LO_NAME_SIZE], ..a }));
    }

    /// A negative offset in the old layout is a request for an impossible
    /// window. Sign-extending it would produce an enormous one instead.
    #[test]
    fn a_negative_old_offset_is_refused_not_sign_extended() {
        let mut old = old_from_info64(&LoopInfo64::default()).unwrap();
        old.lo_offset = -1;
        assert_eq!(info64_from_old(&old), Err(Errno::Einval));
        old.lo_offset = 0;
        old.lo_encrypt_key_size = -1;
        assert_eq!(info64_from_old(&old), Err(Errno::Einval));
    }

    /// A window the old layout cannot express is refused, never truncated: a
    /// caller acting on a truncated offset reads the wrong bytes.
    #[test]
    fn a_window_the_old_layout_cannot_hold_is_refused() {
        assert_eq!(old_from_info64(&info(|i| i.lo_offset = i32::MAX as u64 + 1)), Err(Errno::Eoverflow));
        assert_eq!(old_from_info64(&info(|i| i.lo_sizelimit = 1)), Err(Errno::Eoverflow));
        assert!(old_from_info64(&info(|i| i.lo_offset = i32::MAX as u64)).is_ok());
    }

    /// The old and new layouts round-trip for a window both can express.
    #[test]
    fn the_two_layouts_round_trip_a_representable_window() {
        let original = info(|i| { i.lo_offset = 8192; i.lo_number = 3; i.lo_file_name[0] = b'a'; });
        let old = old_from_info64(&original).unwrap();
        let back = info64_from_old(&old).unwrap();
        assert_eq!(back.lo_offset, original.lo_offset);
        assert_eq!(back.lo_number, original.lo_number);
        assert_eq!(back.lo_file_name[0], b'a');
    }

    /// A device over a description that cannot be written is read-only
    /// whatever the caller asked for — the refusal belongs at configure time,
    /// not at every write.
    #[test]
    fn a_read_only_backing_file_forces_a_read_only_device() {
        assert_eq!(flags_after_configure(0, false), Ok(LO_FLAGS_READ_ONLY));
        assert_eq!(flags_after_configure(LO_FLAGS_PARTSCAN, false),
                   Ok(LO_FLAGS_PARTSCAN | LO_FLAGS_READ_ONLY));
        assert_eq!(flags_after_configure(0, true), Ok(0));
    }

    /// A flag outside the configurable set is refused rather than dropped, so
    /// a caller cannot believe it asked for something that never took effect.
    #[test]
    fn an_unknown_configure_flag_is_refused() {
        assert_eq!(flags_after_configure(1 << 20, true), Err(Errno::Einval));
        assert_eq!(flags_after_configure(2, true), Err(Errno::Einval), "no flag owns bit 1");
    }
}
