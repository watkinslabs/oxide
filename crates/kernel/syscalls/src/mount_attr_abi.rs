// `struct mount_attr` ABI: the `AT_*` mask, the versioned-size ladder, the
// no-op short circuit, and the attribute/propagation validation that
// `mount_setattr(2)` and `open_tree_attr(2)` share.
//
// Ungated on purpose: `442_mount_setattr.rs` is `#![cfg(target_os =
// "oxide-kernel")]`, so a `#[cfg(test)]` block inside it compiles out silently
// (CLAUDE.md phantom-test rule) and none of these decisions had a test. The
// slot file keeps the user copies, the capability gate, and the transaction.

use syscall::errno::Errno;

/// `copy_struct_from_user` upper bound for the attribute block.
pub const PAGE_SIZE: usize = 4096;
/// `sizeof(struct mount_attr)` at version 0 — four `__u64` fields.
pub const MOUNT_ATTR_SIZE_VER0: usize = 32;

/// The `AT_*` bits `mount_setattr(2)` accepts, widened from the one canonical
/// `at`-flag table so this ABI cannot disagree with `openat`/`statx` about what
/// a bit means.
pub const AT_SYMLINK_NOFOLLOW: u64 = syscall::at::AT_SYMLINK_NOFOLLOW as u64;
pub const AT_NO_AUTOMOUNT: u64 = syscall::at::AT_NO_AUTOMOUNT as u64;
pub const AT_EMPTY_PATH: u64 = syscall::at::AT_EMPTY_PATH as u64;
pub const AT_RECURSIVE: u64 = syscall::at::AT_RECURSIVE as u64;
/// Every `AT_*` bit `mount_setattr(2)` accepts.
pub const VALID_AT_FLAGS: u64 =
    AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_RECURSIVE;

/// The four propagation requests, of which at most one may be set. Taken from
/// the mount-flag table that `mount(2)`'s own propagation arm uses, so the two
/// entry points cannot disagree about which bit means which mode.
pub use vfs::mount::{
    MS_PRIVATE, MS_PROPAGATION as PROPAGATION_MASK, MS_SHARED, MS_SLAVE, MS_UNBINDABLE,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MountAttr {
    pub attr_set:    u64,
    pub attr_clr:    u64,
    pub propagation: u64,
    pub userns_fd:   u64,
}

impl MountAttr {
    /// Decode one version-0 block. # C: O(1)
    pub fn decode(bytes: &[u8; MOUNT_ATTR_SIZE_VER0]) -> Self {
        let field = |offset: usize| {
            u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
        };
        Self {
            attr_set: field(0),
            attr_clr: field(8),
            propagation: field(16),
            userns_fd: field(24),
        }
    }

    /// A block that asks for nothing. Linux answers such a call with success
    /// before it looks up either the path or `userns_fd`. # C: O(1)
    pub fn is_nop(&self) -> bool {
        self.attr_set == 0 && self.attr_clr == 0 && self.propagation == 0
    }
}

/// `wants_mount_setattr`'s size ladder, which runs before the capability gate
/// and before any copy: an oversized block is E2BIG and a block smaller than
/// version 0 is EINVAL. A zero size therefore reports EINVAL, which is what a
/// userspace probe for "does this kernel have the new mount API" reads as
/// "present" — the probe passes a null block deliberately. # C: O(1)
pub fn admit_size(size: usize) -> Result<(), Errno> {
    if size > PAGE_SIZE { return Err(Errno::E2big); }
    if size < MOUNT_ATTR_SIZE_VER0 { return Err(Errno::Einval); }
    Ok(())
}

/// A tail beyond version 0 must be entirely zero: a nonzero extension byte is a
/// request this kernel cannot honour. # C: O(n)
pub fn admit_tail(tail: &[u8]) -> Result<(), Errno> {
    if tail.iter().any(|byte| *byte != 0) { return Err(Errno::E2big); }
    Ok(())
}

/// Map a propagation request to its mount-tree form. `None` covers both "none
/// requested" and a multi-bit request, which `validate` rejects first.
/// # C: O(1)
pub fn propagation(raw: u64) -> Option<vfs::mount::Propagation> {
    match raw {
        MS_SHARED => Some(vfs::mount::Propagation::Shared),
        MS_SLAVE => Some(vfs::mount::Propagation::Slave),
        MS_UNBINDABLE => Some(vfs::mount::Propagation::Unbindable),
        MS_PRIVATE => Some(vfs::mount::Propagation::Private),
        _ => None,
    }
}

/// `build_mount_kattr`: at most one propagation request, no unsettable
/// attribute bit, and the atime rule — an atime mode may only be set together
/// with a full clear of the atime field, and the clear must be the full field.
/// # C: O(1)
pub fn validate(attr: &MountAttr) -> Result<(), Errno> {
    use vfs::mount::{
        MOUNT_ATTR_NOATIME, MOUNT_ATTR_SETTABLE, MOUNT_ATTR_STRICTATIME, MOUNT_ATTR__ATIME,
    };
    if attr.propagation & !PROPAGATION_MASK != 0
        || (attr.propagation & PROPAGATION_MASK).count_ones() > 1 {
        return Err(Errno::Einval);
    }
    if (attr.attr_set | attr.attr_clr) & !MOUNT_ATTR_SETTABLE != 0 {
        return Err(Errno::Einval);
    }
    let set_atime = attr.attr_set & MOUNT_ATTR__ATIME;
    let clr_atime = attr.attr_clr & MOUNT_ATTR__ATIME;
    if clr_atime != 0 {
        if clr_atime != MOUNT_ATTR__ATIME { return Err(Errno::Einval); }
        if set_atime != 0 && set_atime != MOUNT_ATTR_NOATIME
            && set_atime != MOUNT_ATTR_STRICTATIME {
            return Err(Errno::Einval);
        }
    } else if set_atime != 0 {
        return Err(Errno::Einval);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::mount::{
        MOUNT_ATTR_NOATIME, MOUNT_ATTR_NODEV, MOUNT_ATTR_STRICTATIME, MOUNT_ATTR__ATIME,
    };

    // The support probe every systemd-based userspace issues at boot passes a
    // null block with size 0 and reads the errno: ENOSYS (or success) means the
    // new mount API is absent, anything else means present. The size ladder
    // must therefore answer EINVAL, and must answer it BEFORE the capability
    // gate so an unprivileged prober gets the same reading.
    #[test]
    fn a_zero_sized_block_is_einval_and_that_is_the_support_probe_answer() {
        assert_eq!(admit_size(0), Err(Errno::Einval));
        assert_eq!(admit_size(MOUNT_ATTR_SIZE_VER0 - 1), Err(Errno::Einval));
        assert_eq!(admit_size(MOUNT_ATTR_SIZE_VER0), Ok(()));
        assert_eq!(admit_size(PAGE_SIZE), Ok(()));
        assert_eq!(admit_size(PAGE_SIZE + 1), Err(Errno::E2big));
    }

    #[test]
    fn a_nonzero_extension_byte_is_e2big() {
        assert_eq!(admit_tail(&[0, 0, 0, 0]), Ok(()));
        assert_eq!(admit_tail(&[0, 0, 1, 0]), Err(Errno::E2big));
        assert_eq!(admit_tail(&[]), Ok(()));
    }

    #[test]
    fn the_at_mask_is_the_four_documented_bits() {
        assert_eq!(VALID_AT_FLAGS, 0x9900);
        for bit in [AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT, AT_EMPTY_PATH, AT_RECURSIVE] {
            assert_eq!(VALID_AT_FLAGS & bit, bit);
        }
        // `AT_SYMLINK_FOLLOW` and `AT_EACCESS` are not in the set.
        assert_eq!(VALID_AT_FLAGS & syscall::at::AT_SYMLINK_FOLLOW as u64, 0);
        assert_eq!(VALID_AT_FLAGS & syscall::at::AT_EACCESS as u64, 0);
    }

    #[test]
    fn decode_reads_four_native_endian_fields_in_order() {
        let mut bytes = [0u8; MOUNT_ATTR_SIZE_VER0];
        for (slot, value) in [1u64, 2, MS_SLAVE, 9].iter().enumerate() {
            bytes[slot * 8..slot * 8 + 8].copy_from_slice(&value.to_ne_bytes());
        }
        assert_eq!(MountAttr::decode(&bytes), MountAttr {
            attr_set: 1, attr_clr: 2, propagation: MS_SLAVE, userns_fd: 9,
        });
    }

    // A block that asks for nothing succeeds without a lookup, so a caller
    // cannot use it to probe for a path's existence — and `userns_fd` is never
    // read, so a garbage descriptor there is not an error either.
    #[test]
    fn a_block_that_asks_for_nothing_is_a_nop_regardless_of_userns_fd() {
        assert!(MountAttr::default().is_nop());
        assert!(MountAttr { userns_fd: u64::MAX, ..Default::default() }.is_nop());
        assert!(!MountAttr { attr_set: MOUNT_ATTR_NODEV, ..Default::default() }.is_nop());
        assert!(!MountAttr { attr_clr: MOUNT_ATTR_NODEV, ..Default::default() }.is_nop());
        assert!(!MountAttr { propagation: MS_PRIVATE, ..Default::default() }.is_nop());
    }

    #[test]
    fn at_most_one_propagation_request_and_no_foreign_bit() {
        for one in [MS_SHARED, MS_SLAVE, MS_PRIVATE, MS_UNBINDABLE] {
            let attr = MountAttr { propagation: one, ..Default::default() };
            assert_eq!(validate(&attr), Ok(()));
            assert!(propagation(one).is_some());
        }
        assert_eq!(validate(&MountAttr {
            propagation: MS_SHARED | MS_SLAVE, ..Default::default()
        }), Err(Errno::Einval));
        assert_eq!(validate(&MountAttr { propagation: 1, ..Default::default() }),
            Err(Errno::Einval));
        assert_eq!(propagation(MS_SHARED | MS_SLAVE), None);
        assert_eq!(propagation(0), None);
    }

    #[test]
    fn an_unsettable_attribute_bit_is_einval_in_either_word() {
        let foreign = 1u64 << 40;
        assert_eq!(validate(&MountAttr { attr_set: foreign, ..Default::default() }),
            Err(Errno::Einval));
        assert_eq!(validate(&MountAttr { attr_clr: foreign, ..Default::default() }),
            Err(Errno::Einval));
        assert_eq!(validate(&MountAttr { attr_set: MOUNT_ATTR_NODEV, ..Default::default() }),
            Ok(()));
    }

    // The atime field is a mode, not a bit set: selecting a mode requires
    // clearing the whole field, a partial clear is invalid, and clearing
    // without selecting is the "reset to the superblock default" request.
    #[test]
    fn an_atime_mode_requires_a_full_clear_of_the_atime_field() {
        let with = |set, clr| validate(&MountAttr {
            attr_set: set, attr_clr: clr, ..Default::default()
        });
        assert_eq!(with(MOUNT_ATTR_NOATIME, MOUNT_ATTR__ATIME), Ok(()));
        assert_eq!(with(MOUNT_ATTR_STRICTATIME, MOUNT_ATTR__ATIME), Ok(()));
        assert_eq!(with(0, MOUNT_ATTR__ATIME), Ok(()));
        // Selecting a mode without clearing the field.
        assert_eq!(with(MOUNT_ATTR_NOATIME, 0), Err(Errno::Einval));
        // Partial clear.
        assert_eq!(with(0, MOUNT_ATTR_NOATIME), Err(Errno::Einval));
        // The relatime mode is the zero value of the field — the clear-only
        // case above IS the way to request it, and both named modes live
        // inside the field they clear.
        assert_eq!(MOUNT_ATTR_NOATIME & MOUNT_ATTR__ATIME, MOUNT_ATTR_NOATIME);
        assert_eq!(MOUNT_ATTR_STRICTATIME & MOUNT_ATTR__ATIME, MOUNT_ATTR_STRICTATIME);
        assert_ne!(MOUNT_ATTR_NOATIME, MOUNT_ATTR_STRICTATIME);
        // Two modes at once.
        assert_eq!(with(MOUNT_ATTR_NOATIME | MOUNT_ATTR_STRICTATIME, MOUNT_ATTR__ATIME),
            Err(Errno::Einval));
    }
}
