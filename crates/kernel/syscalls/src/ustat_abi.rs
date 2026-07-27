// `struct ustat` wire layout for ustat(2) slot 136. Pure ABI: compiled into
// the kernel AND the hosted test build, because the field offsets and the
// `f_tfree` truncation are the whole observable contract and a boot cannot
// unit-test them (`08§7`, CLAUDE.md phantom-test rule).
//
// Linux `include/linux/types.h`:
//   struct ustat {
//       __kernel_daddr_t f_tfree;      /* `int` per asm-generic posix_types.h */
//       unsigned long    f_tinode;     /* `unsigned int` only when
//                                         CONFIG_ARCH_32BIT_USTAT_F_TINODE,
//                                         which x86_64/aarch64 do NOT set */
//       char             f_fname[6];
//       char             f_fpack[6];
//   };
// `unsigned long` forces 8-byte alignment, so `f_tfree` is followed by 4 bytes
// of padding and the struct tail-pads to 32.

/// Field offsets and total size of `struct ustat` on a 64-bit LP64 target.
pub const OFF_TFREE:  usize = 0;
pub const OFF_TINODE: usize = 8;
pub const OFF_FNAME:  usize = 16;
pub const OFF_FPACK:  usize = 22;
pub const FNAME_LEN:  usize = 6;
pub const FPACK_LEN:  usize = 6;
/// `sizeof(struct ustat)` — 28 bytes of fields tail-padded to the 8-byte
/// alignment `unsigned long f_tinode` imposes.
pub const USTAT_BYTES: usize = 32;

/// Encode `struct ustat` exactly as `fs/statfs.c` `SYSCALL_DEFINE2(ustat)`
/// builds it: zero the whole struct, then `f_tfree = sbuf.f_bfree` (a 64-bit
/// count assigned to a 32-bit `int`, so it TRUNCATES — reproduced with a
/// wrapping cast rather than a saturate, which would report a different number
/// than Linux for a filesystem above 2^31 free blocks) and `f_tinode =
/// sbuf.f_ffree` at full 64-bit width. `f_fname`/`f_fpack` are the SysV
/// filesystem-name/pack fields Linux never fills and so stay zero.
/// # C: O(1)
pub fn encode_ustat(f_bfree: u64, f_ffree: u64) -> [u8; USTAT_BYTES] {
    let mut out = [0u8; USTAT_BYTES];
    let tfree = f_bfree as u32; // `int f_tfree = (u64)f_bfree` truncation
    out[OFF_TFREE..OFF_TFREE + 4].copy_from_slice(&tfree.to_le_bytes());
    out[OFF_TINODE..OFF_TINODE + 8].copy_from_slice(&f_ffree.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The struct is 32 bytes and `f_tinode` sits at 8, not 4: a naive packed
    /// layout would put it at 4 and shift every subsequent field, so `df`-style
    /// callers would read `f_tinode`'s low half as the whole value. # C: O(1)
    #[test]
    fn layout_matches_lp64_struct_ustat() {
        assert_eq!(USTAT_BYTES, 32);
        assert_eq!(OFF_TFREE, 0);
        assert_eq!(OFF_TINODE, 8);
        assert_eq!(OFF_FNAME, 16);
        assert_eq!(OFF_FPACK, OFF_FNAME + FNAME_LEN);
        assert_eq!(OFF_FPACK + FPACK_LEN, 28, "fields end at 28, tail-padded to 32");
    }

    /// Padding and the two unused SysV name fields read as zero, matching the
    /// `memset(&tmp, 0, sizeof(struct ustat))` Linux does first. # C: O(1)
    #[test]
    fn unset_fields_are_zero() {
        let img = encode_ustat(1, 2);
        assert_eq!(&img[4..8], &[0u8; 4], "f_tfree tail padding");
        assert_eq!(&img[OFF_FNAME..OFF_FNAME + FNAME_LEN], &[0u8; FNAME_LEN]);
        assert_eq!(&img[OFF_FPACK..OFF_FPACK + FPACK_LEN], &[0u8; FPACK_LEN]);
        assert_eq!(&img[28..32], &[0u8; 4], "struct tail padding");
    }

    /// `f_tfree` TRUNCATES a free-block count that does not fit `int`, and
    /// `f_tinode` does not. Asserting the exact wrapped value pins the Linux
    /// behaviour rather than any locally-invented clamp. # C: O(1)
    #[test]
    fn tfree_truncates_and_tinode_does_not() {
        let img = encode_ustat(0x1_2345_6789, 0xAABB_CCDD_EEFF_0011);
        assert_eq!(u32::from_le_bytes(img[0..4].try_into().unwrap()), 0x2345_6789,
            "f_tfree keeps only the low 32 bits");
        assert_eq!(u64::from_le_bytes(img[8..16].try_into().unwrap()), 0xAABB_CCDD_EEFF_0011,
            "f_tinode is full 64-bit on LP64");
    }

    /// A count whose low 32 bits have the sign bit set still round-trips as the
    /// same BYTES — `f_tfree` is a signed `int` in Linux, so the value userspace
    /// reads is negative and that is exactly what Linux hands it. # C: O(1)
    #[test]
    fn tfree_sign_bit_is_preserved_as_bytes() {
        let img = encode_ustat(0xFFFF_FFFF, 0);
        assert_eq!(i32::from_le_bytes(img[0..4].try_into().unwrap()), -1);
    }
}
