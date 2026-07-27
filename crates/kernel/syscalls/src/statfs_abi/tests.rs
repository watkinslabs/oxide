// statfs(2) wire-ABI tests: exact LP64 field offsets (identical on x86_64 and
// aarch64), the `MNT_*`/`SB_*` → statvfs `ST_*` mapping, and the no-fabrication
// rule for a pseudo filesystem's zero block accounting.

use super::*;
use vfs::SbStatFs;

fn field(img: &[u8; STATFS_BYTES], off: usize) -> u64 {
    u64::from_le_bytes(img[off..off + 8].try_into().unwrap())
}

/// The one sample every offset assertion reads: distinct value per field so a
/// swapped pair cannot pass.
fn sample() -> SbStatFs {
    SbStatFs {
        f_type:    0xEF53,
        f_bsize:   4096,
        f_blocks:  0x1111_1111,
        f_bfree:   0x2222_2222,
        f_bavail:  0x3333_3333,
        f_files:   0x4444_4444,
        f_ffree:   0x5555_5555,
        f_fsid:    0x6666_6666_7777_7777,
        f_flags:   ST_RDONLY | ST_NOSUID,
        f_namelen: 255,
        f_frsize:  1024,
    }
}

#[test]
fn struct_statfs_is_120_bytes_on_both_lp64_arches() {
    // asm-generic/statfs.h: 7 __statfs_word + __kernel_fsid_t (2×int) +
    // 3 __statfs_word + f_spare[4] = (7+1+3+4)*8 = 120 on LP64. x86_64 and
    // aarch64 both take the generic 64-bit definition, so ONE encoder serves
    // both — this constant is the lockstep contract.
    assert_eq!(STATFS_BYTES, 120);
    assert_eq!(encode_statfs(&sample()).len(), 120);
}

#[test]
fn every_field_lands_at_its_linux_offset() {
    let img = encode_statfs(&sample());
    assert_eq!(field(&img, OFF_TYPE),    0xEF53);
    assert_eq!(field(&img, OFF_BSIZE),   4096);
    assert_eq!(field(&img, OFF_BLOCKS),  0x1111_1111);
    assert_eq!(field(&img, OFF_BFREE),   0x2222_2222);
    assert_eq!(field(&img, OFF_BAVAIL),  0x3333_3333);
    assert_eq!(field(&img, OFF_FILES),   0x4444_4444);
    assert_eq!(field(&img, OFF_FFREE),   0x5555_5555);
    assert_eq!(field(&img, OFF_FSID),    0x6666_6666_7777_7777);
    assert_eq!(field(&img, OFF_NAMELEN), 255);
    assert_eq!(field(&img, OFF_FRSIZE),  1024);
    assert_eq!(field(&img, OFF_FLAGS),   ST_RDONLY | ST_NOSUID);
}

#[test]
fn offsets_are_the_linux_uapi_values() {
    assert_eq!((OFF_TYPE, OFF_BSIZE, OFF_BLOCKS, OFF_BFREE), (0, 8, 16, 24));
    assert_eq!((OFF_BAVAIL, OFF_FILES, OFF_FFREE, OFF_FSID), (32, 40, 48, 56));
    assert_eq!((OFF_NAMELEN, OFF_FRSIZE, OFF_FLAGS, OFF_SPARE), (64, 72, 80, 88));
}

#[test]
fn f_spare_tail_is_zeroed() {
    let img = encode_statfs(&sample());
    assert!(img[OFF_SPARE..].iter().all(|&b| b == 0), "f_spare[4] must be zero");
    assert_eq!(STATFS_BYTES - OFF_SPARE, 32, "f_spare is 4 LP64 words");
}

#[test]
fn zero_block_accounting_is_reported_verbatim() {
    // A pseudo filesystem (procfs, sysfs, cgroup2) has no blocks. Linux
    // `simple_statfs` reports zeros; fabricating a 1-block/0-free row so `df`
    // keeps the line would invent capacity that does not exist.
    let st = SbStatFs { f_type: 0x9fa0, f_bsize: 4096, f_namelen: 255, f_frsize: 4096, ..Default::default() };
    let img = encode_statfs(&st);
    assert_eq!(field(&img, OFF_TYPE), 0x9fa0);
    for off in [OFF_BLOCKS, OFF_BFREE, OFF_BAVAIL, OFF_FILES, OFF_FFREE] {
        assert_eq!(field(&img, off), 0, "pseudo-fs accounting must stay zero at offset {off}");
    }
}

/// `calculate_f_flags` sets ST_VALID unconditionally; glibc's `statvfs` reads
/// it to decide whether `f_flags` means anything. Without it every mount looks
/// like a kernel too old to report mount flags.
#[test]
fn st_valid_is_always_set_even_for_a_flagless_mount() {
    assert_eq!(st_flags(0, 0), ST_VALID);
    assert_ne!(st_flags(0, 0) & ST_VALID, 0);
    let img = encode_statfs(&SbStatFs { f_flags: st_flags(0, 0), ..sample() });
    assert_eq!(field(&img, OFF_FLAGS) & ST_VALID, ST_VALID);
}

#[test]
fn mount_flags_map_by_name_to_statvfs_bits() {
    use vfs::mount::{MNT_NOATIME, MNT_NODEV, MNT_NODIRATIME, MNT_NOEXEC, MNT_NOSUID, MNT_NOSYMFOLLOW, MNT_RDONLY, MNT_RELATIME};
    assert_eq!(st_flags(MNT_RDONLY, 0), ST_VALID | ST_RDONLY);
    assert_eq!(st_flags(MNT_NOSUID, 0), ST_VALID | ST_NOSUID);
    assert_eq!(st_flags(MNT_NODEV, 0), ST_VALID | ST_NODEV);
    assert_eq!(st_flags(MNT_NOEXEC, 0), ST_VALID | ST_NOEXEC);
    assert_eq!(st_flags(MNT_NOATIME, 0), ST_VALID | ST_NOATIME);
    assert_eq!(st_flags(MNT_NODIRATIME, 0), ST_VALID | ST_NODIRATIME);
    assert_eq!(st_flags(MNT_RELATIME, 0), ST_VALID | ST_RELATIME);
    assert_eq!(st_flags(MNT_NOSYMFOLLOW, 0), ST_VALID | ST_NOSYMFOLLOW);
    // The mapping is by NAME, not a raw copy: MNT_RELATIME and ST_RELATIME are
    // different bit positions.
    assert_ne!(MNT_RELATIME, ST_RELATIME);
    assert_ne!(MNT_NOSYMFOLLOW, ST_NOSYMFOLLOW);
}

#[test]
fn superblock_flags_contribute_their_own_statvfs_bits() {
    use vfs::superblock::{SB_MANDLOCK, SB_RDONLY, SB_SYNCHRONOUS};
    assert_eq!(st_flags(0, SB_SYNCHRONOUS), ST_VALID | ST_SYNCHRONOUS);
    assert_eq!(st_flags(0, SB_MANDLOCK), ST_VALID | ST_MANDLOCK);
    // A read-only SUPERBLOCK reports ST_RDONLY even on a mount without
    // MNT_RDONLY (Linux `flags_by_sb`).
    assert_eq!(st_flags(0, SB_RDONLY), ST_VALID | ST_RDONLY);
}

#[test]
fn mount_and_superblock_flag_sets_union() {
    use vfs::mount::{MNT_NOEXEC, MNT_NOSUID};
    use vfs::superblock::SB_RDONLY;
    assert_eq!(st_flags(MNT_NOSUID | MNT_NOEXEC, SB_RDONLY),
               ST_VALID | ST_NOSUID | ST_NOEXEC | ST_RDONLY);
}

#[test]
fn statvfs_bit_values_match_linux_statfs_h() {
    assert_eq!(ST_RDONLY, 0x0001);
    assert_eq!(ST_NOSUID, 0x0002);
    assert_eq!(ST_NODEV, 0x0004);
    assert_eq!(ST_NOEXEC, 0x0008);
    assert_eq!(ST_SYNCHRONOUS, 0x0010);
    assert_eq!(ST_VALID, 0x0020);
    assert_eq!(ST_MANDLOCK, 0x0040);
    // 0x0080/0x0100/0x0200 are glibc's ST_WRITE/ST_APPEND/ST_IMMUTABLE and are
    // never set by the kernel.
    assert_eq!(ST_NOATIME, 0x0400);
    assert_eq!(ST_NODIRATIME, 0x0800);
    assert_eq!(ST_RELATIME, 0x1000);
    assert_eq!(ST_NOSYMFOLLOW, 0x2000);
}
