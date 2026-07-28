//! `struct file_attr` ABI conformance for `file_getattr(2)`/`file_setattr(2)`
//! (slots 468/469). Every case cites the Linux `fs/file_attr.c` /
//! `include/linux/fileattr.h` / `uapi/linux/fs.h` rule it pins.
//!
//! Before F761 both slots were stubs: they resolved the path, then wrote 24
//! zero bytes (getattr) or rejected any non-zero field with `EOPNOTSUPP`
//! (setattr). They never reached `vfs_fileattr_{get,set}`, never validated
//! `at_flags`, never enforced the `usize > PAGE_SIZE` `E2BIG` bound, and never
//! honoured `copy_struct_{from,to}_user`'s trailing-byte contract.

use fs::fileattr::{FILE_ATTR_SIZE_VER0, check_struct_size, decode, encode, map_backend_err,
                   read_user, write_user};
use syscall::errno::Errno;
use vfs::FileAttr;
use vfs::inode::{FS_APPEND_FL, FS_IMMUTABLE_FL, FS_XFLAG_APPEND, FS_XFLAG_CASEFOLD,
                 FS_XFLAG_COWEXTSIZE, FS_XFLAG_EXTSIZE, FS_XFLAG_IMMUTABLE, FS_XFLAG_VERITY,
                 FS_XFLAGS_MASK};

fn e(x: Errno) -> i64 { -(x.as_i32() as i64) }

/// A VER0 `struct file_attr` image, plus `pad` trailing bytes.
fn img(xflags: u64, extsize: u32, nextents: u32, projid: u32, cowextsize: u32, pad: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&xflags.to_le_bytes());
    v.extend_from_slice(&extsize.to_le_bytes());
    v.extend_from_slice(&nextents.to_le_bytes());
    v.extend_from_slice(&projid.to_le_bytes());
    v.extend_from_slice(&cowextsize.to_le_bytes());
    v.extend_from_slice(pad);
    v
}

// --- the `usize` handshake (`fs/file_attr.c:393`, `:449`) ------------------

#[test]
fn struct_size_below_ver0_is_einval_and_over_a_page_is_e2big() {
    assert_eq!(FILE_ATTR_SIZE_VER0, 24, "uapi/linux/fs.h FILE_ATTR_SIZE_VER0");
    assert_eq!(check_struct_size(0), Err(e(Errno::Einval)));
    assert_eq!(check_struct_size(23), Err(e(Errno::Einval)));
    assert_eq!(check_struct_size(24), Ok(()));
    assert_eq!(check_struct_size(hal::PAGE_SIZE_BYTES as usize), Ok(()));
    // The stub had no upper bound at all — any huge `usize` was accepted.
    assert_eq!(check_struct_size(hal::PAGE_SIZE_BYTES as usize + 1), Err(e(Errno::E2big)));
    assert_eq!(check_struct_size(1 << 20), Err(e(Errno::E2big)));
}

// --- `copy_struct_from_user` + `file_attr_to_fileattr` (`:141`) ------------

#[test]
fn unknown_trailing_bytes_must_be_zero() {
    // `copy_struct_from_user`: `check_zeroed_user` on the tail, `-E2BIG` if set.
    assert!(decode(&img(0, 0, 0, 0, 0, &[0u8; 8])).is_ok());
    assert_eq!(decode(&img(0, 0, 0, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0])), Err(e(Errno::E2big)));
}

#[test]
fn xflags_outside_fs_xflags_mask_are_einval() {
    // `file_attr_to_fileattr`: `if (fattr->fa_xflags & ~mask) return -EINVAL;`
    // NOT `-EOPNOTSUPP` — that is what the *ioctl* (`copy_fsxattr_from_user`)
    // returns, and what the old stub returned for every non-zero field.
    assert_eq!(decode(&img(1 << 40, 0, 0, 0, 0, &[])), Err(e(Errno::Einval)));
    assert_eq!(decode(&img(0x0000_0004, 0, 0, 0, 0, &[])), Err(e(Errno::Einval)));
    assert!(decode(&img(FS_XFLAGS_MASK as u64, 0, 0, 0, 0, &[])).is_ok());
}

#[test]
fn set_drops_readonly_xflags_and_ignores_nextents() {
    // `fileattr_fill_xflags(fa, fattr->fa_xflags & ~FS_XFLAG_RDONLY_MASK)`, and
    // `fa_nextents` is get-only: `file_attr_to_fileattr` never reads it.
    let fa = decode(&img((FS_XFLAG_APPEND | FS_XFLAG_VERITY | FS_XFLAG_CASEFOLD) as u64,
                         4096, 0xdead_beef, 7, 8192, &[])).unwrap();
    assert_eq!(fa.fsx_xflags, FS_XFLAG_APPEND, "VERITY/CASEFOLD are read-only xflags");
    assert_eq!(fa.flags, FS_APPEND_FL, "fileattr_fill_xflags derives the FS_*_FL view");
    assert_eq!(fa.fsx_extsize, 4096);
    assert_eq!(fa.fsx_projid, 7);
    assert_eq!(fa.fsx_cowextsize, 8192);
    assert_eq!(fa.fsx_nextents, 0, "fa_nextents is get-only");
}

#[test]
fn set_translates_every_settable_xflag_to_its_fs_fl_twin() {
    let fa = decode(&img((FS_XFLAG_IMMUTABLE | FS_XFLAG_EXTSIZE | FS_XFLAG_COWEXTSIZE) as u64,
                         1, 0, 0, 1, &[])).unwrap();
    assert_eq!(fa.flags, FS_IMMUTABLE_FL);
    assert_eq!(fa.fsx_xflags, FS_XFLAG_IMMUTABLE | FS_XFLAG_EXTSIZE | FS_XFLAG_COWEXTSIZE);
}

// --- `fileattr_to_file_attr` (`:102`) -------------------------------------

#[test]
fn get_masks_reported_xflags_and_reports_nextents() {
    let fa = FileAttr { flags: FS_IMMUTABLE_FL, fsx_xflags: FS_XFLAG_IMMUTABLE | (1 << 22),
                        fsx_extsize: 11, fsx_nextents: 22, fsx_projid: 33, fsx_cowextsize: 44 };
    let b = encode(&fa);
    assert_eq!(u64::from_le_bytes(b[0..8].try_into().unwrap()), FS_XFLAG_IMMUTABLE as u64,
               "fa_xflags = fa->fsx_xflags & FS_XFLAGS_MASK");
    assert_eq!(u32::from_le_bytes(b[8..12].try_into().unwrap()), 11);
    assert_eq!(u32::from_le_bytes(b[12..16].try_into().unwrap()), 22, "fa_nextents @12");
    assert_eq!(u32::from_le_bytes(b[16..20].try_into().unwrap()), 33, "fa_projid @16");
    assert_eq!(u32::from_le_bytes(b[20..24].try_into().unwrap()), 44, "fa_cowextsize @20");
}

// --- the user-buffer edge --------------------------------------------------

#[test]
fn write_user_zero_fills_the_caller_declared_tail() {
    // `copy_struct_to_user`: `clear_user(dst + ksize, usize - ksize)`. The stub
    // wrote exactly 24 bytes, so a newer userspace read stale memory.
    let mut buf = vec![0xAAu8; 64];
    let p = buf.as_mut_ptr() as u64;
    let fa = FileAttr { fsx_projid: 5, ..Default::default() };
    assert_eq!(write_user(p, 40, &fa), 0);
    assert_eq!(u32::from_le_bytes(buf[16..20].try_into().unwrap()), 5);
    assert!(buf[24..40].iter().all(|b| *b == 0), "tail must be cleared, got {:?}", &buf[24..40]);
    assert!(buf[40..].iter().all(|b| *b == 0xAA), "nothing past usize may be touched");
}

#[test]
fn user_edge_rejects_null_and_bad_sizes_before_touching_memory() {
    assert_eq!(read_user(0, 24), Err(e(Errno::Efault)));
    assert_eq!(read_user(0, 8), Err(e(Errno::Einval)), "size handshake outranks EFAULT");
    assert_eq!(write_user(0, 1 << 20, &FileAttr::default()), e(Errno::E2big));
}

#[test]
fn read_user_round_trips_a_ver0_image() {
    let src = img(FS_XFLAG_IMMUTABLE as u64, 512, 0, 9, 0, &[0u8; 16]);
    let fa = read_user(src.as_ptr() as u64, src.len()).unwrap();
    assert_eq!(fa.fsx_xflags, FS_XFLAG_IMMUTABLE);
    assert_eq!(fa.flags, FS_IMMUTABLE_FL);
    assert_eq!(fa.fsx_extsize, 512);
    assert_eq!(fa.fsx_projid, 9);
}

// --- backend errno translation (`:418`, `:481`) ---------------------------

#[test]
fn a_filesystem_without_fileattr_ops_answers_eopnotsupp() {
    // `if (error == -ENOIOCTLCMD || error == -ENOTTY) error = -EOPNOTSUPP;`
    assert_eq!(map_backend_err(vfs::VfsError::Enotty), e(Errno::Eopnotsupp));
    assert_eq!(map_backend_err(vfs::VfsError::Eperm), e(Errno::Eperm));
    assert_eq!(map_backend_err(vfs::VfsError::Einval), e(Errno::Einval));
}
