//! `IS_IMMUTABLE`/`IS_APPEND`/`IS_NOATIME`/`IS_SYNC` predicates (Linux
//! `include/linux/fs.h` `IS_*` macros) over `Inode::i_flags`, plus the
//! Linux-exact numeric reps of the added `S_*` flag bits (`S_DAX`/`S_ENCRYPTED`/
//! `S_CASEFOLD`/`S_VERITY`). The predicates are the reusable VFS primitives the
//! write/open/atime paths call instead of open-coding `i_flags() & S_FOO`.

use vfs::inode::{
    is_append, is_immutable, is_noatime, is_sync, Inode, S_APPEND, S_CASEFOLD, S_DAX, S_DEAD,
    S_DIRSYNC, S_ENCRYPTED, S_IMMUTABLE, S_NOATIME, S_SYNC, S_VERITY,
};
use vfs::{FileType, InodeRef, KResult, VfsError};

struct FlagFile { flags: u32 }
impl Inode for FlagFile {
    fn ino(&self) -> vfs::Ino { 1 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn i_flags(&self) -> u32 { self.flags }
}

/// The added `S_*` bits match Linux `include/linux/fs.h` numeric reps exactly.
#[test]
fn s_flag_bits_match_linux() {
    assert_eq!(S_SYNC, 1 << 0);
    assert_eq!(S_NOATIME, 1 << 1);
    assert_eq!(S_APPEND, 1 << 2);
    assert_eq!(S_IMMUTABLE, 1 << 3);
    assert_eq!(S_DEAD, 1 << 4);
    assert_eq!(S_DIRSYNC, 1 << 6);
    assert_eq!(S_DAX, 1 << 13);
    assert_eq!(S_ENCRYPTED, 1 << 14);
    assert_eq!(S_CASEFOLD, 1 << 15);
    assert_eq!(S_VERITY, 1 << 16);
}

/// Each predicate keys ONLY on its own bit.
#[test]
fn predicates_isolate_their_bit() {
    let imm = FlagFile { flags: S_IMMUTABLE };
    assert!(is_immutable(&imm));
    assert!(!is_append(&imm));
    assert!(!is_noatime(&imm));
    assert!(!is_sync(&imm));

    let app = FlagFile { flags: S_APPEND };
    assert!(is_append(&app));
    assert!(!is_immutable(&app));

    let na = FlagFile { flags: S_NOATIME };
    assert!(is_noatime(&na));
    assert!(!is_sync(&na));

    let sy = FlagFile { flags: S_SYNC };
    assert!(is_sync(&sy));
    assert!(!is_immutable(&sy));
}

/// A no-flags inode answers `false` to every predicate; a combined flag word
/// answers `true` for each set bit.
#[test]
fn none_and_combined() {
    let plain = FlagFile { flags: 0 };
    assert!(!is_immutable(&plain) && !is_append(&plain) && !is_noatime(&plain) && !is_sync(&plain));

    let both = FlagFile { flags: S_IMMUTABLE | S_APPEND };
    assert!(is_immutable(&both));
    assert!(is_append(&both));
    assert!(!is_noatime(&both));
}
