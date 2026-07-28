// execveat(2) AT_* flag policy — Linux `fs/exec.c` `do_open_execat` (l.774,
// the EINVAL mask + `LOOKUP_NO_FOLLOW`), `SYSCALL_DEFINE5(execveat)` (l.1953),
// `fs/namei.c` `do_getname` (l.204, empty-path ENOENT) and `may_open` (l.4236,
// the file-type ladder) as of linux-master v7.2.0-rc4.
//
// NOT target-gated: `322_execveat.rs` carries `#![cfg(target_os =
// "oxide-kernel")]`, so a `#[cfg(test)]` block inside it never compiles. The
// flag ladder, the empty-path rule, the dirfd-base decision and the
// file-type verdict live here where hosted `cargo test` reaches them.

use alloc::string::String;
use syscall::errno::Errno;

/// `include/uapi/linux/fcntl.h:132,138,190`.
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
pub const AT_EMPTY_PATH:       u32 = 0x1000;
pub const AT_EXECVE_CHECK:     u32 = 0x10000;
/// The complete set `do_open_execat` tolerates (`fs/exec.c:779`).
pub const AT_EXEC_VALID: u32 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_EXECVE_CHECK;

/// `AT_FDCWD` (`include/uapi/linux/fcntl.h`), re-stated here so the hosted
/// tests do not need the kernel-only `pathresolve` module.
pub const AT_FDCWD: i32 = -100;

/// `do_open_execat`'s first act, ahead of `do_file_open` — so an undefined
/// flag bit outranks the `EFAULT`/`ENOENT` a bad or empty pathname produces
/// (`do_file_open` only unwraps the `getname_uflags` error AFTER this check).
/// # C: O(1)
pub fn validate_flags(flags: u32) -> Result<(), Errno> {
    if flags & !AT_EXEC_VALID != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// `getname_uflags` maps `AT_EMPTY_PATH` to `LOOKUP_EMPTY`; without it
/// `do_getname` turns the empty pathname into `ENOENT` (`fs/namei.c:202`).
/// # C: O(1)
pub fn empty_path_verdict(flags: u32) -> Result<(), Errno> {
    if flags & AT_EMPTY_PATH == 0 { return Err(Errno::Enoent); }
    Ok(())
}

/// Whether `dirfd` participates in resolving `raw`. `path_init` jumps straight
/// to the resolution root for an absolute pathname and never consults `dfd`,
/// and `AT_FDCWD` is the cwd the plain execve path already walks from — every
/// other combination MUST start at the dirfd.
/// # C: O(1)
pub fn needs_dirfd_base(dirfd: i32, raw: &str) -> bool {
    dirfd != AT_FDCWD && !raw.starts_with('/')
}

/// Splice a dirfd's rendered directory path with the caller's relative path.
/// `dir` is an absolute path (possibly bare `/`); the result never doubles the
/// separator and never loses a leading `/`.
/// # C: O(dir + rel)
pub fn join_dirfd_path(dir: &str, rel: &str) -> String {
    let mut out = String::from(dir.trim_end_matches('/'));
    if out.is_empty() { out.push('/'); }
    if !out.ends_with('/') { out.push('/'); }
    out.push_str(rel.trim_start_matches('/'));
    out
}

/// The exec target's file-type verdict from `may_open(..., MAY_EXEC, ...)`
/// (`fs/namei.c:4246`): a symlink reached with `LOOKUP_NO_FOLLOW` is `ELOOP`,
/// a directory or any non-regular file is `EACCES`, a regular file proceeds to
/// the DAC `inode_permission` test.
/// # C: O(1)
pub fn may_exec_file_type(ft: vfs::FileType) -> Result<(), Errno> {
    match ft {
        vfs::FileType::Symlink => Err(Errno::Eloop),
        vfs::FileType::Regular => Ok(()),
        _ => Err(Errno::Eacces),
    }
}

/// The pathname `alloc_bprm` records for an `AT_EMPTY_PATH` exec
/// (`fs/exec.c:1444`: `kasprintf(..., "/dev/fd/%d", fd)`). oxide's
/// `pathresolve::lookup::dup_fd_target` recognises exactly this spelling as a
/// pure string fast-path — `proc_fd_file` hands back the OPEN FILE
/// DESCRIPTION's inode with no `/proc` mount involved — so exec'ing the fd
/// directly needs no `/proc` and works for a sealed memfd whose synthetic
/// d_path could never re-resolve.
/// # C: O(1)
pub fn fd_exec_path(fd: i32) -> String {
    use core::fmt::Write as _;
    let mut s = String::from("/dev/fd/");
    let _ = write!(s, "{}", fd);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_three_documented_flags_are_accepted() {
        assert_eq!(validate_flags(0), Ok(()));
        assert_eq!(validate_flags(AT_EMPTY_PATH), Ok(()));
        assert_eq!(validate_flags(AT_SYMLINK_NOFOLLOW), Ok(()));
        assert_eq!(validate_flags(AT_EXECVE_CHECK), Ok(()));
        assert_eq!(validate_flags(AT_EXEC_VALID), Ok(()));
    }

    #[test]
    fn any_other_bit_is_einval() {
        // AT_SYMLINK_FOLLOW (0x400) and AT_NO_AUTOMOUNT (0x800) are valid for
        // other *at() syscalls and rejected here.
        assert_eq!(validate_flags(0x400), Err(Errno::Einval));
        assert_eq!(validate_flags(0x800), Err(Errno::Einval));
        assert_eq!(validate_flags(AT_EMPTY_PATH | 0x1), Err(Errno::Einval));
        assert_eq!(validate_flags(0x8000_0000), Err(Errno::Einval));
    }

    #[test]
    fn an_empty_pathname_needs_at_empty_path() {
        assert_eq!(empty_path_verdict(0), Err(Errno::Enoent));
        assert_eq!(empty_path_verdict(AT_SYMLINK_NOFOLLOW), Err(Errno::Enoent));
        assert_eq!(empty_path_verdict(AT_EMPTY_PATH), Ok(()));
    }

    #[test]
    fn dirfd_is_the_base_only_for_a_relative_path_and_a_real_fd() {
        assert!(needs_dirfd_base(5, "rel/path"));
        assert!(needs_dirfd_base(5, "prog"));
        assert!(!needs_dirfd_base(5, "/abs/path"));
        assert!(!needs_dirfd_base(AT_FDCWD, "rel/path"));
        assert!(!needs_dirfd_base(AT_FDCWD, "/abs/path"));
    }

    #[test]
    fn joining_never_doubles_or_drops_a_separator() {
        assert_eq!(join_dirfd_path("/a/b", "c/d"), "/a/b/c/d");
        assert_eq!(join_dirfd_path("/a/b/", "c/d"), "/a/b/c/d");
        assert_eq!(join_dirfd_path("/", "c"), "/c");
        assert_eq!(join_dirfd_path("/a", "./c"), "/a/./c");
        assert_eq!(join_dirfd_path("", "c"), "/c");
    }

    #[test]
    fn the_file_type_ladder_matches_may_open() {
        assert_eq!(may_exec_file_type(vfs::FileType::Regular), Ok(()));
        assert_eq!(may_exec_file_type(vfs::FileType::Symlink), Err(Errno::Eloop));
        assert_eq!(may_exec_file_type(vfs::FileType::Directory), Err(Errno::Eacces));
        assert_eq!(may_exec_file_type(vfs::FileType::CharDev), Err(Errno::Eacces));
        assert_eq!(may_exec_file_type(vfs::FileType::BlockDev), Err(Errno::Eacces));
        assert_eq!(may_exec_file_type(vfs::FileType::Fifo), Err(Errno::Eacces));
        assert_eq!(may_exec_file_type(vfs::FileType::Socket), Err(Errno::Eacces));
    }

    #[test]
    fn the_fd_exec_path_is_the_dev_fd_spelling_linux_records() {
        assert_eq!(fd_exec_path(3), "/dev/fd/3");
        assert_eq!(fd_exec_path(0), "/dev/fd/0");
        assert_eq!(fd_exec_path(1023), "/dev/fd/1023");
    }
}
