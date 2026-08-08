//! Queue-name validation for `mq_open(2)` / `mq_unlink(2)`.

use syscall::errno::Errno;

use super::limits::{NAME_MAX, PATH_MAX};

/// The name ladder as the KERNEL sees it. glibc (and this tree's libc) strip
/// the leading `/` before the syscall, so a kernel-visible mq name is a single
/// path component under the per-namespace mqueue root:
///
/// 1. Name copy-in: the empty string is `ENOENT`; a string that
///    does not fit in `PATH_MAX` bytes including its NUL is `ENAMETOOLONG`.
/// 2. Path-component validation, reached through
///    the create/remove lookup path: `.`, `..`, or any
///    embedded `/` or NUL is `EACCES`.
/// 3. mqueuefs's `->lookup`: a component
///    longer than `NAME_MAX` is `ENAMETOOLONG`.
///
/// The ORDER is the contract: an over-long name that also contains a `/` is
/// `EACCES`, because step 2 runs before the `->lookup` of step 3.
/// # C: O(name.len())
pub fn check_name(name: &str) -> Result<(), Errno> {
    if name.is_empty() { return Err(Errno::Enoent); }
    if name.len() >= PATH_MAX { return Err(Errno::Enametoolong); }
    if name == "." || name == ".." { return Err(Errno::Eacces); }
    if name.as_bytes().iter().any(|&c| c == b'/' || c == 0) { return Err(Errno::Eacces); }
    if name.len() > NAME_MAX { return Err(Errno::Enametoolong); }
    Ok(())
}
