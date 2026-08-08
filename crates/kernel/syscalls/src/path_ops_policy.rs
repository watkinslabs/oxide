// Directory-operation decision core — the order-sensitive half of Linux's
// `filename_create` / `filename_mkdirat` / `filename_rmdir` /
// `filename_unlinkat` / `filename_symlinkat` / `filename_linkat` and
// `do_readlinkat`.
//
// Deliberately NOT `#![cfg(target_os = "oxide-kernel")]`: the slot files
// (083/084/086/087/088/089/258/263/265/266/267/133) are kernel-only, so
// anything written inside them is invisible to `cargo test`. What these
// syscalls actually expose is an errno LADDER whose ORDER is the contract, so
// the rules live here and the slots stay thin shims (docs/53).
//
// Module manifest:
//   this file — leaf-component, existence, trailing-slash and buffer-size
//     decisions shared by the create and remove families.
//   tests/path_ops_policy.rs — hosted unit tests.
//   tests/path_ops_ladder_oracle.rs — differential vs. the host kernel.

use syscall::errno::Errno;

pub use crate::rename_policy::{has_trailing_slash, LastKind};

/// What a create op is bringing into existence. Only `mkdir` asks the walker
/// for a directory (Linux `LOOKUP_DIRECTORY`), and that single bit decides
/// whether a trailing slash on the new name is acceptable. # C: O(1)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CreateKind { Dir, NonDir }

/// `filename_create` step 1 — the leaf must be an ordinary name. `foo/.`,
/// `foo/..` and `/` all already name something that exists, so every one of
/// them is `EEXIST` regardless of what the caller was trying to create.
/// # C: O(1)
pub fn check_create_leaf_kind(last: LastKind) -> Result<(), Errno> {
    if last == LastKind::Norm { Ok(()) } else { Err(Errno::Eexist) }
}

/// `filename_create` step 2 — the final exclusive lookup. It always keeps
/// `LOOKUP_EXCL`, so an occupied name is `EEXIST`; it keeps `LOOKUP_CREATE`
/// only when the pathname's shape agrees with what is being made, so a
/// trailing slash on anything but a `mkdir` leaves the lookup unable to
/// create and a FREE name reports `ENOENT`.
///
/// Both verdicts precede the read-only-mount test, the cross-mount test and
/// every permission check, because Linux runs this lookup before applying the
/// deferred `mnt_want_write` error. # C: O(1)
pub fn check_create_leaf(exists: bool, trailing_slash: bool, kind: CreateKind)
    -> Result<(), Errno>
{
    if exists { return Err(Errno::Eexist); }
    if trailing_slash && kind == CreateKind::NonDir { return Err(Errno::Enoent); }
    Ok(())
}

/// `filename_rmdir`'s leaf verdict. Each non-ordinary leaf gets its own
/// errno, and they disagree with `unlink`'s: removing `.` is a request the
/// kernel cannot even name (`EINVAL`), removing `..` would leave the parent
/// non-empty (`ENOTEMPTY`), and a filesystem root is in use (`EBUSY`).
/// # C: O(1)
pub fn check_rmdir_leaf_kind(last: LastKind) -> Result<(), Errno> {
    match last {
        LastKind::Norm   => Ok(()),
        LastKind::Dot    => Err(Errno::Einval),
        LastKind::Dotdot => Err(Errno::Enotempty),
        LastKind::Root   => Err(Errno::Ebusy),
    }
}

/// `filename_unlinkat`'s leaf verdict: every non-ordinary leaf names a
/// directory, and `unlink` refuses directories with `EISDIR`. # C: O(1)
pub fn check_unlink_leaf_kind(last: LastKind) -> Result<(), Errno> {
    if last == LastKind::Norm { Ok(()) } else { Err(Errno::Eisdir) }
}

/// `filename_unlinkat`'s trailing-slash rule, applied AFTER the victim has
/// been found ("Why not before? Because we want correct error value"): `foo/`
/// asserts `foo` is a directory, so a directory victim reports the `unlink`
/// refusal `EISDIR` and a non-directory victim reports the broken assertion
/// `ENOTDIR`. A name that does not exist never reaches here — the lookup's
/// own `ENOENT` wins. # C: O(1)
pub fn check_unlink_trailing_slash(trailing_slash: bool, victim_is_dir: bool)
    -> Result<(), Errno>
{
    if !trailing_slash { return Ok(()); }
    Err(if victim_is_dir { Errno::Eisdir } else { Errno::Enotdir })
}

/// `do_readlinkat`'s buffer-size gate. `bufsiz` reaches the kernel as a
/// SIGNED int, so a caller passing a negative value gets `EINVAL` rather than
/// having it reinterpreted as an enormous length. Zero is equally rejected —
/// there is no "read zero bytes of a link" success. # C: O(1)
pub fn check_readlink_bufsiz(bufsiz: i32) -> Result<(), Errno> {
    if bufsiz <= 0 { return Err(Errno::Einval); }
    Ok(())
}

/// `readlink_copy` — the target is copied out truncated to the buffer, and the
/// RETURN VALUE is the truncated length. A too-small buffer is not an error
/// and there is no NUL terminator, so a caller cannot distinguish "exact fit"
/// from "truncated" except by retrying with a larger buffer. # C: O(1)
pub fn readlink_copy_len(target_len: usize, bufsiz: i32) -> usize {
    target_len.min(bufsiz.max(0) as usize)
}
