// fsconfig(2) 431, stage two: copying `_key`, `_value` and the `SET_BINARY`
// blob in from user memory, in the reference's order and with the reference's
// per-stage errno.
//
// Ungated on purpose. `431_fsconfig.rs` is `#![cfg(target_os =
// "oxide-kernel")]`, so every EFAULT rung written there is untestable — a
// `#[cfg(test)]` block in that file compiles out silently (docs/53, CLAUDE.md
// phantom-test rule). The user-memory ACCESS is the only part that needs the
// kernel; which read happens, in what order, and what a failed read reports are
// decisions, and they live here behind [`UserCopy`] so a hosted test can fault
// any one of them and assert what comes back.
//
// Ordering is observable: a call with BOTH a bad key pointer and a bad value
// pointer reports the KEY's failure, and a `SET_PATH` with a bad pointer is
// EFAULT while the same command with a readable EMPTY pathname is ENOENT.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::fsconfig_abi::{self, FsconfigCmd, ValueKind};

/// The user-memory reads `fsconfig(2)` performs. The kernel implementation is
/// the bounded copy-in helpers; a hosted test supplies a map of readable
/// regions so the faulting rungs are reachable.
pub trait UserCopy {
    /// `strndup_user(ptr, max)`'s raw half: the bytes up to the first NUL or
    /// `max` bytes, whichever comes first, with NO terminator. Returning
    /// exactly `max` bytes is how "did not terminate inside the bound" is
    /// reported — [`fsconfig_abi::strndup_admit`] turns that into EINVAL rather
    /// than a silent prefix. `Err(Efault)` for an unreadable pointer.
    fn cstr(&self, ptr: u64, max: usize) -> Result<Vec<u8>, Errno>;
    /// `memdup_user(ptr, len)` — the `FSCONFIG_SET_BINARY` blob, exactly `len`
    /// bytes, NUL included.
    fn bytes(&self, ptr: u64, len: usize) -> Result<Vec<u8>, Errno>;
}

/// What the copy-in produced, ready to become an `FsParameter`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Fetched {
    /// Empty for the `CMD_*` trio, which carry no key.
    pub key:   String,
    /// Empty unless the command reads a string or a pathname value.
    pub value: String,
    /// `Some` only for `FSCONFIG_SET_BINARY`.
    pub blob:  Option<Vec<u8>>,
}

/// Copy in everything the command names, in the reference's order.
///
/// The key is read FIRST for every command that carries one, so a call that
/// gets both pointers wrong reports the key's failure — the same rung the
/// reference reaches first. Path values are decoded with the reversible path
/// codec rather than being required to be UTF-8: pathname bytes are opaque, and
/// a `journal_path=` naming a non-UTF-8 file must reach the filesystem
/// unchanged instead of becoming EINVAL here.
/// # C: O(len key + len value + aux)
pub fn fetch<U: UserCopy>(cmd: FsconfigCmd, key_ptr: u64, value_ptr: u64, aux: i32, u: &U)
    -> Result<Fetched, Errno>
{
    let key = if cmd.takes_key() {
        let raw = u.cstr(key_ptr, fsconfig_abi::KEY_MAX)?;
        fsconfig_abi::strndup_admit(&raw, fsconfig_abi::KEY_MAX)?.to_string()
    } else { String::new() };

    let (value, blob) = match cmd.value_kind() {
        ValueKind::None => (String::new(), None),
        ValueKind::Str => {
            let raw = u.cstr(value_ptr, fsconfig_abi::VALUE_MAX)?;
            (fsconfig_abi::strndup_admit(&raw, fsconfig_abi::VALUE_MAX)?.to_string(), None)
        }
        ValueKind::Path { empty_ok } => {
            let raw = u.cstr(value_ptr, vfs::path::PATH_MAX)?;
            let path = vfs::path_from_bytes(&raw);
            if !path.is_empty() {
                vfs::path::check_path_len(&path).map_err(|_| Errno::Enametoolong)?;
            }
            fsconfig_abi::admit_path_value(&path, empty_ok)?;
            (path, None)
        }
        ValueKind::Blob => {
            // `aux` is bounded to `(0, BINARY_MAX]` by the admission switch, so
            // the cast cannot be negative and cannot overflow the allocation.
            (String::new(), Some(u.bytes(value_ptr, aux as usize)?))
        }
    };
    Ok(Fetched { key, value, blob })
}
