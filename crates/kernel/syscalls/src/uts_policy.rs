// sethostname(2) / setdomainname(2) prologue — Linux `kernel/sys.c`.
//
// Kept OUTSIDE the `target_os = "oxide-kernel"` gate so `cargo test -p
// syscalls` exercises the ORDER, which is the only observable part of a
// rejected call (`CLAUDE.md` "Verify left").

use syscall::errno::Errno;

/// Linux `__NEW_UTS_LEN` (`include/uapi/linux/utsname.h`): 64 bytes, NOT
/// counting the terminating NUL that `new_utsname.nodename[65]` holds.
pub const NEW_UTS_LEN: usize = 64;

/// The shared prologue of `SYSCALL_DEFINE2(sethostname)` and
/// `SYSCALL_DEFINE2(setdomainname)`:
///
/// ```text
/// if (!ns_capable(current->nsproxy->uts_ns->user_ns, CAP_SYS_ADMIN))
///         return -EPERM;
/// if (len < 0 || len > __NEW_UTS_LEN)
///         return -EINVAL;
/// errno = -EFAULT;
/// if (!copy_from_user(tmp, name, len)) { ... }
/// ```
///
/// Three things are load-bearing:
/// * EPERM comes FIRST — an unprivileged caller passing a bogus length sees
///   EPERM, never EINVAL, and never learns whether the length was valid.
/// * `len` is declared `int`, so only the low 32 bits of the syscall register
///   are significant and a negative value is EINVAL. Treating the raw 64-bit
///   register as the length turns `len = 0x1_0000_0020` (a valid 32) into a
///   spurious EINVAL.
/// * EFAULT is last, so it can only be reported for an accepted length.
/// # C: O(1)
pub fn check_uts_set(len_raw: u64, permitted: bool) -> Result<usize, Errno> {
    if !permitted { return Err(Errno::Eperm); }
    let len = len_raw as u32 as i32;
    if len < 0 || len as usize > NEW_UTS_LEN { return Err(Errno::Einval); }
    Ok(len as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eperm_precedes_the_length_window() {
        assert_eq!(check_uts_set(0, false), Err(Errno::Eperm));
        assert_eq!(check_uts_set(u64::MAX, false), Err(Errno::Eperm));
        assert_eq!(check_uts_set(NEW_UTS_LEN as u64 + 1, false), Err(Errno::Eperm));
    }

    #[test]
    fn negative_length_is_einval() {
        assert_eq!(check_uts_set(-1i64 as u64, true), Err(Errno::Einval));
        assert_eq!(check_uts_set(-64i64 as u64, true), Err(Errno::Einval));
    }

    #[test]
    fn length_window_is_new_uts_len_inclusive() {
        assert_eq!(NEW_UTS_LEN, 64);
        assert_eq!(check_uts_set(0, true), Ok(0));
        assert_eq!(check_uts_set(64, true), Ok(64));
        assert_eq!(check_uts_set(65, true), Err(Errno::Einval));
    }

    #[test]
    fn only_the_low_32_bits_of_len_are_significant() {
        // `int len` — Linux truncates. 0x1_0000_0020 is 32, an accepted length.
        assert_eq!(check_uts_set(0x1_0000_0020, true), Ok(32));
        // ...and 0x1_FFFF_FFFF truncates to -1, which is EINVAL.
        assert_eq!(check_uts_set(0x1_FFFF_FFFF, true), Err(Errno::Einval));
    }
}
