// Slots 246 `kexec_load` and 320 `kexec_file_load`: the ABI decisions that do
// not need the kernel.
//
// Ungated on purpose. The slot files carry `#![cfg(target_os =
// "oxide-kernel")]`, so a `#[cfg(test)]` block inside either would compile out
// silently and report "ok" having built nothing (CLAUDE.md, phantom tests).
// The errno mapping and the argument decoding live here so they are checked.

use syscall::errno::Errno;

/// Map a kexec refusal to its errno return value.
///
/// Every arm is a value a real `kexec-tools` distinguishes:
/// `EPERM` "you may not", `EINVAL` "your request is malformed",
/// `EADDRNOTAVAIL` "that physical address is not usable", `EBUSY` "another
/// load or a kexec reboot is in flight", `ENOEXEC` "no loader recognises this
/// kernel file".
/// # C: O(1)
pub fn errno_for(e: kexec::Error) -> i64 {
    let n = match e {
        kexec::Error::Perm => Errno::Eperm,
        kexec::Error::Inval => Errno::Einval,
        kexec::Error::AddrNotAvail => Errno::Eaddrnotavail,
        kexec::Error::Nomem => Errno::Enomem,
        kexec::Error::Busy => Errno::Ebusy,
        kexec::Error::Fault => Errno::Efault,
        kexec::Error::BadFd => Errno::Ebadf,
        kexec::Error::NoExec => Errno::Enoexec,
        // The relocation trampoline is not built (`kexec::machine`). Not a
        // value the reference returns here, and deliberately distinct from the
        // two refusals it does make, so "this kernel cannot jump" can never be
        // read as "no image was loaded" or "try again".
        kexec::Error::NoSys => Errno::Enosys,
    };
    -(n.as_i32() as i64)
}

/// Result encoding for a kexec work-fn: 0, or the negative errno.
/// # C: O(1)
pub fn encode(r: kexec::KResult<()>) -> i64 {
    match r { Ok(()) => 0, Err(e) => errno_for(e) }
}

/// Bytes the segment array occupies, refusing an `nr_segments` whose array
/// would overflow the address space. The cap is applied before this, so the
/// product is small in practice — but a caller that passes `u64::MAX` must get
/// a refusal, never a wrapped length that reads a few bytes and calls it an
/// array (Linux's `memdup_array_user` overflow test).
/// # C: O(1)
pub fn segment_array_bytes(nr_segments: u64) -> Option<u64> {
    nr_segments.checked_mul(kexec::KEXEC_SEGMENT_SIZE as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_refusal_maps_to_the_errno_a_loader_can_act_on() {
        assert_eq!(errno_for(kexec::Error::Perm), -1);
        assert_eq!(errno_for(kexec::Error::Inval), -22);
        assert_eq!(errno_for(kexec::Error::AddrNotAvail), -99);
        assert_eq!(errno_for(kexec::Error::Nomem), -12);
        assert_eq!(errno_for(kexec::Error::Busy), -16);
        assert_eq!(errno_for(kexec::Error::Fault), -14);
        assert_eq!(errno_for(kexec::Error::BadFd), -9);
        assert_eq!(errno_for(kexec::Error::NoExec), -8);
        assert_eq!(errno_for(kexec::Error::NoSys), -38);
    }

    #[test]
    fn success_encodes_as_zero_and_never_as_a_positive_count() {
        assert_eq!(encode(Ok(())), 0);
        assert_eq!(encode(Err(kexec::Error::Busy)), -16);
    }

    #[test]
    fn a_segment_count_whose_array_would_overflow_is_refused() {
        assert_eq!(segment_array_bytes(0), Some(0));
        assert_eq!(segment_array_bytes(16), Some(512));
        assert_eq!(segment_array_bytes(u64::MAX), None);
    }

    /// The two slots are implemented, at the numbers Linux assigns them.
    /// The aarch64 route and the misroute pin live with the table itself, in
    /// `syscall::arm_abi`'s tests — that module is not compiled into a hosted
    /// build of THIS crate, so a check written here could never fail.
    #[test]
    fn the_slot_numbers_are_the_ones_linux_assigns() {
        assert_eq!(syscall::nrs::NR_KEXEC_LOAD, 246);
        assert_eq!(syscall::nrs::NR_KEXEC_FILE_LOAD, 320);
    }
}
