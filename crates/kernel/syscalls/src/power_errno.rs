// One mapping from the power crate's failure classes to errno.
//
// `power` is below `syscall` in the crate graph and cannot name `Errno`, so
// the translation lives here rather than being spelled out at each call site
// (`reboot(2)`, the `/sys/power/*` attribute stores).

use syscall::errno::Errno;

/// Errno for a power/sleep failure class (`32a§13`). # C: O(1)
pub fn of(e: power::Error) -> Errno {
    match e {
        power::Error::Inval  => Errno::Einval,
        power::Error::Perm   => Errno::Eperm,
        power::Error::Io     => Errno::Eio,
        power::Error::Busy   => Errno::Ebusy,
        power::Error::Nosys  => Errno::Enosys,
        power::Error::Opnotsupp => Errno::Eopnotsupp,
        power::Error::Again  => Errno::Eagain,
        power::Error::Intr   => Errno::Eintr,
        power::Error::Nomem  => Errno::Enomem,
        power::Error::Nodata => Errno::Enodata,
        power::Error::Nospc  => Errno::Enospc,
    }
}
