pub(crate) const AT_NULL: u64 = 0;
pub(crate) const AT_IGNORE: u64 = 1;
pub(crate) const AT_PHDR: u64 = 3;
pub(crate) const AT_PHENT: u64 = 4;
pub(crate) const AT_PHNUM: u64 = 5;
pub(crate) const AT_PAGESZ: u64 = 6;
pub(crate) const AT_BASE: u64 = 7;
pub(crate) const AT_FLAGS: u64 = 8;
pub(crate) const AT_ENTRY: u64 = 9;
pub(crate) const AT_UID: u64 = 11;
pub(crate) const AT_EUID: u64 = 12;
pub(crate) const AT_GID: u64 = 13;
pub(crate) const AT_EGID: u64 = 14;
pub(crate) const AT_PLATFORM: u64 = 15;
pub(crate) const AT_HWCAP: u64 = 16;
pub(crate) const AT_CLKTCK: u64 = 17;
pub(crate) const AT_SECURE: u64 = 23;
pub(crate) const AT_RANDOM: u64 = 25;
pub(crate) const AT_EXECFN: u64 = 31;
pub(crate) const AT_SYSINFO_EHDR: u64 = 33;
/// Linux `AT_MINSIGSTKSZ` (`include/uapi/linux/auxvec.h`): bytes of stack one
/// signal delivery needs on THIS CPU. Dynamic — the frame carries the FPU/SIMD
/// save area — which is why Linux exports it rather than leaving userspace
/// with the frozen `MINSIGSTKSZ`; glibc 2.34+ answers
/// `sysconf(_SC_MINSIGSTKSZ)` from it.
pub(crate) const AT_MINSIGSTKSZ: u64 = 51;
