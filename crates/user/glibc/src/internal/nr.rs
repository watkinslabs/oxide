// Per-arch Linux syscall numbers (docs/59§4). Sourced from the canonical
// Linux uapi tables — x86_64 from arch/x86/.../syscall_64.tbl, aarch64
// from include/uapi/asm-generic/unistd.h — the same split glibc keeps in
// sysdeps/<arch>. Named constants only; call sites use `nr::FOO`, never a
// bare slot literal (07§5). Numbers grow per area as wrappers land.
//
// aarch64 is asm-generic: it has NO open/stat/lstat/access/pipe/dup2/
// poll/select/fork/rename/*at-less variants — libc composes those from
// openat/newfstatat/faccessat/etc. (see posix/io.rs arch dispatch).
#![allow(dead_code)]

#[cfg(target_arch = "aarch64")]
pub use self::aarch64::*;
#[cfg(not(target_arch = "aarch64"))]
pub use self::x86_64::*;

// x86_64 also covers the dev-box host build (target_arch = x86_64), so
// hosted/test rlib builds resolve here too.
pub mod x86_64 {
    pub const READ: usize = 0;
    pub const WRITE: usize = 1;
    pub const OPEN: usize = 2;
    pub const CLOSE: usize = 3;
    pub const STAT: usize = 4;
    pub const FSTAT: usize = 5;
    pub const LSTAT: usize = 6;
    pub const LSEEK: usize = 8;
    pub const MMAP: usize = 9;
    pub const MPROTECT: usize = 10;
    pub const MUNMAP: usize = 11;
    pub const BRK: usize = 12;
    pub const RT_SIGACTION: usize = 13;
    pub const RT_SIGPROCMASK: usize = 14;
    pub const RT_SIGRETURN: usize = 15;
    pub const IOCTL: usize = 16;
    pub const PREAD64: usize = 17;
    pub const PWRITE64: usize = 18;
    pub const ACCESS: usize = 21;
    pub const PIPE: usize = 22;
    pub const SCHED_YIELD: usize = 24;
    pub const MREMAP: usize = 25;
    pub const MADVISE: usize = 28;
    pub const DUP: usize = 32;
    pub const DUP2: usize = 33;
    pub const NANOSLEEP: usize = 35;
    pub const GETPID: usize = 39;
    pub const CLONE: usize = 56;
    pub const FORK: usize = 57;
    pub const EXECVE: usize = 59;
    pub const EXIT: usize = 60;
    pub const WAIT4: usize = 61;
    pub const KILL: usize = 62;
    pub const UNAME: usize = 63;
    pub const FCNTL: usize = 72;
    pub const GETCWD: usize = 79;
    pub const READLINK: usize = 89;
    pub const GETTID: usize = 186;
    pub const FUTEX: usize = 202;
    pub const GETDENTS64: usize = 217;
    pub const SET_TID_ADDRESS: usize = 218;
    pub const CLOCK_GETTIME: usize = 228;
    pub const EXIT_GROUP: usize = 231;
    pub const TGKILL: usize = 234;
    pub const OPENAT: usize = 257;
    pub const NEWFSTATAT: usize = 262;
    pub const UNLINKAT: usize = 263;
    pub const FACCESSAT: usize = 269;
    pub const SET_ROBUST_LIST: usize = 273;
    pub const DUP3: usize = 292;
    pub const PIPE2: usize = 293;
    pub const PRLIMIT64: usize = 302;
    pub const GETRANDOM: usize = 318;
}

pub mod aarch64 {
    pub const GETCWD: usize = 17;
    pub const DUP: usize = 23;
    pub const DUP3: usize = 24;
    pub const FCNTL: usize = 25;
    pub const IOCTL: usize = 29;
    pub const FACCESSAT: usize = 48;
    pub const OPENAT: usize = 56;
    pub const CLOSE: usize = 57;
    pub const PIPE2: usize = 59;
    pub const GETDENTS64: usize = 61;
    pub const LSEEK: usize = 62;
    pub const READ: usize = 63;
    pub const WRITE: usize = 64;
    pub const PREAD64: usize = 67;
    pub const PWRITE64: usize = 68;
    pub const READLINKAT: usize = 78;
    pub const NEWFSTATAT: usize = 79;
    pub const FSTAT: usize = 80;
    pub const EXIT: usize = 93;
    pub const EXIT_GROUP: usize = 94;
    pub const SET_TID_ADDRESS: usize = 96;
    pub const SET_ROBUST_LIST: usize = 99;
    pub const NANOSLEEP: usize = 101;
    pub const CLOCK_GETTIME: usize = 113;
    pub const SCHED_YIELD: usize = 124;
    pub const KILL: usize = 129;
    pub const TGKILL: usize = 131;
    pub const RT_SIGACTION: usize = 134;
    pub const RT_SIGPROCMASK: usize = 135;
    pub const RT_SIGRETURN: usize = 139;
    pub const UNAME: usize = 160;
    pub const GETPID: usize = 172;
    pub const GETTID: usize = 178;
    pub const FUTEX: usize = 98;
    pub const BRK: usize = 214;
    pub const MUNMAP: usize = 215;
    pub const MREMAP: usize = 216;
    pub const CLONE: usize = 220;
    pub const EXECVE: usize = 221;
    pub const MMAP: usize = 222;
    pub const MPROTECT: usize = 226;
    pub const MADVISE: usize = 233;
    pub const WAIT4: usize = 260;
    pub const PRLIMIT64: usize = 261;
    pub const GETRANDOM: usize = 278;
}
