//! `struct signalfd_siginfo` ABI: size, field offsets, and the `SFD_*` flag
//! set. Identical on x86_64 and aarch64 — every member is fixed-width, which
//! is why `read(2)` on a signalfd needs no compat translation.

/// `sizeof(struct signalfd_siginfo)`. Frozen at 128 bytes by the trailing pad.
pub const SIGINFO_SIZE: usize = 128;

pub const SSI_SIGNO:     usize = 0;   // u32
pub const SSI_ERRNO:     usize = 4;   // s32
pub const SSI_CODE:      usize = 8;   // s32
pub const SSI_PID:       usize = 12;  // u32
pub const SSI_UID:       usize = 16;  // u32
pub const SSI_FD:        usize = 20;  // s32
pub const SSI_TID:       usize = 24;  // u32
pub const SSI_BAND:      usize = 28;  // u32
pub const SSI_OVERRUN:   usize = 32;  // u32
pub const SSI_TRAPNO:    usize = 36;  // u32
pub const SSI_STATUS:    usize = 40;  // s32
pub const SSI_INT:       usize = 44;  // s32
pub const SSI_PTR:       usize = 48;  // u64
pub const SSI_UTIME:     usize = 56;  // u64
pub const SSI_STIME:     usize = 64;  // u64
pub const SSI_ADDR:      usize = 72;  // u64
pub const SSI_ADDR_LSB:  usize = 80;  // u16
pub const SSI_SYSCALL:   usize = 84;  // s32
pub const SSI_CALL_ADDR: usize = 88;  // u64
pub const SSI_ARCH:      usize = 96;  // u32
/// First byte of the trailing pad; everything from here to `SIGINFO_SIZE`
/// reads back as zero.
pub const SSI_PAD:       usize = 100;

/// `SFD_CLOEXEC` — aliases `O_CLOEXEC`.
pub const SFD_CLOEXEC:  u64 = 0o2_000_000;
/// `SFD_NONBLOCK` — aliases `O_NONBLOCK`.
pub const SFD_NONBLOCK: u64 = 0o0_004_000;

/// `sizeof(sigset_t)` as the syscall's `sizemask` argument must state it.
pub const SIGSET_BYTES: u64 = 8;
