// pidfs ioctl vocabulary and admission — the pure half of a pidfd's `ioctl(2)`
// surface. `pidfd.rs` performs the live work and is kernel-only, so nothing
// decidable may live there: a `#[cfg(test)]` block inside it compiles away in
// silence.
//
// Two shapes share the command space. The namespace descriptors are FIXED
// `_IO(0xFF, n)` commands, matched whole. `PIDFD_GET_INFO` is EXTENSIBLE: its
// size field carries the caller's `struct pidfd_info` length, so the command
// word varies with the struct version and only its direction, magic and number
// may be matched — with the size floored at the first published version, which
// is what keeps a non-pidfd fd's stray ioctl from being mistaken for one.

use nscg::proc_ns::NsKind;

/// `PIDFS_IOCTL_MAGIC`.
pub const PIDFS_IOCTL_MAGIC: u64 = 0xFF;

/// `_IOC_NR` of `PIDFD_GET_INFO`.
pub const PIDFD_GET_INFO_NR: u64 = 11;

/// Published `struct pidfd_info` sizes. A caller's length is floored at VER0
/// (admission) and the reply is truncated to whichever version it spans.
pub const PIDFD_INFO_SIZE_VER0: usize = 64;
pub const PIDFD_INFO_SIZE_VER1: usize = 72;
pub const PIDFD_INFO_SIZE_VER2: usize = 80;
pub const PIDFD_INFO_SIZE_VER3: usize = 88;

/// `struct pidfd_info` request/result mask bits.
pub const PIDFD_INFO_PID:             u64 = 1 << 0;
pub const PIDFD_INFO_CREDS:           u64 = 1 << 1;
pub const PIDFD_INFO_CGROUPID:        u64 = 1 << 2;
pub const PIDFD_INFO_EXIT:            u64 = 1 << 3;
pub const PIDFD_INFO_COREDUMP:        u64 = 1 << 4;
pub const PIDFD_INFO_SUPPORTED_MASK:  u64 = 1 << 5;
pub const PIDFD_INFO_COREDUMP_SIGNAL: u64 = 1 << 6;
pub const PIDFD_INFO_COREDUMP_CODE:   u64 = 1 << 7;

/// `@coredump_mask` values.
pub const PIDFD_COREDUMPED:      u32 = 1 << 0;
pub const PIDFD_COREDUMP_SKIP:   u32 = 1 << 1;
pub const PIDFD_COREDUMP_USER:   u32 = 1 << 2;
pub const PIDFD_COREDUMP_ROOT:   u32 = 1 << 3;

/// `struct pidfd_info` field offsets.
pub const INFO_OFF_MASK:            usize = 0;
pub const INFO_OFF_CGROUPID:        usize = 8;
pub const INFO_OFF_PID:             usize = 16;
pub const INFO_OFF_EXIT_CODE:       usize = 60;
pub const INFO_OFF_COREDUMP_MASK:   usize = 64;
pub const INFO_OFF_COREDUMP_SIGNAL: usize = 68;
pub const INFO_OFF_COREDUMP_CODE:   usize = 72;
pub const INFO_OFF_SUPPORTED_MASK:  usize = 80;

/// Ioctl command-word field extraction (`_IOC_*`), Linux asm-generic layout.
const IOC_NRSHIFT:   u64 = 0;
const IOC_TYPESHIFT: u64 = 8;
const IOC_SIZESHIFT: u64 = 16;
const IOC_DIRSHIFT:  u64 = 30;
const IOC_NRMASK:    u64 = 0xFF;
const IOC_TYPEMASK:  u64 = 0xFF;
const IOC_SIZEMASK:  u64 = 0x3FFF;
const IOC_DIRMASK:   u64 = 0x3;
/// `_IOC_READ | _IOC_WRITE`, the direction `_IOWR` encodes.
const IOC_RDWR:      u64 = 0x3;

/// # C: O(1)
pub const fn ioc_nr(req: u64) -> u64 { (req >> IOC_NRSHIFT) & IOC_NRMASK }
/// # C: O(1)
pub const fn ioc_type(req: u64) -> u64 { (req >> IOC_TYPESHIFT) & IOC_TYPEMASK }
/// # C: O(1)
pub const fn ioc_size(req: u64) -> usize { ((req >> IOC_SIZESHIFT) & IOC_SIZEMASK) as usize }
/// # C: O(1)
pub const fn ioc_dir(req: u64) -> u64 { (req >> IOC_DIRSHIFT) & IOC_DIRMASK }

/// `_IO(PIDFS_IOCTL_MAGIC, nr)`. # C: O(1)
pub const fn pidfs_io(nr: u64) -> u64 { (PIDFS_IOCTL_MAGIC << IOC_TYPESHIFT) | nr }

/// What a pidfd's `ioctl(2)` command names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PidfsIoctl {
    /// Hand back a descriptor for one of the target's namespaces.
    Namespace(NsKind),
    /// `PIDFD_GET_INFO`, carrying the caller's `struct pidfd_info` length.
    Info { size: usize },
}

/// Linux `pidfs_ioctl_valid` plus the command decode. `None` is
/// `ENOIOCTLCMD` — every command this file does not name, including a
/// `PIDFD_GET_INFO` whose extensible size cannot span the first published
/// struct.
/// # C: O(1)
pub fn decide(req: u64) -> Option<PidfsIoctl> {
    if let Some(kind) = namespace_kind(req) { return Some(PidfsIoctl::Namespace(kind)); }
    // Extensible: match on direction/magic/number only, never the whole word.
    if ioc_dir(req) == IOC_RDWR
        && ioc_type(req) == PIDFS_IOCTL_MAGIC
        && ioc_nr(req) == PIDFD_GET_INFO_NR
        && ioc_size(req) >= PIDFD_INFO_SIZE_VER0
    {
        return Some(PidfsIoctl::Info { size: ioc_size(req) });
    }
    None
}

/// The namespace a fixed `_IO(0xFF, n)` command names. # C: O(1)
pub fn namespace_kind(req: u64) -> Option<NsKind> {
    if ioc_dir(req) != 0 || ioc_size(req) != 0 || ioc_type(req) != PIDFS_IOCTL_MAGIC {
        return None;
    }
    Some(match ioc_nr(req) {
        1  => NsKind::Cgroup,
        2  => NsKind::Ipc,
        3  => NsKind::Mnt,
        4  => NsKind::Net,
        5  => NsKind::Pid,
        6  => NsKind::PidForChildren,
        7  => NsKind::Time,
        8  => NsKind::TimeForChildren,
        9  => NsKind::User,
        10 => NsKind::Uts,
        _  => return None,
    })
}

/// Result-mask bits this kernel can ever set, reported through
/// `PIDFD_INFO_SUPPORTED_MASK`. Coredump reporting needs a recorded coredump
/// verdict per exit, which the exit path now latches, so those bits are live.
pub const SUPPORTED_MASK: u64 = PIDFD_INFO_PID
    | PIDFD_INFO_CREDS
    | PIDFD_INFO_CGROUPID
    | PIDFD_INFO_EXIT
    | PIDFD_INFO_COREDUMP
    | PIDFD_INFO_SUPPORTED_MASK
    | PIDFD_INFO_COREDUMP_SIGNAL
    | PIDFD_INFO_COREDUMP_CODE;

/// Which result bits a reply of `length` bytes can carry. The uapi is explicit
/// that a field the caller's struct is too short to hold must NOT have its bit
/// set, or userspace reads a bit whose field it never received and acts on
/// uninitialised memory. Each rung is the end offset of the field it guards.
/// # C: O(1)
pub const fn mask_fitting(length: usize) -> u64 {
    // VER0 fields: everything up to and including `exit_code`.
    let mut ok = PIDFD_INFO_PID | PIDFD_INFO_CREDS | PIDFD_INFO_CGROUPID | PIDFD_INFO_EXIT;
    if length >= INFO_OFF_COREDUMP_MASK + 4   { ok |= PIDFD_INFO_COREDUMP; }
    if length >= INFO_OFF_COREDUMP_SIGNAL + 4 { ok |= PIDFD_INFO_COREDUMP_SIGNAL; }
    if length >= INFO_OFF_COREDUMP_CODE + 4   { ok |= PIDFD_INFO_COREDUMP_CODE; }
    if length >= INFO_OFF_SUPPORTED_MASK + 8  { ok |= PIDFD_INFO_SUPPORTED_MASK; }
    ok
}

#[cfg(test)]
#[path = "pidfs_ioctl/tests.rs"]
mod tests;
