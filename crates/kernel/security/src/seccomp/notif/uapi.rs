// User-notification ABI: ioctl numbers, response/addfd flags, and the wire
// codecs for the three structures the supervisor exchanges over the listener
// fd. Numbers only — every decision lives in `state.rs`.
//
// UNGATED (`CLAUDE.md` phantom-test rule): the encodings are what a libseccomp
// build depends on, so the hosted suite must be able to assert them.

use crate::seccomp::insn::SeccompData;
use crate::seccomp::uapi::SECCOMP_DATA_BYTES;

// ---- ioctl encoding -------------------------------------------------------

const IOC_NRBITS:   u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT:   u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT:  u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u32 = 1;
const IOC_READ:  u32 = 2;
/// `_IOC_SIZEMASK << _IOC_SIZESHIFT` — the size field of an encoded command.
const IOC_SIZEMASK_SHIFTED: u32 = ((1 << IOC_SIZEBITS) - 1) << IOC_SIZESHIFT;
/// `IOC_INOUT` — both direction bits.
const IOC_INOUT: u32 = (IOC_WRITE | IOC_READ) << IOC_DIRSHIFT;

/// `'!'`, the seccomp ioctl type letter.
const SECCOMP_IOC_MAGIC: u32 = 0x21;

const fn ioc(dir: u32, nr: u32, size: u32) -> u32 {
    (dir << IOC_DIRSHIFT) | (SECCOMP_IOC_MAGIC << IOC_TYPESHIFT)
        | (nr << IOC_NRSHIFT) | (size << IOC_SIZESHIFT)
}

// ---- structure sizes ------------------------------------------------------

/// `sizeof(struct seccomp_notif)` — u64 id, u32 pid, u32 flags, `seccomp_data`.
pub const NOTIF_BYTES: u32 = 16 + SECCOMP_DATA_BYTES;
/// `sizeof(struct seccomp_notif_resp)` — u64 id, s64 val, s32 error, u32 flags.
pub const NOTIF_RESP_BYTES: u32 = 24;
/// `sizeof(struct seccomp_notif_addfd)` — u64 id, then four u32 members. Also
/// the smallest accepted size: the structure has had one layout so far, and an
/// extensible-argument ioctl accepts anything from the first version's size up.
pub const ADDFD_SIZE_VER0: u32 = 24;
/// Upper bound on an extensible-argument ioctl payload.
pub const ADDFD_SIZE_MAX: u32 = 4096;

// ---- ioctl commands -------------------------------------------------------

pub const IOCTL_NOTIF_RECV:      u32 = ioc(IOC_WRITE | IOC_READ, 0, NOTIF_BYTES);
pub const IOCTL_NOTIF_SEND:      u32 = ioc(IOC_WRITE | IOC_READ, 1, NOTIF_RESP_BYTES);
pub const IOCTL_NOTIF_ID_VALID:  u32 = ioc(IOC_WRITE, 2, 8);
/// The originally shipped `ID_VALID` number encoded the direction backwards.
/// Both are accepted forever: programs built against the first header still
/// send the old one.
pub const IOCTL_NOTIF_ID_VALID_WRONG_DIR: u32 = ioc(IOC_READ, 2, 8);
pub const IOCTL_NOTIF_ADDFD:     u32 = ioc(IOC_WRITE, 3, ADDFD_SIZE_VER0);
pub const IOCTL_NOTIF_SET_FLAGS: u32 = ioc(IOC_WRITE, 4, 8);

/// Strip direction and size from an extensible-argument command, leaving the
/// type/number pair that identifies it whatever payload size the caller built
/// against.
/// # C: O(1)
pub const fn ea_ioctl(cmd: u32) -> u32 { cmd & !(IOC_INOUT | IOC_SIZEMASK_SHIFTED) }

/// Payload size an extensible-argument command declares.
/// # C: O(1)
pub const fn ioc_size(cmd: u32) -> u32 { (cmd & IOC_SIZEMASK_SHIFTED) >> IOC_SIZESHIFT }

// ---- flags ----------------------------------------------------------------

/// Response flag: run the syscall instead of returning the supervisor's value.
pub const USER_NOTIF_FLAG_CONTINUE: u32 = 1 << 0;
/// Listener flag: hand the woken side the CPU directly on wake-up.
pub const USER_NOTIF_FD_SYNC_WAKE_UP: u64 = 1 << 0;

/// addfd: the supervisor picked the descriptor number in the target.
pub const ADDFD_FLAG_SETFD: u32 = 1 << 0;
/// addfd: install the descriptor AND reply with it in one step.
pub const ADDFD_FLAG_SEND:  u32 = 1 << 1;
pub const ADDFD_FLAG_MASK:  u32 = ADDFD_FLAG_SETFD | ADDFD_FLAG_SEND;

/// `O_CLOEXEC` — the only flag an injected descriptor may carry.
pub const O_CLOEXEC: u32 = 0o2000000;

// ---- wire codecs ----------------------------------------------------------

/// `struct seccomp_notif`, encoded for the supervisor's `NOTIF_RECV`.
/// # C: O(1)
pub fn encode_notif(id: u64, pid: u32, flags: u32, d: &SeccompData) -> [u8; NOTIF_BYTES as usize] {
    let mut b = [0u8; NOTIF_BYTES as usize];
    b[0..8].copy_from_slice(&id.to_le_bytes());
    b[8..12].copy_from_slice(&pid.to_le_bytes());
    b[12..16].copy_from_slice(&flags.to_le_bytes());
    b[16..].copy_from_slice(&d.bytes());
    b
}

/// `struct seccomp_notif_resp` as the supervisor sends it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct NotifResp {
    pub id:    u64,
    pub val:   i64,
    pub error: i32,
    pub flags: u32,
}

impl NotifResp {
    /// # C: O(1)
    pub fn decode(b: &[u8; NOTIF_RESP_BYTES as usize]) -> Self {
        Self {
            id:    u64::from_le_bytes(b[0..8].try_into().unwrap_or([0; 8])),
            val:   i64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8])),
            error: i32::from_le_bytes(b[16..20].try_into().unwrap_or([0; 4])),
            flags: u32::from_le_bytes(b[20..24].try_into().unwrap_or([0; 4])),
        }
    }
}

/// `struct seccomp_notif_addfd` as the supervisor sends it. Members past the
/// caller's declared size read as zero.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct AddfdReq {
    pub id:          u64,
    pub flags:       u32,
    pub srcfd:       u32,
    pub newfd:       u32,
    pub newfd_flags: u32,
}

impl AddfdReq {
    /// # C: O(1)
    pub fn decode(b: &[u8; ADDFD_SIZE_VER0 as usize]) -> Self {
        Self {
            id:          u64::from_le_bytes(b[0..8].try_into().unwrap_or([0; 8])),
            flags:       u32::from_le_bytes(b[8..12].try_into().unwrap_or([0; 4])),
            srcfd:       u32::from_le_bytes(b[12..16].try_into().unwrap_or([0; 4])),
            newfd:       u32::from_le_bytes(b[16..20].try_into().unwrap_or([0; 4])),
            newfd_flags: u32::from_le_bytes(b[20..24].try_into().unwrap_or([0; 4])),
        }
    }
}

#[cfg(test)]
#[path = "tests/uapi.rs"]
mod tests;
