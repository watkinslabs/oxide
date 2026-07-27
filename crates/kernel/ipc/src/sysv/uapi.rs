//! `ipc64_perm` / `semid64_ds` / `msqid64_ds` / `seminfo` / `msginfo` wire
//! layouts. Encoded field-by-field at fixed offsets rather than through a
//! `#[repr(C)]` struct so the two 64-bit ABIs this kernel targets can differ
//! without an arch-specific type: `semid64_ds` is NOT the same on x86_64 and
//! aarch64 (see [`SEMID64_DS_BYTES`]).

use super::perm::IpcPerm;
use core::sync::atomic::Ordering;

/// `struct ipc64_perm` (`asm-generic/ipcbuf.h`), identical on both targets.
pub const IPC64_PERM_BYTES: usize = 48;
pub const IPC64_PERM_KEY_OFF:  usize = 0;
pub const IPC64_PERM_UID_OFF:  usize = 4;
pub const IPC64_PERM_GID_OFF:  usize = 8;
pub const IPC64_PERM_CUID_OFF: usize = 12;
pub const IPC64_PERM_CGID_OFF: usize = 16;
pub const IPC64_PERM_MODE_OFF: usize = 20;
pub const IPC64_PERM_SEQ_OFF:  usize = 24;

/// `struct semid64_ds`. x86_64 uses `arch/x86/include/uapi/asm/sembuf.h`,
/// which interleaves an unused 64-bit word after each of `sem_otime` and
/// `sem_ctime`; aarch64 takes `asm-generic/sembuf.h`, which does not. Getting
/// this wrong hands userspace a `sem_nsems` read out of padding.
#[cfg(target_arch = "x86_64")]
pub const SEMID64_OTIME_OFF: usize = 48;
#[cfg(target_arch = "x86_64")]
pub const SEMID64_CTIME_OFF: usize = 64;
#[cfg(target_arch = "x86_64")]
pub const SEMID64_NSEMS_OFF: usize = 80;
#[cfg(target_arch = "x86_64")]
pub const SEMID64_DS_BYTES: usize = 104;

#[cfg(not(target_arch = "x86_64"))]
pub const SEMID64_OTIME_OFF: usize = 48;
#[cfg(not(target_arch = "x86_64"))]
pub const SEMID64_CTIME_OFF: usize = 56;
#[cfg(not(target_arch = "x86_64"))]
pub const SEMID64_NSEMS_OFF: usize = 64;
#[cfg(not(target_arch = "x86_64"))]
pub const SEMID64_DS_BYTES: usize = 88;

/// `struct msqid64_ds` — identical on x86_64 and 64-bit asm-generic.
pub const MSQID64_STIME_OFF:  usize = 48;
pub const MSQID64_RTIME_OFF:  usize = 56;
pub const MSQID64_CTIME_OFF:  usize = 64;
pub const MSQID64_CBYTES_OFF: usize = 72;
pub const MSQID64_QNUM_OFF:   usize = 80;
pub const MSQID64_QBYTES_OFF: usize = 88;
pub const MSQID64_LSPID_OFF:  usize = 96;
pub const MSQID64_LRPID_OFF:  usize = 100;
pub const MSQID64_DS_BYTES:   usize = 120;

/// `struct seminfo` — ten `int`s.
pub const SEMINFO_BYTES: usize = 40;
pub const SEMINFO_SEMMAP_OFF: usize = 0;
pub const SEMINFO_SEMMNI_OFF: usize = 4;
pub const SEMINFO_SEMMNS_OFF: usize = 8;
pub const SEMINFO_SEMMNU_OFF: usize = 12;
pub const SEMINFO_SEMMSL_OFF: usize = 16;
pub const SEMINFO_SEMOPM_OFF: usize = 20;
pub const SEMINFO_SEMUME_OFF: usize = 24;
pub const SEMINFO_SEMUSZ_OFF: usize = 28;
pub const SEMINFO_SEMVMX_OFF: usize = 32;
pub const SEMINFO_SEMAEM_OFF: usize = 36;

/// `struct msginfo` — seven `int`s then an `unsigned short`, tail-padded to
/// the `int` alignment.
pub const MSGINFO_BYTES: usize = 32;
pub const MSGINFO_MSGPOOL_OFF: usize = 0;
pub const MSGINFO_MSGMAP_OFF:  usize = 4;
pub const MSGINFO_MSGMAX_OFF:  usize = 8;
pub const MSGINFO_MSGMNB_OFF:  usize = 12;
pub const MSGINFO_MSGMNI_OFF:  usize = 16;
pub const MSGINFO_MSGSSZ_OFF:  usize = 20;
pub const MSGINFO_MSGTQL_OFF:  usize = 24;
pub const MSGINFO_MSGSEG_OFF:  usize = 28;

/// # C: O(1)
pub fn put_u16(out: &mut [u8], off: usize, v: u16) { out[off..off + 2].copy_from_slice(&v.to_le_bytes()); }
/// # C: O(1)
pub fn put_i32(out: &mut [u8], off: usize, v: i32) { out[off..off + 4].copy_from_slice(&v.to_le_bytes()); }
/// # C: O(1)
pub fn put_u32(out: &mut [u8], off: usize, v: u32) { out[off..off + 4].copy_from_slice(&v.to_le_bytes()); }
/// # C: O(1)
pub fn put_i64(out: &mut [u8], off: usize, v: i64) { out[off..off + 8].copy_from_slice(&v.to_le_bytes()); }
/// # C: O(1)
pub fn put_u64(out: &mut [u8], off: usize, v: u64) { out[off..off + 8].copy_from_slice(&v.to_le_bytes()); }
/// # C: O(1)
pub fn get_u32(b: &[u8], off: usize) -> u32 { u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]) }
/// # C: O(1)
pub fn get_u64(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

/// Linux `kernel_to_ipc64_perm`. # C: O(1)
pub fn encode_ipc64_perm(out: &mut [u8], perm: &IpcPerm) {
    put_i32(out, IPC64_PERM_KEY_OFF, perm.key);
    put_u32(out, IPC64_PERM_UID_OFF, perm.uid.load(Ordering::Acquire));
    put_u32(out, IPC64_PERM_GID_OFF, perm.gid.load(Ordering::Acquire));
    put_u32(out, IPC64_PERM_CUID_OFF, perm.cuid);
    put_u32(out, IPC64_PERM_CGID_OFF, perm.cgid);
    put_u32(out, IPC64_PERM_MODE_OFF, perm.mode.load(Ordering::Acquire) & 0xffff);
    put_u16(out, IPC64_PERM_SEQ_OFF, perm.seq);
}

/// uid/gid/mode read back out of a userspace `ipc64_perm` for `IPC_SET`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ipc64PermIn { pub uid: u32, pub gid: u32, pub mode: u32 }

/// # C: O(1)
pub fn decode_ipc64_perm(b: &[u8]) -> Ipc64PermIn {
    Ipc64PermIn {
        uid: get_u32(b, IPC64_PERM_UID_OFF),
        gid: get_u32(b, IPC64_PERM_GID_OFF),
        mode: get_u32(b, IPC64_PERM_MODE_OFF),
    }
}
