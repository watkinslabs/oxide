// pidfd surface per Linux 5.3+. v1: each pidfd_open allocates a
// PidfdInode with the target tid encoded in the low 24 bits of the
// inode number; pidfd_send_signal extracts the tid by inode marker.


use alloc::sync::Arc;

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// Inode-number marker — high byte 0x70.
const PIDFD_INO_MARKER: Ino = 0x7000_0000;
const PIDFD_TID_MASK:   Ino = 0x00FF_FFFF;

/// Pidfd inode. Stores the target tid; read/write are noops (pidfds
/// aren't I/O fds — they're handles for pidfd_send_signal etc).
pub struct PidfdInode {
    pub tid: u32,
}

impl Inode for PidfdInode {
    fn ino(&self) -> Ino { PIDFD_INO_MARKER | (self.tid as Ino & PIDFD_TID_MASK) }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// `ioctl(pidfd, PIDFD_GET_INFO)` (Linux 6.13+). Returns a populated
/// `struct pidfd_info` for the target. systemd forks a service (e.g.
/// console-getty) then verifies it is its own child via this ioctl to
/// read `ppid`; an ENOTTY makes systemd conclude the child is foreign
/// and SIGKILL it — the getty never stays up and never re-prompts after
/// logout. `id` is the value the pidfd was opened with (a vpid in the
/// opener's pid_ns); resolve via tid then vpid.
///
/// Request encodes `_IOWR(0xFF, 11, struct pidfd_info)`; the struct size
/// (bits 16..=29) varies across kernel/systemd versions, so match on
/// dir|type|nr only and honor the caller's size for the write-back.
/// # C: O(N_tasks)
pub fn handle_pidfd_ioctl(id: u32, req: u64, arg: u64) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    // dir(IOWR=3)|type(0xFF)|nr(11) with the size field masked out.
    const PIDFD_GET_INFO_DTN: u64 = 0xC000_FF0B;
    const PIDFD_INFO_PID:   u64 = 1 << 0;
    const PIDFD_INFO_CREDS: u64 = 1 << 1;
    if (req & 0xC000_FFFF) != PIDFD_GET_INFO_DTN {
        return -(Errno::Enotty.as_i32() as i64);
    }
    let want = ((req >> 16) & 0x3FFF) as usize; // caller's sizeof(struct)
    if arg == 0 || arg >= hal::USER_VA_END || want < 64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let task = match sched::live::registry::lookup(id)
        .or_else(|| sched::live::registry::lookup_by_vpid(id))
    {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: arg validated in user range; 8-byte read of the requested mask.
    let req_mask = unsafe { core::ptr::read_volatile(arg as *const u64) };
    let pid  = sched::live::registry::display_vpid(task.tid) as u32;
    let ppid = sched::live::registry::parent_vpid(task.tid) as u32;
    // struct pidfd_info: mask@0 cgroupid@8 pid@16 tgid@20 ppid@24
    // ruid@28 rgid@32 euid@36 egid@40 suid@44 sgid@48 fsuid@52 fsgid@56 exit_code@60
    let mut out = [0u8; 64];
    let mut omask = PIDFD_INFO_PID; // pid/tgid/ppid always provided
    out[16..20].copy_from_slice(&pid.to_le_bytes());
    out[20..24].copy_from_slice(&pid.to_le_bytes());
    out[24..28].copy_from_slice(&ppid.to_le_bytes());
    if req_mask & PIDFD_INFO_CREDS != 0 {
        omask |= PIDFD_INFO_CREDS;
        let c = &task.creds;
        out[28..32].copy_from_slice(&c.ruid.load(Ordering::Acquire).to_le_bytes());
        out[32..36].copy_from_slice(&c.rgid.load(Ordering::Acquire).to_le_bytes());
        out[36..40].copy_from_slice(&c.euid.load(Ordering::Acquire).to_le_bytes());
        out[40..44].copy_from_slice(&c.egid.load(Ordering::Acquire).to_le_bytes());
        out[44..48].copy_from_slice(&c.suid.load(Ordering::Acquire).to_le_bytes());
        out[48..52].copy_from_slice(&c.sgid.load(Ordering::Acquire).to_le_bytes());
        out[52..56].copy_from_slice(&c.fsuid.load(Ordering::Acquire).to_le_bytes());
        out[56..60].copy_from_slice(&c.fsgid.load(Ordering::Acquire).to_le_bytes());
    }
    out[0..8].copy_from_slice(&omask.to_le_bytes());
    // SAFETY: arg..arg+64 inside the caller's >=64-byte buffer (want>=64);
    // CPL=0 byte writes through the caller's address space.
    unsafe { for i in 0..64 { core::ptr::write_volatile((arg + i as u64) as *mut u8, out[i]); } }
    0
}

/// Decode the tid from a pidfd inode-number; returns `None` for
/// non-pidfd inodes.
/// # C: O(1)
pub fn tid_from_ino(ino: Ino) -> Option<u32> {
    if (ino & 0xFF00_0000) == PIDFD_INO_MARKER {
        Some((ino & PIDFD_TID_MASK) as u32)
    } else { None }
}

/// Construct a pidfd inode for `tid`. Wraps in `Arc<dyn Inode>`.
/// # C: O(1)
pub fn new_pidfd_inode(tid: u32) -> InodeRef {
    Arc::new(PidfdInode { tid }) as InodeRef
}
