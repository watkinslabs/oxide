// pidfd surface per Linux 5.3+. Each pidfd_open allocates a PidfdInode with
// a stable reference to the target process identity. The inode number still
// encodes the target internal tid for fdinfo/stat/debug consumers.


use alloc::sync::Arc;

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// Inode-number marker — high 32 bits spell "PIDF". The low 32 bits store the
/// full internal tid; truncating to 24 bits broke long-running PID spaces.
const PIDFD_INO_MARKER: Ino = 0x5049_4446_0000_0000;
const PIDFD_MARKER_MASK: Ino = 0xFFFF_FFFF_0000_0000;
const PIDFD_TID_MASK: Ino = 0x0000_0000_FFFF_FFFF;

/// Pidfd inode. Linux pidfds pin `struct pid`; in this kernel the closest
/// stable process identity is the Task object itself. Keeping this reference
/// means pidfd ioctls/fdinfo remain meaningful after task exit and before all
/// pidfd references are closed instead of spuriously degrading to ESRCH when
/// the weak scheduler registry entry is reaped.
pub struct PidfdInode {
    pub tid: u32,
    target: Arc<sched::Task>,
}

impl Inode for PidfdInode {
    fn as_any(&self) -> Option<&dyn core::any::Any> { Some(self) }
    fn ino(&self) -> Ino { PIDFD_INO_MARKER | self.tid as Ino }
    fn statfs_magic(&self) -> u64 { 0x5049_4446 } // PIDFS_MAGIC
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
    /// Linux `pidfd_show_fdinfo`: append `Pid:`/`NSpid:` so `/proc/<pid>/
    /// fdinfo/<n>` carries the target pid. `Pid:` = the target's vpid in the
    /// reader's pidns (init-ns global pid here); a reaped target shows -1 (and
    /// NSpid omitted, matching Linux). glibc/systemd `pidfd_get_pid()` parses
    /// this; a missing `Pid:` line makes it return ENOTTY. # C: O(1)
    fn fdinfo_extra(&self, out: &mut alloc::vec::Vec<u8>) {
        use core::fmt::Write;
        let vpid = self.target.vtgid.load(core::sync::atomic::Ordering::Acquire);
        if vpid != 0 {
            let _ = write!(FdinfoFmt(out), "Pid:\t{}\nNSpid:\t{}\n", vpid, vpid);
        } else {
            // Linux emits `Pid:\t-1` for a pidfd whose target has been reaped.
            let _ = write!(FdinfoFmt(out), "Pid:\t-1\n");
        }
    }
}

/// `core::fmt::Write` adapter appending UTF-8 into a byte vec (pidfd fdinfo).
struct FdinfoFmt<'a>(&'a mut alloc::vec::Vec<u8>);
impl<'a> core::fmt::Write for FdinfoFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.extend_from_slice(s.as_bytes()); Ok(())
    }
}

/// Resolve a pidfd number in the current task's fd table to the target
/// internal tid stored in its inode.
/// # C: O(1)
pub fn tid_from_fd(fd: i32) -> Result<u32, syscall::errno::Errno> {
    use syscall::errno::Errno;
    let cur = sched::live::current().ok_or(Errno::Ebadf)?;
    // SAFETY: current task is running on this CPU; fd_table pointer is stable
    // for the duration of the syscall.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let file = fdt.get(fd).map_err(|_| Errno::Ebadf)?;
    tid_from_ino(file.inode().ino()).ok_or(Errno::Einval)
}

/// Recover the pinned target task from a pidfd inode.
/// # C: O(1)
pub fn task_from_inode(inode: &InodeRef) -> Option<Arc<sched::Task>> {
    inode.as_any()?.downcast_ref::<PidfdInode>().map(|p| Arc::clone(&p.target))
}

/// `ioctl(pidfd, PIDFD_GET_INFO)` (Linux 6.13+). Returns a populated
/// `struct pidfd_info` for the target. systemd forks a service (e.g.
/// console-getty) then verifies it is its own child via this ioctl to
/// read `ppid`; an ENOTTY makes systemd conclude the child is foreign
/// and SIGKILL it — the getty never stays up and never re-prompts after
/// logout. `id` is the internal tid stored in the pidfd inode.
///
/// Request encodes `_IOWR(0xFF, 11, struct pidfd_info)`; the struct size
/// (bits 16..=29) varies across kernel/systemd versions, so match on
/// dir|type|nr only and honor the caller's size for the write-back.
/// # C: O(N_tasks)
pub fn handle_pidfd_ioctl(task: Arc<sched::Task>, req: u64, arg: u64) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    // dir(IOWR=3)|type(0xFF)|nr(11) with the size field masked out.
    const PIDFD_GET_INFO_DTN: u64 = 0xC000_FF0B;
    const PIDFD_INFO_PID: u64 = 1 << 0;
    const PIDFD_INFO_CREDS: u64 = 1 << 1;
    const PIDFD_INFO_EXIT: u64 = 1 << 3;
    const PIDFD_INFO_SUPPORTED_MASK: u64 = 1 << 5;
    const SUPPORTED: u64 = PIDFD_INFO_PID | PIDFD_INFO_CREDS | PIDFD_INFO_EXIT | PIDFD_INFO_SUPPORTED_MASK;
    if (req & 0xC000_FFFF) != PIDFD_GET_INFO_DTN {
        return -(Errno::Enotty.as_i32() as i64);
    }
    let want = ((req >> 16) & 0x3FFF) as usize; // caller's sizeof(struct)
    if arg == 0 || arg >= hal::USER_VA_END || want < 64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: arg validated in user range; 8-byte read of the requested mask.
    let req_mask = unsafe { core::ptr::read_volatile(arg as *const u64) };
    let pid  = sched::live::registry::display_vpid(task.tid) as u32;
    let ppid = sched::live::registry::parent_vpid(task.tid) as u32;
    // struct pidfd_info v2:
    // mask@0 cgroupid@8 pid@16 tgid@20 ppid@24 ruid@28 rgid@32 euid@36
    // egid@40 suid@44 sgid@48 fsuid@52 fsgid@56 exit_code@60
    // coredump_mask@64 coredump_signal@68 supported_mask@72.
    let mut out = [0u8; 80];
    // Current Linux always returns PID and CREDS when the caller's struct is
    // large enough for those fields, regardless of the requested mask.
    let mut omask = PIDFD_INFO_PID | PIDFD_INFO_CREDS;
    out[16..20].copy_from_slice(&pid.to_le_bytes());
    out[20..24].copy_from_slice(&pid.to_le_bytes());
    out[24..28].copy_from_slice(&ppid.to_le_bytes());
    let c = &task.creds;
    out[28..32].copy_from_slice(&c.ruid.load(Ordering::Acquire).to_le_bytes());
    out[32..36].copy_from_slice(&c.rgid.load(Ordering::Acquire).to_le_bytes());
    out[36..40].copy_from_slice(&c.euid.load(Ordering::Acquire).to_le_bytes());
    out[40..44].copy_from_slice(&c.egid.load(Ordering::Acquire).to_le_bytes());
    out[44..48].copy_from_slice(&c.suid.load(Ordering::Acquire).to_le_bytes());
    out[48..52].copy_from_slice(&c.sgid.load(Ordering::Acquire).to_le_bytes());
    out[52..56].copy_from_slice(&c.fsuid.load(Ordering::Acquire).to_le_bytes());
    out[56..60].copy_from_slice(&c.fsgid.load(Ordering::Acquire).to_le_bytes());
    if req_mask & PIDFD_INFO_EXIT != 0 && want >= 64 {
        omask |= PIDFD_INFO_EXIT;
        out[60..64].copy_from_slice(&task.exit_status.load(Ordering::Acquire).to_le_bytes());
    }
    if req_mask & PIDFD_INFO_SUPPORTED_MASK != 0 && want >= 80 {
        omask |= PIDFD_INFO_SUPPORTED_MASK;
        out[72..80].copy_from_slice(&SUPPORTED.to_le_bytes());
    }
    out[0..8].copy_from_slice(&omask.to_le_bytes());
    let n = core::cmp::min(want, out.len());
    // SAFETY: arg..arg+n inside the caller's `want`-byte buffer; CPL=0 byte
    // writes through the caller's address space.
    unsafe { for (i, b) in out.iter().copied().take(n).enumerate() {
        core::ptr::write_volatile((arg + i as u64) as *mut u8, b);
    } }
    0
}

/// Decode the tid from a pidfd inode-number; returns `None` for
/// non-pidfd inodes.
/// # C: O(1)
pub fn tid_from_ino(ino: Ino) -> Option<u32> {
    if (ino & PIDFD_MARKER_MASK) == PIDFD_INO_MARKER {
        Some((ino & PIDFD_TID_MASK) as u32)
    } else { None }
}

/// Construct a pidfd inode. Wraps in `Arc<dyn Inode>`.
/// # C: O(1)
pub fn new_pidfd_inode(target: Arc<sched::Task>) -> InodeRef {
    Arc::new(PidfdInode { tid: target.tid, target }) as InodeRef
}
