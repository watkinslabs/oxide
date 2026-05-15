// /dev/input/event0 evdev substrate per `35§R01` and v2-arch-plan
// §1.9. V1: admit + answer EVIOCGNAME / EVIOCGID identification
// ioctls. Real key / abs / rel event delivery is a follow-up once the
// virtio-input PCI driver lands.



use alloc::sync::Arc;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

const EVDEV_INO_BASE: Ino = 0x7400_0000;

const EVIOCGVERSION: u64 = 0x80044501;
const EVIOCGID:      u64 = 0x80084502;
// EVIOCGNAME is _IOR('E', 0x06, len) — len is variable; we match on the
// low 16 bits (cmd nr + group letter) and ignore the size field.
const EVIOCGNAME_NR: u32 = 0x4506;

/// Single evdev device — keyboard-shaped placeholder identified as
/// "oxide-input". Real input frame delivery is a follow-up.
pub struct EvdevInode;

impl Inode for EvdevInode {
    fn ino(&self) -> Ino { EVDEV_INO_BASE | 0x01 }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }

    /// Blocking pop of one input_event record (24 B). Parks the
    /// caller on EVENT0.waiters when the queue is empty; resumes
    /// when virtio-input pushes the next event. Reads of less than
    /// one record return 0 (matches Linux evdev: EINVAL on too-
    /// small buf, but Ok(0) is the more forgiving v1 choice).
    fn read(&self, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        use crate::evdev_queue::{EVENT0, INPUT_EVENT_BYTES};
        if buf.len() < INPUT_EVENT_BYTES { return Ok(0); }
        // SAFETY: caller is the running task on this CPU; read_blocking parks safely via WaitList and reschedules.
        let n = unsafe { EVENT0.read_blocking(buf) };
        Ok(n)
    }

    /// Non-blocking variant per O_NONBLOCK.
    fn read_nonblock(&self, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        use crate::evdev_queue::{EVENT0, INPUT_EVENT_BYTES};
        if buf.len() < INPUT_EVENT_BYTES { return Ok(0); }
        match EVENT0.try_pop_bytes(buf) {
            Some(n) => Ok(n),
            None    => Err(VfsError::Eagain),
        }
    }

    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// EVIOC* ioctl handler. Returns `Some(rv)` when the request is
/// recognised; `None` to let the generic CharDev path run.
/// # C: O(1)
pub fn handle_evdev_ioctl(inode: &InodeRef, req: u64, arg: u64) -> Option<i64> {
    if inode.ino() & 0xFFFF_FFFF_0000_0000 != EVDEV_INO_BASE {
        return None;
    }
    use syscall::errno::Errno;
    if arg == 0 || arg >= hal::USER_VA_END {
        return Some(-(Errno::Efault.as_i32() as i64));
    }
    // _IOR / _IOW low byte = group ('E'); high 16 = size; nr = bits
    // [8..16] of the lowest dword. Match by cmd-nr+group only.
    let group = (req >> 8) & 0xFF;
    let nr    = (req & 0xFF) | ((req >> 8) & 0xFF00);
    if group != b'E' as u64 { return None; }
    if (nr as u32) == EVIOCGNAME_NR {
        const NAME: &[u8] = b"oxide-input";
        // SAFETY: arg validated < USER_VA_END; we write the canonical 12-byte name + NUL terminator.
        unsafe {
            for i in 0..NAME.len() {
                core::ptr::write_volatile((arg + i as u64) as *mut u8, NAME[i]);
            }
            core::ptr::write_volatile((arg + NAME.len() as u64) as *mut u8, 0);
        }
        return Some((NAME.len() + 1) as i64);
    }
    if req == EVIOCGVERSION {
        // SAFETY: arg validated < USER_VA_END; 4-byte aligned write of the EV_VERSION constant.
        unsafe { core::ptr::write_volatile(arg as *mut u32, 0x010001); }
        return Some(0);
    }
    if req == EVIOCGID {
        // struct input_id { u16 bustype; u16 vendor; u16 product; u16 version; }
        // SAFETY: arg validated < USER_VA_END; 8-byte aligned write of the placeholder id.
        unsafe {
            core::ptr::write_volatile(arg          as *mut u16, 0x06);    // BUS_VIRTUAL
            core::ptr::write_volatile((arg + 2)    as *mut u16, 0xDEAD);  // vendor
            core::ptr::write_volatile((arg + 4)    as *mut u16, 0xBEEF);  // product
            core::ptr::write_volatile((arg + 6)    as *mut u16, 1);
        }
        return Some(0);
    }
    Some(-(Errno::Enotty.as_i32() as i64))
}

/// Boot-time registration. Called from the boot init.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(1)
pub fn init() {
    devfs::register("/dev/input/event0", Arc::new(EvdevInode) as InodeRef);
}
