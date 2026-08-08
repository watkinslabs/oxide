use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use super::{
    current_ipc_cred, ipc_permitted, lookup_by_id, IpcCred, ShmSegment, REG,
    PAGE_SIZE, SHM_DEST, SHM_LOCKED, SHM_MAX_SIZE, SHMMNI,
};

const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;
const SHM_LOCK: u64 = 11;
const SHM_UNLOCK: u64 = 12;
const SHM_STAT: u64 = 13;
const SHM_INFO: u64 = 14;
const SHM_STAT_ANY: u64 = 15;
const PAGE_MASK: u64 = !(hal::PAGE_SIZE_BYTES - 1);

const S_IRUGO: u64 = 0o444;
const S_IRWXUGO: u32 = 0o777;
const SHMID64_DS_BYTES: usize = 112;
const SHMINFO64_BYTES: usize = 72;
const SHM_INFO_BYTES: usize = 48;
const IPC64_PERM_KEY_OFF: usize = 0;
const IPC64_PERM_UID_OFF: usize = 4;
const IPC64_PERM_GID_OFF: usize = 8;
const IPC64_PERM_CUID_OFF: usize = 12;
const IPC64_PERM_CGID_OFF: usize = 16;
const IPC64_PERM_MODE_OFF: usize = 20;
const SHMID64_SEGSZ_OFF: usize = 48;
const SHMID64_CPID_OFF: usize = 80;
const SHMID64_NATTCH_OFF: usize = 88;
const SHMINFO_SHMMAX_OFF: usize = 0;
const SHMINFO_SHMMIN_OFF: usize = 8;
const SHMINFO_SHMMNI_OFF: usize = 16;
const SHMINFO_SHMSEG_OFF: usize = 24;
const SHMINFO_SHMALL_OFF: usize = 32;
const SHM_INFO_USED_IDS_OFF: usize = 0;
const SHM_INFO_TOT_OFF: usize = 8;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct ShmctlSet {
    uid: u32,
    gid: u32,
    mode: u32,
}

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn can_admin(seg: &ShmSegment, cred: &IpcCred) -> bool {
    cred.euid == seg.cuid || cred.euid == seg.uid.load(Ordering::Acquire) || cred.cap_sys_admin
}

fn can_lock(seg: &ShmSegment, cred: &IpcCred) -> bool {
    cred.cap_ipc_lock || cred.euid == seg.cuid || cred.euid == seg.uid.load(Ordering::Acquire)
}

fn validate_user_buf(ptr: u64, len: usize, write: bool) -> Result<(), i64> {
    let _ = write;
    if ptr == 0 { return Err(err(Errno::Efault)); }
    let end = ptr.checked_add(len as u64).ok_or(err(Errno::Efault))?;
    if end > hal::USER_VA_END { return Err(err(Errno::Efault)); }
    #[cfg(target_os = "oxide-kernel")]
    {
        use hal::UserVirtAddr;
        use vmm::VmaProt;
        let cur = sched::current().ok_or(err(Errno::Efault))?;
        // SAFETY: current task mm is stable for this syscall while the kernel copies the fixed IPC object.
        let mm = unsafe { cur.mm_ref() }.ok_or(err(Errno::Efault))?.clone();
        if len == 0 { return Ok(()); }
        let mut va = ptr & PAGE_MASK;
        let end_inclusive = ptr + len as u64 - 1;
        while va <= (end_inclusive & PAGE_MASK) {
            let uva = UserVirtAddr::new(va).ok_or(err(Errno::Efault))?;
            let want = if write { VmaProt::WRITE } else { VmaProt::READ };
            match mm.find_vma(uva) {
                Some(v) if v.prot.contains(want) => {}
                _ => return Err(err(Errno::Efault)),
            }
            va = va.checked_add(hal::PAGE_SIZE_BYTES).ok_or(err(Errno::Efault))?;
        }
    }
    Ok(())
}

fn write_user_bytes(ptr: u64, src: &[u8]) -> Result<(), i64> {
    validate_user_buf(ptr, src.len(), true)?;
    // SAFETY: ptr validated writable for src.len() bytes; byte stores accept unaligned user buffers.
    unsafe { for (i, b) in src.iter().enumerate() { core::ptr::write_unaligned((ptr + i as u64) as *mut u8, *b); } }
    Ok(())
}

fn read_user_shmctl_set(ptr: u64) -> Result<ShmctlSet, i64> {
    validate_user_buf(ptr, SHMID64_DS_BYTES, false)?;
    // SAFETY: ptr validated readable for a Linux shmid64_ds; unaligned scalar reads match copy_from_user.
    unsafe {
        Ok(ShmctlSet {
            uid: core::ptr::read_unaligned((ptr + IPC64_PERM_UID_OFF as u64) as *const u32),
            gid: core::ptr::read_unaligned((ptr + IPC64_PERM_GID_OFF as u64) as *const u32),
            mode: core::ptr::read_unaligned((ptr + IPC64_PERM_MODE_OFF as u64) as *const u32),
        })
    }
}

fn put_u32(out: &mut [u8], off: usize, v: u32) { out[off..off + 4].copy_from_slice(&v.to_le_bytes()); }
fn put_i32(out: &mut [u8], off: usize, v: i32) { out[off..off + 4].copy_from_slice(&v.to_le_bytes()); }
fn put_u64(out: &mut [u8], off: usize, v: u64) { out[off..off + 8].copy_from_slice(&v.to_le_bytes()); }

fn encode_shmid64(seg: &ShmSegment) -> [u8; SHMID64_DS_BYTES] {
    let mut ds = [0u8; SHMID64_DS_BYTES];
    put_u32(&mut ds, IPC64_PERM_KEY_OFF, seg.key.load(Ordering::Acquire) as u32);
    put_u32(&mut ds, IPC64_PERM_UID_OFF, seg.uid.load(Ordering::Acquire));
    put_u32(&mut ds, IPC64_PERM_GID_OFF, seg.gid.load(Ordering::Acquire));
    put_u32(&mut ds, IPC64_PERM_CUID_OFF, seg.cuid);
    put_u32(&mut ds, IPC64_PERM_CGID_OFF, seg.cgid);
    put_u32(&mut ds, IPC64_PERM_MODE_OFF, seg.mode.load(Ordering::Acquire));
    put_u64(&mut ds, SHMID64_SEGSZ_OFF, seg.size as u64);
    put_i32(&mut ds, SHMID64_CPID_OFF, seg.cpid as i32);
    put_u64(&mut ds, SHMID64_NATTCH_OFF, seg.nattch.load(Ordering::Acquire).max(0) as u64);
    ds
}

fn encode_shminfo64() -> [u8; SHMINFO64_BYTES] {
    let mut b = [0u8; SHMINFO64_BYTES];
    put_u64(&mut b, SHMINFO_SHMMAX_OFF, SHM_MAX_SIZE as u64);
    put_u64(&mut b, SHMINFO_SHMMIN_OFF, 1);
    put_u64(&mut b, SHMINFO_SHMMNI_OFF, SHMMNI as u64);
    put_u64(&mut b, SHMINFO_SHMSEG_OFF, SHMMNI as u64);
    put_u64(&mut b, SHMINFO_SHMALL_OFF, SHM_MAX_SIZE as u64);
    b
}

fn encode_shm_info(segs: &[alloc::sync::Arc<ShmSegment>], ns: namespace_identity::NamespaceId) -> [u8; SHM_INFO_BYTES] {
    let mut b = [0u8; SHM_INFO_BYTES];
    let used = segs.iter().filter(|s| s.ns == ns && (s.mode.load(Ordering::Acquire) & SHM_DEST) == 0).count() as i32;
    let pages = segs.iter()
        .filter(|s| s.ns == ns && (s.mode.load(Ordering::Acquire) & SHM_DEST) == 0)
        .map(|s| ((s.size as u64) + PAGE_SIZE - 1) / PAGE_SIZE)
        .sum::<u64>();
    put_i32(&mut b, SHM_INFO_USED_IDS_OFF, used);
    put_u64(&mut b, SHM_INFO_TOT_OFF, pages);
    b
}

fn ns_segments(ns: namespace_identity::NamespaceId) -> Vec<alloc::sync::Arc<ShmSegment>> {
    let mut v: Vec<_> = REG.segs.lock().iter().filter(|s| s.ns == ns).cloned().collect();
    v.sort_unstable_by_key(|s| s.id);
    v
}

fn max_stat_index(segs: &[alloc::sync::Arc<ShmSegment>]) -> i64 {
    if segs.is_empty() { 0 } else { (segs.len() - 1) as i64 }
}

fn stat_segment(shmid: i32, cmd: u64, cred: &IpcCred) -> Result<(alloc::sync::Arc<ShmSegment>, i64), i64> {
    let owner = crate::ipc_namespace::current().map_err(|_| err(Errno::Einval))?;
    let ns = owner.key();
    let seg = if cmd == IPC_STAT {
        lookup_by_id(shmid).ok_or(err(Errno::Einval))?
    } else {
        if shmid < 0 { return Err(err(Errno::Einval)); }
        ns_segments(ns).get(shmid as usize).cloned().ok_or(err(Errno::Einval))?
    };
    if (seg.mode.load(Ordering::Acquire) & SHM_DEST) != 0 { return Err(err(Errno::Eidrm)); }
    if cmd != SHM_STAT_ANY && !ipc_permitted(&seg, cred, S_IRUGO) { return Err(err(Errno::Eacces)); }
    let ret = if cmd == IPC_STAT { 0 } else { seg.id as i64 };
    Ok((seg, ret))
}

fn set_segment(shmid: i32, cred: &IpcCred, set: ShmctlSet) -> i64 {
    let owner = match crate::ipc_namespace::current() {
        Ok(owner) => owner, Err(_) => return err(Errno::Einval),
    };
    let ns = owner.key();
    let g = REG.segs.lock();
    let Some(s) = g.iter().find(|s| s.id == shmid && s.ns == ns) else { return err(Errno::Einval); };
    if (s.mode.load(Ordering::Acquire) & SHM_DEST) != 0 { return err(Errno::Eidrm); }
    if !can_admin(s, cred) { return err(Errno::Eperm); }
    s.uid.store(set.uid, Ordering::Release);
    s.gid.store(set.gid, Ordering::Release);
    s.mode.fetch_update(Ordering::AcqRel, Ordering::Acquire, |mode| Some((mode & !S_IRWXUGO) | (set.mode & S_IRWXUGO))).ok();
    0
}

fn rmid_segment(shmid: i32, cred: &IpcCred) -> i64 {
    let owner = match crate::ipc_namespace::current() {
        Ok(owner) => owner, Err(_) => return err(Errno::Einval),
    };
    let ns = owner.key();
    let mut g = REG.segs.lock();
    let Some(pos) = g.iter().position(|s| s.id == shmid && s.ns == ns) else { return err(Errno::Einval); };
    if (g[pos].mode.load(Ordering::Acquire) & SHM_DEST) != 0 { return err(Errno::Eidrm); }
    if !can_admin(&g[pos], cred) { return err(Errno::Eperm); }
    if g[pos].nattch.load(Ordering::Acquire) > 0 {
        {
            let m = &g[pos];
            m.mode.fetch_or(SHM_DEST, Ordering::AcqRel);
            // Linux `do_shm_rmid` -> `ipc_set_key_private`: a doomed segment
            // leaves the key hash, so `shmget(key, ...)` can neither find it
            // nor be handed an id that is already being torn down. Without
            // this the marked segment stays reachable by key for as long as
            // an attacher survives.
            m.key.store(super::IPC_PRIVATE, Ordering::Release);
        }
    } else {
        g.remove(pos);
    }
    0
}

fn lock_segment(shmid: i32, cmd: u64, cred: &IpcCred) -> i64 {
    let owner = match crate::ipc_namespace::current() {
        Ok(owner) => owner, Err(_) => return err(Errno::Einval),
    };
    let ns = owner.key();
    let g = REG.segs.lock();
    let Some(s) = g.iter().find(|s| s.id == shmid && s.ns == ns) else { return err(Errno::Einval); };
    if (s.mode.load(Ordering::Acquire) & SHM_DEST) != 0 { return err(Errno::Eidrm); }
    if !can_lock(s, cred) { return err(Errno::Eperm); }
    // Huge pages are already unevictable — there is no swap path to lock them
    // out of — so the command succeeds and changes nothing, including the
    // `SHM_LOCKED` bit `IPC_STAT` reports. The permission checks above still
    // run: a caller with no claim on the segment is refused either way.
    if super::huge::seg_page_size(&s.backing) != PAGE_SIZE { return 0; }
    if cmd == SHM_LOCK { s.mode.fetch_or(SHM_LOCKED, Ordering::AcqRel); }
    else { s.mode.fetch_and(!SHM_LOCKED, Ordering::AcqRel); }
    0
}

/// `shmctl(shmid, cmd, buf)` — slot 31.
/// # C: O(N_segments)
pub fn sys_shmctl(args: &syscall::SyscallArgs) -> i64 {
    let shmid = args.a0 as i32;
    let cmd   = args.a1;
    let buf   = args.a2;
    if shmid < 0 || (cmd as i64) < 0 { return err(Errno::Einval); }
    let cred = current_ipc_cred();
    match cmd {
        IPC_INFO => {
            let owner = match crate::ipc_namespace::current() {
                Ok(owner) => owner, Err(_) => return err(Errno::Einval),
            };
            let ns = owner.key();
            let segs = ns_segments(ns);
            if let Err(e) = write_user_bytes(buf, &encode_shminfo64()) { return e; }
            max_stat_index(&segs)
        }
        SHM_INFO => {
            let owner = match crate::ipc_namespace::current() {
                Ok(owner) => owner, Err(_) => return err(Errno::Einval),
            };
            let ns = owner.key();
            let segs = ns_segments(ns);
            if let Err(e) = write_user_bytes(buf, &encode_shm_info(&segs, ns)) { return e; }
            max_stat_index(&segs)
        }
        IPC_STAT | SHM_STAT | SHM_STAT_ANY => {
            let (seg, ret) = match stat_segment(shmid, cmd, &cred) {
                Ok(v) => v, Err(e) => return e,
            };
            if let Err(e) = write_user_bytes(buf, &encode_shmid64(&seg)) { return e; }
            ret
        }
        IPC_SET => {
            let set = match read_user_shmctl_set(buf) {
                Ok(v) => v, Err(e) => return e,
            };
            set_segment(shmid, &cred, set)
        }
        IPC_RMID => rmid_segment(shmid, &cred),
        SHM_LOCK | SHM_UNLOCK => lock_segment(shmid, cmd, &cred),
        _ => err(Errno::Einval),
    }
}

#[cfg(test)]
mod tests;
