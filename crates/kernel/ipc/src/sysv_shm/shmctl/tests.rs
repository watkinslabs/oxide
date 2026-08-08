//! `shmctl(2)` command tests: the permission ladders, the encoded
//! `shmid64_ds`/`shminfo64`/`shm_info` layouts, and the huge-page cases.

use super::*;
use alloc::sync::Arc;
use sync::Spinlock;

struct FakeBacking;

impl vmm::FileBacking for FakeBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { 0 }
}


fn backing() -> Arc<dyn vmm::FileBacking> {
    Arc::new(FakeBacking)
}

/// A backing made of huge pages, standing in for the hugetlbfs file a
/// `SHM_HUGETLB` segment is built on.
struct FakeHugeBacking;

impl vmm::FileBacking for FakeHugeBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { HUGE_2M }
    fn huge_page_size(&self) -> u64 { HUGE_2M }
}

const HUGE_2M: u64 = 2 * 1024 * 1024;

fn shim(want: crate::sysv_shm::SegBacking) -> Result<Arc<dyn vmm::FileBacking>, Errno> {
    Ok(match want {
        crate::sysv_shm::SegBacking::Shmem => backing(),
        crate::sysv_shm::SegBacking::Huge { .. } => Arc::new(FakeHugeBacking),
    })
}

/// The one reset body lives with the claim that owns it.
fn reset() { crate::sysv_shm::test_claim::reset_shm() }

fn cred(euid: u32, egid: u32, groups: &[u32], cap_ipc_owner: bool) -> IpcCred {
    cred_caps(euid, egid, groups, cap_ipc_owner, false, cap_ipc_owner)
}

fn cred_caps(
    euid: u32, egid: u32, groups: &[u32], cap_ipc_owner: bool, cap_ipc_lock: bool, cap_sys_admin: bool,
) -> IpcCred {
    let out = IpcCred {
        euid,
        egid,
        groups: vfs::GroupList::from_slice(groups),
        cap_ipc_owner,
        cap_ipc_lock,
        cap_sys_admin,
        cap_sys_resource: cap_sys_admin,
    };
    out
}

fn shmget(key: i32, size: usize, flg: u64, cred: IpcCred) -> i64 {
    crate::sysv_shm::shmget_with_backing_cred(key, size, flg, 77, cred, shim)
}

fn get_u32(b: &[u8], off: usize) -> u32 { u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) }
fn get_u64(b: &[u8], off: usize) -> u64 { u64::from_le_bytes(b[off..off + 8].try_into().unwrap()) }

#[test]
fn ipc_info_and_shm_info_do_not_require_valid_shmid() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let c = cred(10, 20, &[], false);
    assert!(shmget(10, 4096, crate::sysv_shm::IPC_CREAT | 0o600, c.clone()) > 0);
    assert!(shmget(11, 8192, crate::sysv_shm::IPC_CREAT | 0o600, c) > 0);
    let owner = crate::ipc_namespace::current().unwrap();
    let ns = owner.key();
    let segs = ns_segments(ns);
    assert_eq!(max_stat_index(&segs), 1);
    let info = encode_shminfo64();
    assert_eq!(get_u64(&info, SHMINFO_SHMMAX_OFF), SHM_MAX_SIZE as u64);
    assert_eq!(get_u64(&info, SHMINFO_SHMMNI_OFF), SHMMNI as u64);
    let si = encode_shm_info(&segs, ns);
    assert_eq!(get_u32(&si, SHM_INFO_USED_IDS_OFF), 2);
    assert_eq!(get_u64(&si, SHM_INFO_TOT_OFF), 3);
}

#[test]
fn stat_permissions_and_stat_any_match_linux() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let owner = crate::ipc_namespace::current().unwrap();
    let seg = alloc::sync::Arc::new(ShmSegment {
        id: 7, key: core::sync::atomic::AtomicI32::new(9), ns: owner.key(), size: 4096, mode: core::sync::atomic::AtomicU32::new(0o600),
        uid: core::sync::atomic::AtomicU32::new(10), gid: core::sync::atomic::AtomicU32::new(20), cuid: 10, cgid: 20, cpid: 77,
        nattch: core::sync::atomic::AtomicI64::new(2),
        creator: Spinlock::new(None),
        backing: backing(),
    });
    REG.segs.lock().push(seg.clone());
    let other = cred(30, 30, &[], false);
    assert!(matches!(stat_segment(7, IPC_STAT, &other), Err(e) if e == err(Errno::Eacces)));
    let (got, ret) = stat_segment(0, SHM_STAT_ANY, &other).unwrap();
    assert_eq!(got.id, 7);
    assert_eq!(ret, 7);
    let bytes = encode_shmid64(&seg);
    assert_eq!(get_u32(&bytes, IPC64_PERM_KEY_OFF), 9);
    assert_eq!(get_u32(&bytes, IPC64_PERM_MODE_OFF), 0o600);
    assert_eq!(get_u64(&bytes, SHMID64_SEGSZ_OFF), 4096);
    assert_eq!(get_u64(&bytes, SHMID64_NATTCH_OFF), 2);
}

#[test]
fn ipc_set_and_rmid_require_owner_or_sys_admin() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let owner = cred(10, 20, &[], false);
    let id = shmget(77, 4096, crate::sysv_shm::IPC_CREAT | 0o600, owner.clone()) as i32;
    assert_eq!(set_segment(id, &cred(99, 99, &[], false), ShmctlSet { uid: 1, gid: 2, mode: 0o644 }), err(Errno::Eperm));
    assert_eq!(set_segment(id, &owner, ShmctlSet { uid: 1, gid: 2, mode: 0o644 }), 0);
    let s = lookup_by_id(id).unwrap();
    assert_eq!((s.uid.load(Ordering::Acquire), s.gid.load(Ordering::Acquire), s.mode.load(Ordering::Acquire) & S_IRWXUGO), (1, 2, 0o644));
    drop(s);
    assert_eq!(rmid_segment(id, &cred_caps(99, 99, &[], false, false, true)), 0);
    assert!(lookup_by_id(id).is_none());
}

#[test]
fn rmid_with_attachers_marks_and_unpublishes_the_key() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    const KEY: i32 = 0x5900;
    let owner = cred(10, 20, &[], false);
    let id = shmget(KEY, 4096, crate::sysv_shm::IPC_CREAT | 0o600, owner.clone()) as i32;
    lookup_by_id(id).unwrap().nattch.store(1, Ordering::Release);
    assert_eq!(rmid_segment(id, &owner), 0);
    let seg = lookup_by_id(id).expect("an attached segment is marked, not removed");
    assert_ne!(seg.mode.load(Ordering::Acquire) & SHM_DEST, 0);
    assert_eq!(seg.key.load(Ordering::Acquire), crate::sysv_shm::IPC_PRIVATE, "a doomed segment leaves the key hash");
    drop(seg);
    // Linux: the key is free again, so this creates a NEW segment rather
    // than handing back the id being torn down.
    let fresh = shmget(KEY, 4096, crate::sysv_shm::IPC_CREAT | 0o600, owner) as i32;
    assert!(fresh > 0);
    assert_ne!(fresh, id);
    reset();
}

#[test]
fn lock_unlock_require_owner_or_ipc_lock_and_toggle_mode_bit() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let owner = cred(10, 20, &[], false);
    let id = shmget(88, 4096, crate::sysv_shm::IPC_CREAT | 0o600, owner.clone()) as i32;
    assert_eq!(lock_segment(id, SHM_LOCK, &cred(99, 99, &[], false)), err(Errno::Eperm));
    assert_eq!(lock_segment(id, SHM_LOCK, &owner), 0);
    let s = lookup_by_id(id).unwrap();
    assert_ne!(s.mode.load(Ordering::Acquire) & SHM_LOCKED, 0);
    drop(s);
    assert_eq!(lock_segment(id, SHM_UNLOCK, &cred(99, 99, &[], false)), err(Errno::Eperm));
    assert_eq!(lock_segment(id, SHM_UNLOCK, &cred_caps(99, 99, &[], false, true, false)), 0);
    assert_eq!(lookup_by_id(id).unwrap().mode.load(Ordering::Acquire) & SHM_LOCKED, 0);
}

#[test]
fn lock_on_a_huge_segment_succeeds_and_leaves_the_mode_bit_alone() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let owner = cred_caps(10, 20, &[], false, true, false);
    let id = shmget(
        89, 4096, crate::sysv_shm::IPC_CREAT | crate::sysv_shm::huge::SHM_HUGETLB | 0o600, owner.clone()) as i32;
    assert!(id > 0);
    assert_eq!(lock_segment(id, SHM_LOCK, &owner), 0);
    let s = lookup_by_id(id).unwrap();
    assert_eq!(s.mode.load(Ordering::Acquire) & SHM_LOCKED, 0,
               "huge pages are already unevictable, so there is nothing to record");
    drop(s);
    assert_eq!(lock_segment(id, SHM_UNLOCK, &owner), 0);
    // The permission ladder still runs ahead of the huge-page short-circuit.
    assert_eq!(lock_segment(id, SHM_LOCK, &cred(99, 99, &[], false)), err(Errno::Eperm));
}

#[test]
fn a_huge_segment_counts_its_requested_size_in_base_pages_for_shm_info() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let owner = cred_caps(10, 20, &[], false, true, false);
    assert!(shmget(
        90, 8192, crate::sysv_shm::IPC_CREAT | crate::sysv_shm::huge::SHM_HUGETLB | 0o600, owner) as i32 > 0);
    let ns = crate::ipc_namespace::current().unwrap().key();
    let si = encode_shm_info(&ns_segments(ns), ns);
    assert_eq!(get_u64(&si, SHM_INFO_TOT_OFF), 2,
               "shm_tot is the requested size in base pages, not the huge-page span");
}

#[test]
fn control_operations_succeed_while_an_attacher_holds_a_segment_reference() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let owner = cred(10, 20, &[], false);
    let set_id = shmget(101, 4096, crate::sysv_shm::IPC_CREAT | 0o600, owner.clone()) as i32;
    let set_hold = lookup_by_id(set_id).unwrap();
    assert_eq!(set_segment(set_id, &owner, ShmctlSet { uid: 11, gid: 21, mode: 0o640 }), 0);
    assert_eq!(set_hold.uid.load(Ordering::Acquire), 11);

    let lock_id = shmget(102, 4096, crate::sysv_shm::IPC_CREAT | 0o600, owner.clone()) as i32;
    let lock_hold = lookup_by_id(lock_id).unwrap();
    assert_eq!(lock_segment(lock_id, SHM_LOCK, &owner), 0);
    assert_ne!(lock_hold.mode.load(Ordering::Acquire) & SHM_LOCKED, 0);

    let rmid_id = shmget(103, 4096, crate::sysv_shm::IPC_CREAT | 0o600, owner.clone()) as i32;
    let rmid_hold = lookup_by_id(rmid_id).unwrap();
    rmid_hold.nattch.store(1, Ordering::Release);
    assert_eq!(rmid_segment(rmid_id, &owner), 0);
    assert_ne!(rmid_hold.mode.load(Ordering::Acquire) & SHM_DEST, 0);
    assert_eq!(rmid_hold.key.load(Ordering::Acquire), crate::sysv_shm::IPC_PRIVATE);
}

#[test]
fn syscall_entry_copies_stat_info_and_set_buffers() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let owner = cred(10, 20, &[], false);
    let id = shmget(99, 4096, crate::sysv_shm::IPC_CREAT | 0o600, owner) as i32;
    let mut ds = [0u8; SHMID64_DS_BYTES];
    let stat = syscall::SyscallArgs { a0: id as u64, a1: IPC_STAT, a2: ds.as_mut_ptr() as u64, ..Default::default() };
    assert_eq!(sys_shmctl(&stat), 0);
    assert_eq!(get_u32(&ds, IPC64_PERM_KEY_OFF), 99);
    assert_eq!(get_u64(&ds, SHMID64_SEGSZ_OFF), 4096);
    assert_eq!(sys_shmctl(&syscall::SyscallArgs { a0: id as u64, a1: IPC_STAT, a2: 0, ..Default::default() }), err(Errno::Efault));

    let mut set = [0u8; SHMID64_DS_BYTES];
    put_u32(&mut set, IPC64_PERM_UID_OFF, 42);
    put_u32(&mut set, IPC64_PERM_GID_OFF, 43);
    put_u32(&mut set, IPC64_PERM_MODE_OFF, 0o640);
    let set_args = syscall::SyscallArgs { a0: id as u64, a1: IPC_SET, a2: set.as_ptr() as u64, ..Default::default() };
    assert_eq!(sys_shmctl(&set_args), 0);
    let seg = lookup_by_id(id).unwrap();
    assert_eq!((seg.uid.load(Ordering::Acquire), seg.gid.load(Ordering::Acquire), seg.mode.load(Ordering::Acquire) & S_IRWXUGO), (42, 43, 0o640));
    drop(seg);

    let mut info = [0u8; SHMINFO64_BYTES];
    let info_args = syscall::SyscallArgs { a0: 12345, a1: IPC_INFO, a2: info.as_mut_ptr() as u64, ..Default::default() };
    assert_eq!(sys_shmctl(&info_args), 0);
    assert_eq!(get_u64(&info, SHMINFO_SHMMNI_OFF), SHMMNI as u64);
}
