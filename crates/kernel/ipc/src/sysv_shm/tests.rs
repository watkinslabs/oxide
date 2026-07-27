use super::*;
use core::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

struct FakeBacking;

impl vmm::FileBacking for FakeBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { 0 }
}

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn err(e: syscall::errno::Errno) -> i64 {
    -(e.as_i32() as i64)
}

fn cred(euid: u32, egid: u32, groups: &[u32], cap: bool) -> IpcCred {
    let mut out = IpcCred {
        euid,
        egid,
        groups: [0; sched::Creds::NGROUPS_V1],
        ngroups: groups.len().min(sched::Creds::NGROUPS_V1),
        cap_ipc_owner: cap,
        cap_ipc_lock: false,
        cap_sys_admin: cap,
        cap_sys_resource: cap,
    };
    out.groups[..out.ngroups].copy_from_slice(&groups[..out.ngroups]);
    out
}

fn reset() {
    REG.next_id.store(1, AtomicOrdering::Release);
    REG.segs.lock().clear();
}

fn backing() -> Arc<dyn vmm::FileBacking> {
    Arc::new(FakeBacking)
}

fn shmget(key: i32, size: usize, flg: u64, cred: IpcCred) -> i64 {
    shmget_with_backing_cred(key, size, flg, 77, cred, backing)
}

fn segment(mode: u32, size: usize) -> Arc<ShmSegment> {
    let owner = crate::ipc_namespace::current().unwrap();
    Arc::new(ShmSegment {
        id: 1, key: 1, ns: owner.key(), size, mode,
        uid: 10, gid: 20, cuid: 10, cgid: 20, cpid: 77,
        nattch: core::sync::atomic::AtomicI64::new(0),
        backing: backing(),
    })
}

#[test]
fn private_key_always_creates_and_validates_new_size() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let c = cred(10, 20, &[], false);
    let a = shmget(IPC_PRIVATE, 1, 0, c.clone());
    let b = shmget(IPC_PRIVATE, 1, 0, c.clone());
    assert!(a > 0);
    assert!(b > 0);
    assert_ne!(a, b);
    assert_eq!(shmget(IPC_PRIVATE, 0, 0, c), err(syscall::errno::Errno::Einval));
}

#[test]
fn missing_public_key_without_create_returns_enoent_before_size_validation() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let calls = AtomicUsize::new(0);
    let r = shmget_with_backing_cred(123, 0, 0, 77, cred(1, 1, &[], false), || {
        calls.fetch_add(1, AtomicOrdering::AcqRel);
        backing()
    });
    assert_eq!(r, err(syscall::errno::Errno::Enoent));
    assert_eq!(calls.load(AtomicOrdering::Acquire), 0);
}

#[test]
fn create_public_key_records_owner_mode_and_lazy_allocates() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let calls = AtomicUsize::new(0);
    let id = shmget_with_backing_cred(44, 4096, IPC_CREAT | 0o640, 77, cred(42, 7, &[], false), || {
        calls.fetch_add(1, AtomicOrdering::AcqRel);
        backing()
    });
    assert!(id > 0);
    assert_eq!(calls.load(AtomicOrdering::Acquire), 1);
    let seg = lookup_by_id(id as i32).unwrap();
    assert_eq!(seg.key, 44);
    assert_eq!(seg.size, 4096);
    assert_eq!(seg.mode, 0o640);
    assert_eq!(seg.uid, 42);
    assert_eq!(seg.gid, 7);
    assert_eq!(seg.cuid, 42);
    assert_eq!(seg.cgid, 7);
}

#[test]
fn existing_key_honors_excl_size_and_permissions() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let owner = cred(10, 20, &[], false);
    let id = shmget(55, 8192, IPC_CREAT | 0o640, owner.clone());
    assert!(id > 0);
    assert_eq!(shmget(55, 0, 0, owner.clone()), id);
    assert_eq!(shmget(55, 8193, 0, owner.clone()), err(syscall::errno::Errno::Einval));
    assert_eq!(shmget(55, 1, IPC_CREAT | IPC_EXCL, owner.clone()), err(syscall::errno::Errno::Eexist));
    assert_eq!(shmget(55, 1, 0o400, cred(99, 99, &[], false)), err(syscall::errno::Errno::Eacces));
    assert_eq!(shmget(55, 1, 0o400, cred(99, 20, &[], false)), id);
    assert_eq!(shmget(55, 1, 0o400, cred(99, 99, &[20], false)), id);
    assert_eq!(shmget(55, 1, 0o400, cred(99, 99, &[], true)), id);
}

#[test]
fn hugetlb_create_is_rejected_without_allocating_normal_shmem() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let calls = AtomicUsize::new(0);
    let c = cred(10, 20, &[], false);
    let r = shmget_with_backing_cred(66, 4096, IPC_CREAT | SHM_HUGETLB | 0o600, 77, c.clone(), || {
        calls.fetch_add(1, AtomicOrdering::AcqRel);
        backing()
    });
    assert_eq!(r, err(syscall::errno::Errno::Einval));
    assert_eq!(calls.load(AtomicOrdering::Acquire), 0);
    let id = shmget(66, 4096, IPC_CREAT | 0o600, c.clone());
    assert_eq!(shmget(66, 1, SHM_HUGETLB, c), id);
}

#[test]
fn shmat_readonly_and_write_permissions_match_ipcperms() {
    let seg = segment(0o400, 4096);
    let owner = cred(10, 20, &[], false);
    let ro = shmat_plan(&seg, &owner, 0, SHM_RDONLY, false).unwrap();
    assert_eq!(ro.prot, vmm::VmaProt::READ);
    assert_eq!(shmat_plan(&seg, &owner, 0, 0, false).unwrap_err(), syscall::errno::Errno::Eacces);
}

#[test]
fn shmat_exec_requires_execute_permission() {
    let owner = cred(10, 20, &[], false);
    let no_exec = segment(0o600, 4096);
    assert_eq!(shmat_plan(&no_exec, &owner, 0, SHM_EXEC, false).unwrap_err(), syscall::errno::Errno::Eacces);
    let exec = segment(0o700, 4096);
    let plan = shmat_plan(&exec, &owner, 0, SHM_EXEC, false).unwrap();
    assert!(plan.prot.contains(vmm::VmaProt::READ));
    assert!(plan.prot.contains(vmm::VmaProt::WRITE));
    assert!(plan.prot.contains(vmm::VmaProt::EXEC));
}

#[test]
fn shmat_address_alignment_rounding_and_remap_null_match_linux() {
    let owner = cred(10, 20, &[], false);
    let seg = segment(0o600, 4096);
    assert_eq!(shmat_plan(&seg, &owner, 0x4000_0123, 0, false).unwrap_err(), syscall::errno::Errno::Einval);
    let rounded = shmat_plan(&seg, &owner, 0x4000_0123, SHM_RND, false).unwrap();
    assert_eq!(rounded.addr, Some(0x4000_0000));
    assert_eq!(shmat_plan(&seg, &owner, 0, SHM_REMAP, false).unwrap_err(), syscall::errno::Errno::Einval);
    assert_eq!(shmat_plan(&seg, &owner, 0x123, SHM_RND | SHM_REMAP, false).unwrap_err(), syscall::errno::Errno::Einval);
}

#[test]
fn shmat_overlap_requires_remap() {
    let owner = cred(10, 20, &[], false);
    let seg = segment(0o600, 4096);
    assert_eq!(shmat_plan(&seg, &owner, 0x4000_0000, 0, true).unwrap_err(), syscall::errno::Errno::Einval);
    let plan = shmat_plan(&seg, &owner, 0x4000_0000, SHM_REMAP, true).unwrap();
    assert_eq!(plan.addr, Some(0x4000_0000));
    assert!(plan.fixed);
}
