use super::*;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering as AtomicOrdering};

struct FakeBacking;

impl vmm::FileBacking for FakeBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { 0 }
}

/// A backing made of huge pages, standing in for the hugetlbfs file the ABI
/// shim builds — the granule is the only thing the registry reads from it.
pub(super) struct FakeHugeBacking(pub u64);

impl vmm::FileBacking for FakeHugeBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { self.0 }
    fn huge_page_size(&self) -> u64 { self.0 }
}

const HUGE_2M: u64 = 2 * 1024 * 1024;

/// One lock for EVERY `sysv_shm` test module. `REG` is a single process-wide
/// registry and each module used to hold its own lock, so a `reset()` in one
/// module could clear the registry another module's test had just populated.
fn err(e: syscall::errno::Errno) -> i64 {
    -(e.as_i32() as i64)
}

fn cred(euid: u32, egid: u32, groups: &[u32], cap: bool) -> IpcCred {
    IpcCred {
        euid,
        egid,
        groups: vfs::GroupList::from_slice(groups),
        cap_ipc_owner: cap,
        cap_ipc_lock: false,
        cap_sys_admin: cap,
        cap_sys_resource: cap,
    }
}

fn cred_ipc_lock(euid: u32, egid: u32) -> IpcCred {
    let mut c = cred(euid, egid, &[], false);
    c.cap_ipc_lock = true;
    c
}

/// The one reset body lives with the claim that owns it.
fn reset() { crate::sysv_shm::test_claim::reset_shm() }

fn backing() -> Arc<dyn vmm::FileBacking> {
    Arc::new(FakeBacking)
}

/// The shim's job, faked: turn the registry's request into an object of the
/// kind it asked for. A huge request whose granule the pool cannot serve is
/// what `refuse_huge` stands in for.
fn shim(want: SegBacking) -> Result<Arc<dyn vmm::FileBacking>, syscall::errno::Errno> {
    Ok(match want {
        SegBacking::Shmem => backing(),
        SegBacking::Huge { .. } => Arc::new(FakeHugeBacking(HUGE_2M)),
    })
}

fn shmget(key: i32, size: usize, flg: u64, cred: IpcCred) -> i64 {
    shmget_with_backing_cred(key, size, flg, 77, cred, shim)
}

fn segment(mode: u32, size: usize) -> Arc<ShmSegment> {
    segment_on(mode, size, backing())
}

fn segment_on(mode: u32, size: usize, backing: Arc<dyn vmm::FileBacking>) -> Arc<ShmSegment> {
    let owner = crate::ipc_namespace::current().unwrap();
    Arc::new(ShmSegment {
        id: 1, key: AtomicI32::new(1), ns: owner.key(), size, mode: AtomicU32::new(mode),
        uid: AtomicU32::new(10), gid: AtomicU32::new(20), cuid: 10, cgid: 20, cpid: 77,
        nattch: core::sync::atomic::AtomicI64::new(0),
        creator: Spinlock::new(None),
        backing,
    })
}

#[test]
fn private_key_always_creates_and_validates_new_size() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
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
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let calls = AtomicUsize::new(0);
    let r = shmget_with_backing_cred(123, 0, 0, 77, cred(1, 1, &[], false), |want| {
        calls.fetch_add(1, AtomicOrdering::AcqRel);
        shim(want)
    });
    assert_eq!(r, err(syscall::errno::Errno::Enoent));
    assert_eq!(calls.load(AtomicOrdering::Acquire), 0);
}

#[test]
fn create_public_key_records_owner_mode_and_lazy_allocates() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let calls = AtomicUsize::new(0);
    let id = shmget_with_backing_cred(44, 4096, IPC_CREAT | 0o640, 77, cred(42, 7, &[], false), |want| {
        assert_eq!(want, SegBacking::Shmem);
        calls.fetch_add(1, AtomicOrdering::AcqRel);
        shim(want)
    });
    assert!(id > 0);
    assert_eq!(calls.load(AtomicOrdering::Acquire), 1);
    let seg = lookup_by_id(id as i32).unwrap();
    assert_eq!(seg.key.load(AtomicOrdering::Acquire), 44);
    assert_eq!(seg.size, 4096);
    assert_eq!(seg.mode.load(AtomicOrdering::Acquire), 0o640);
    assert_eq!(seg.uid.load(AtomicOrdering::Acquire), 42);
    assert_eq!(seg.gid.load(AtomicOrdering::Acquire), 7);
    assert_eq!(seg.cuid, 42);
    assert_eq!(seg.cgid, 7);
}

#[test]
fn existing_key_honors_excl_size_and_permissions() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
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

const SHM_HUGE_SHIFT: u32 = 26;
const SHM_HUGE_1GB: u64 = 30 << SHM_HUGE_SHIFT;

#[test]
fn hugetlb_create_builds_a_huge_backing_and_rounds_the_segment_up() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let asked = AtomicUsize::new(0);
    let c = cred_ipc_lock(10, 20);
    let id = shmget_with_backing_cred(66, 4096, IPC_CREAT | huge::SHM_HUGETLB | 0o600, 77, c.clone(), |want| {
        assert_eq!(want, SegBacking::Huge { log: 0, bytes: HUGE_2M },
                   "the default selector asks for one whole default-granule page");
        asked.fetch_add(1, AtomicOrdering::AcqRel);
        shim(want)
    });
    assert!(id > 0);
    assert_eq!(asked.load(AtomicOrdering::Acquire), 1);
    let seg = lookup_by_id(id as i32).unwrap();
    assert_eq!(seg.size, 4096, "IPC_STAT reports the size the caller asked for");
    assert_eq!(seg_span(&seg), Some(HUGE_2M as usize),
               "an attachment covers the whole huge page the file is made of");
}

#[test]
fn the_size_selector_chooses_the_granule_the_backing_is_built_at() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let c = cred_ipc_lock(10, 20);
    let id = shmget_with_backing_cred(
        67, 1, IPC_CREAT | huge::SHM_HUGETLB | SHM_HUGE_1GB | 0o600, 77, c, |want| {
            assert_eq!(want, SegBacking::Huge { log: 30, bytes: 1024 * 1024 * 1024 });
            shim(want)
        });
    assert!(id > 0);
}

#[test]
fn an_invalid_size_selector_is_einval_before_anything_is_built() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let calls = AtomicUsize::new(0);
    let c = cred_ipc_lock(10, 20);
    let r = shmget_with_backing_cred(
        68, 4096, IPC_CREAT | huge::SHM_HUGETLB | (16u64 << SHM_HUGE_SHIFT) | 0o600, 77, c, |want| {
            calls.fetch_add(1, AtomicOrdering::AcqRel);
            shim(want)
        });
    assert_eq!(r, err(syscall::errno::Errno::Einval));
    assert_eq!(calls.load(AtomicOrdering::Acquire), 0);
}

#[test]
fn a_caller_with_neither_the_capability_nor_the_group_is_eperm() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let calls = AtomicUsize::new(0);
    let plain = cred(10, 20, &[], false);
    let ask = |c: IpcCred, key: i32| shmget_with_backing_cred(
        key, 4096, IPC_CREAT | huge::SHM_HUGETLB | 0o600, 77, c, |want| {
            calls.fetch_add(1, AtomicOrdering::AcqRel);
            shim(want)
        });
    assert_eq!(ask(plain.clone(), 69), err(syscall::errno::Errno::Eperm));
    assert_eq!(calls.load(AtomicOrdering::Acquire), 0, "nothing is built for a refused caller");
    // The configured group is the second, independent grant.
    huge::set_hugetlb_shm_group(20);
    assert!(ask(plain.clone(), 70) > 0, "the effective gid is in the group");
    huge::set_hugetlb_shm_group(21);
    assert_eq!(ask(cred(10, 20, &[21], false), 71) > 0, true, "a supplementary group counts");
    assert_eq!(ask(plain, 72), err(syscall::errno::Errno::Eperm));
}

#[test]
fn a_pool_that_cannot_satisfy_the_request_reports_its_own_errno() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let c = cred_ipc_lock(10, 20);
    let r = shmget_with_backing_cred(
        73, 4096, IPC_CREAT | huge::SHM_HUGETLB | 0o600, 77, c, |_| Err(syscall::errno::Errno::Enomem));
    assert_eq!(r, err(syscall::errno::Errno::Enomem));
    assert!(lookup_by_id(1).is_none(), "a segment whose backing failed is not registered");
}

#[test]
fn an_existing_key_is_returned_whatever_the_huge_flag_says() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let c = cred(10, 20, &[], false);
    let id = shmget(66, 4096, IPC_CREAT | 0o600, c.clone());
    assert!(id > 0);
    assert_eq!(shmget(66, 1, huge::SHM_HUGETLB, c), id);
}

#[test]
fn a_huge_segment_attaches_at_granule_alignment_and_maps_whole_pages() {
    let owner = cred(10, 20, &[], false);
    let seg = segment_on(0o600, 4096, Arc::new(FakeHugeBacking(HUGE_2M)));
    let plan = shmat_plan(&seg, &owner, 0, 0, false).unwrap();
    assert_eq!(plan.len, HUGE_2M as usize);
    assert_eq!(shmat_plan(&seg, &owner, HUGE_2M + 4096, 0, false).unwrap_err(),
               syscall::errno::Errno::Einval, "a page-aligned address off the granule is refused");
    assert_eq!(shmat_plan(&seg, &owner, HUGE_2M + 4096 + 0x123, SHM_RND, false).unwrap_err(),
               syscall::errno::Errno::Einval, "rounding to the attach boundary does not rescue it");
    assert_eq!(shmat_plan(&seg, &owner, 2 * HUGE_2M, 0, false).unwrap().addr, Some(2 * HUGE_2M));
}

#[test]
fn an_ordinary_segment_still_attaches_at_base_page_alignment() {
    let owner = cred(10, 20, &[], false);
    let seg = segment(0o600, 4096);
    assert_eq!(shmat_plan(&seg, &owner, 0x4000_1000, 0, false).unwrap().addr, Some(0x4000_1000));
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
