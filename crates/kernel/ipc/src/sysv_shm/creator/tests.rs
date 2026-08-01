//! `exit_shm` + `kernel.shm_rmid_forced`, driven against the real registry
//! with real `Task`s so the creator back-reference is exercised end to end
//! (`ipc/shm.c` `exit_shm` / `shm_destroy_orphaned`, `ipc/ipc_sysctl.c`).

use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use sched::Task;

use super::*;
use crate::sysv_shm::{lookup_by_id, rmid_forced, ShmSegment, SHM_DEST};

const IPC_CREAT: u64 = 0o1000;
const SEG_MODE: u64 = 0o600;
const SEG_SIZE: usize = 4096;

struct FakeBacking;

impl vmm::FileBacking for FakeBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { 0 }
}

fn backing() -> Arc<dyn vmm::FileBacking> { Arc::new(FakeBacking) }

/// `sched::current()` for the duration of a test. Holds no reference of its
/// own — each test keeps the `Arc<Task>` alive across every use.
static CUR: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());

fn hooked_current() -> Option<&'static Task> {
    let p = CUR.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: `become_current` stores only a pointer into a live `Arc<Task>` the calling test owns for the whole test body, and clears it before that Arc drops.
    Some(unsafe { &*p })
}

/// Make `task` the running task AND make it resolvable by tid, which is how
/// `current_creator` reaches an owned reference.
fn become_current(task: &Arc<Task>) {
    sched::registry::insert(task);
    CUR.store(Arc::as_ptr(task) as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
}

fn no_current() { CUR.store(ptr::null_mut(), Ordering::Release); }

fn task(tid: u32) -> Arc<Task> {
    Arc::new(Task::new(tid, "shm-creator", sched::SchedClass::Normal { weight: 1024 }))
}

/// The one reset body lives with the claim that owns it.
fn reset() { crate::sysv_shm::test_claim::reset_shm() }

fn create(key: i32) -> i32 {
    let cpid = 0;
    crate::sysv_shm::shmget_with_backing(key, SEG_SIZE, IPC_CREAT | SEG_MODE, cpid, backing) as i32
}

fn creator_of(id: i32) -> bool {
    lookup_by_id(id).expect("segment present").creator.lock().is_some()
}

#[test]
fn creation_records_the_creating_task() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let a = task(60_001);
    become_current(&a);
    let id = create(0x5100);
    assert!(id > 0);
    assert!(creator_of(id), "shmget records shm_creator");
    no_current();
    reset();
}

#[test]
fn creator_exit_orphans_the_segment_and_leaves_it_for_a_later_sweep() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let a = task(60_002);
    become_current(&a);
    let id = create(0x5200);
    exit_shm(&a);
    assert!(lookup_by_id(id).is_some(),
        "without shm_rmid_forced the creator's exit must not destroy the segment");
    assert!(!creator_of(id), "exit_shm unlinks the segment from its creator");
    // The deferred sweep is the whole point of unlinking without destroying.
    rmid_forced::set_shm_rmid_forced(1);
    assert!(lookup_by_id(id).is_none(),
        "setting kernel.shm_rmid_forced reclaims an already-orphaned segment");
    no_current();
    reset();
}

#[test]
fn creator_exit_under_forced_rmid_destroys_an_idle_segment() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let a = task(60_003);
    become_current(&a);
    rmid_forced::set_shm_rmid_forced(1);
    let id = create(0x5300);
    exit_shm(&a);
    assert!(lookup_by_id(id).is_none(), "forced rmid reclaims at creator exit");
    no_current();
    reset();
}

#[test]
fn a_still_attached_segment_survives_its_creators_exit_even_when_forced() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let a = task(60_004);
    become_current(&a);
    rmid_forced::set_shm_rmid_forced(1);
    let id = create(0x5400);
    lookup_by_id(id).unwrap().nattch.store(1, Ordering::Release);
    exit_shm(&a);
    let seg = lookup_by_id(id).expect("an attached segment outlives its creator");
    assert!(seg.creator.lock().is_none(), "but it is orphaned");
    // The surviving attacher detaching is what reclaims it, via shm_may_destroy.
    crate::sysv_shm::shm_vma_close(&seg.backing);
    assert!(lookup_by_id(id).is_none(),
        "last detach of an orphaned segment under forced rmid destroys it");
    no_current();
    reset();
}

#[test]
fn exit_shm_leaves_another_tasks_segments_alone() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let a = task(60_005);
    let b = task(60_006);
    become_current(&a);
    let mine = create(0x5500);
    become_current(&b);
    let theirs = create(0x5501);
    exit_shm(&a);
    assert!(!creator_of(mine), "the exiting task's segment is orphaned");
    assert!(creator_of(theirs), "a live task keeps its segments");
    no_current();
    reset();
}

#[test]
fn a_recycled_tid_does_not_inherit_the_dead_creators_segments() {
    // The reason the back-reference is a `Weak<Task>` and not `cpid`: tids are
    // reused, and a tid-keyed creator list would let the NEXT task with the
    // same number orphan (and under forced rmid destroy) segments it never
    // created.
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    const TID: u32 = 60_007;
    let first = task(TID);
    become_current(&first);
    let id = create(0x5600);
    let recycled = task(TID);
    assert_eq!(recycled.tid, first.tid);
    become_current(&recycled);
    exit_shm(&recycled);
    assert!(creator_of(id), "same tid, different task: the segment is not unlinked");
    exit_shm(&first);
    assert!(!creator_of(id), "the real creator's exit does unlink it");
    no_current();
    reset();
}

#[test]
fn orphan_sweep_skips_segments_whose_creator_is_still_alive() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let a = task(60_008);
    become_current(&a);
    let live = create(0x5700);
    let doomed = create(0x5701);
    lookup_by_id(doomed).unwrap().creator.lock().take();
    rmid_forced::set_shm_rmid_forced(1);
    assert!(lookup_by_id(live).is_some(),
        "shm_destroy_orphaned only collects segments with no creator");
    assert!(lookup_by_id(doomed).is_none());
    no_current();
    reset();
}

#[test]
fn rmid_forced_flag_round_trips_and_defaults_off() {
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    assert_eq!(rmid_forced::shm_rmid_forced(), 0);
    rmid_forced::set_shm_rmid_forced(1);
    assert_eq!(rmid_forced::shm_rmid_forced(), 1);
    // Setting it twice must not record the namespace twice.
    rmid_forced::set_shm_rmid_forced(1);
    assert_eq!(rmid_forced::shm_rmid_forced(), 1);
    rmid_forced::set_shm_rmid_forced(0);
    assert_eq!(rmid_forced::shm_rmid_forced(), 0);
    assert_eq!(rmid_forced::RMID_FORCED_BOUNDS, (0, 1));
    reset();
}

#[test]
fn forced_rmid_reclaims_a_never_rmided_segment_at_its_last_detach() {
    // The `shm_may_destroy` arm that only exists once the sysctl does: with
    // rmid_forced clear this segment survives, with it set the last detach
    // takes it, without any IPC_RMID ever being issued.
    let _shm = crate::sysv_shm::test_claim::claim_shm();
    let seg = Arc::new(ShmSegment {
        id: 60_100, key: 0x5800, ns: crate::ipc_namespace::current().unwrap().key(),
        size: SEG_SIZE, mode: SEG_MODE as u32,
        uid: 0, gid: 0, cuid: 0, cgid: 0, cpid: 1,
        nattch: core::sync::atomic::AtomicI64::new(2),
        creator: sync::Spinlock::new(None),
        backing: backing(),
    });
    crate::sysv_shm::REG.segs.lock().push(seg.clone());
    crate::sysv_shm::shm_vma_close(&seg.backing);
    crate::sysv_shm::shm_vma_close(&seg.backing);
    assert!(lookup_by_id(60_100).is_some(), "unforced: an idle segment survives");
    assert_eq!(seg.mode & SHM_DEST, 0, "and it was never marked for destruction");
    // Re-attach BEFORE arming the sysctl, so the orphan sweep it runs cannot
    // take the segment and the reclaim under test is the DETACH path.
    seg.nattch.store(1, Ordering::Release);
    rmid_forced::set_shm_rmid_forced(1);
    assert!(lookup_by_id(60_100).is_some(), "an attached segment survives the sweep");
    crate::sysv_shm::shm_vma_close(&seg.backing);
    assert!(lookup_by_id(60_100).is_none(), "forced: the last detach reclaims it");
    reset();
}
