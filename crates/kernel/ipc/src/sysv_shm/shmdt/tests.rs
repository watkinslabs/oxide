//! `shmdt` placement rule + detach accounting, per `ipc/shm.c` `ksys_shmdt`
//! and `shm_close`.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, Ordering};

use super::*;
use crate::sysv_shm::{lookup_by_id, ShmSegment, PAGE_SIZE, REG, SHM_DEST};

const SPAN: u64 = 4 * PAGE_SIZE;
const BASE: u64 = 0x7000_0000;

struct FakeBacking;

impl vmm::FileBacking for FakeBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, vmm::FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { 0 }
}

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn vma(start: u64, end: u64, off: u64, seg: Option<usize>) -> DetachVma {
    DetachVma { start, end, off, seg }
}

fn plan(vmas: &[DetachVma], addr: u64) -> Option<DetachPlan> {
    plan_detach(vmas, addr, |_| Some(SPAN))
}

#[test]
fn whole_attachment_detaches_from_its_base_address() {
    let vmas = [vma(BASE, BASE + SPAN, 0, Some(0))];
    assert_eq!(plan(&vmas, BASE), Some(DetachPlan { seg: 0, victims: alloc::vec![0] }));
}

#[test]
fn address_that_is_not_an_attachment_base_is_einval() {
    let vmas = [vma(BASE, BASE + SPAN, 0, Some(0))];
    // Mid-segment: Linux requires the address to be where the attach was
    // PLACED, so a page inside it detaches nothing.
    assert_eq!(plan(&vmas, BASE + PAGE_SIZE), None);
    // A non-shm mapping at exactly the right address is still not an attach.
    let other = [vma(BASE, BASE + SPAN, 0, None)];
    assert_eq!(plan(&other, BASE), None);
    assert_eq!(plan(&[], BASE), None);
}

#[test]
fn partially_unmapped_attachment_detaches_its_surviving_fragments() {
    // shmat at BASE, then the middle page was munmap'd: two fragments remain,
    // the first still anchoring the attach (start-addr == off == 0).
    let vmas = [
        vma(BASE, BASE + PAGE_SIZE, 0, Some(0)),
        vma(BASE + 2 * PAGE_SIZE, BASE + SPAN, 2 * PAGE_SIZE, Some(0)),
    ];
    assert_eq!(plan(&vmas, BASE), Some(DetachPlan { seg: 0, victims: alloc::vec![0, 1] }));
}

#[test]
fn fragment_of_a_different_segment_is_left_alone() {
    // A second segment attached inside the first's span must survive: Linux
    // matches on the backing file, not just on the address arithmetic.
    let vmas = [
        vma(BASE, BASE + PAGE_SIZE, 0, Some(0)),
        vma(BASE + PAGE_SIZE, BASE + 2 * PAGE_SIZE, PAGE_SIZE, Some(1)),
        vma(BASE + 2 * PAGE_SIZE, BASE + SPAN, 2 * PAGE_SIZE, Some(0)),
    ];
    assert_eq!(plan(&vmas, BASE), Some(DetachPlan { seg: 0, victims: alloc::vec![0, 2] }));
}

#[test]
fn sweep_stops_at_the_attachment_extent() {
    // A later same-segment mapping placed beyond the segment span (a second
    // shmat of the same segment) is a DIFFERENT attachment and is not
    // collected by this shmdt.
    let vmas = [
        vma(BASE, BASE + SPAN, 0, Some(0)),
        vma(BASE + SPAN, BASE + 2 * SPAN, SPAN, Some(0)),
    ];
    assert_eq!(plan(&vmas, BASE), Some(DetachPlan { seg: 0, victims: alloc::vec![0] }));
}

#[test]
fn a_relocated_fragment_no_longer_satisfies_the_placement_rule() {
    // mremap moved the tail elsewhere: its offset no longer equals its
    // distance from the base, so Linux does not treat it as part of this
    // attachment.
    let vmas = [
        vma(BASE, BASE + PAGE_SIZE, 0, Some(0)),
        vma(BASE + PAGE_SIZE, BASE + 2 * PAGE_SIZE, 3 * PAGE_SIZE, Some(0)),
    ];
    assert_eq!(plan(&vmas, BASE), Some(DetachPlan { seg: 0, victims: alloc::vec![0] }));
}

fn seg_with(id: i32, nattch: i64, mode: u32) -> Arc<ShmSegment> {
    let owner = crate::ipc_namespace::current().unwrap();
    Arc::new(ShmSegment {
        id, key: 4242, ns: owner.key(), size: SPAN as usize, mode,
        uid: 0, gid: 0, cuid: 0, cgid: 0, cpid: 1,
        nattch: AtomicI64::new(nattch),
        backing: Arc::new(FakeBacking),
    })
}

#[test]
fn detach_drops_the_attach_count_without_destroying_a_live_segment() {
    let _g = TEST_LOCK.lock().unwrap();
    REG.segs.lock().clear();
    let seg = seg_with(901, 2, 0o600);
    REG.segs.lock().push(seg.clone());
    release_detached(&seg);
    assert_eq!(seg.nattch.load(Ordering::Acquire), 1);
    assert!(lookup_by_id(901).is_some(), "a segment without SHM_DEST survives detach");
    release_detached(&seg);
    assert_eq!(seg.nattch.load(Ordering::Acquire), 0);
    assert!(lookup_by_id(901).is_some(), "IPC_RMID, not the last detach, marks a segment for death");
    REG.segs.lock().clear();
}

#[test]
fn last_detach_destroys_a_segment_already_marked_shm_dest() {
    let _g = TEST_LOCK.lock().unwrap();
    REG.segs.lock().clear();
    let seg = seg_with(902, 2, 0o600 | SHM_DEST);
    REG.segs.lock().push(seg.clone());
    release_detached(&seg);
    assert!(lookup_by_id(902).is_some(), "an RMID'd segment lives until its last attach goes");
    release_detached(&seg);
    assert!(lookup_by_id(902).is_none(), "the last detach of an RMID'd segment destroys it");
    assert!(REG.segs.lock().is_empty());
}

#[test]
fn misaligned_address_is_rejected_before_any_lookup() {
    let args = syscall::SyscallArgs { a0: BASE + 1, ..Default::default() };
    assert_eq!(sys_shmdt(&args), -(syscall::errno::Errno::Einval.as_i32() as i64));
}

#[test]
fn backing_identity_distinguishes_distinct_shmem_objects() {
    let a: Arc<dyn vmm::FileBacking> = Arc::new(FakeBacking);
    let b: Arc<dyn vmm::FileBacking> = Arc::new(FakeBacking);
    assert_ne!(backing_addr(&a), backing_addr(&b));
    assert_eq!(backing_addr(&a), backing_addr(&a.clone()));
    let _ = Vec::<u8>::new();
}
