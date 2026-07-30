use hal::UserVirtAddr;
use alloc::sync::Arc;

use crate::{
    AddressSpace, Error, FileBacking, FileBackingError, FileRmap, MdweRequest,
    MdweSetError, MmapError, MmapPlacement, VmaBacking, VmaFlags, VmaProt,
};

const PAGE: usize = hal::PAGE_SIZE_BYTES as usize;
const ALL: VmaProt = VmaProt::READ.union(VmaProt::WRITE).union(VmaProt::EXEC);

fn va(raw: u64) -> UserVirtAddr { UserVirtAddr::new(raw).expect("test user VA") }
fn private() -> VmaFlags { VmaFlags::PRIVATE | VmaFlags::ANONYMOUS }

struct TestBacking {
    rmap: Arc<FileRmap>,
}

impl FileBacking for TestBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> {
        Ok(0)
    }

    fn size_hint(&self) -> u64 { hal::PAGE_SIZE_BYTES }

    fn file_rmap(&self) -> Option<Arc<FileRmap>> { Some(Arc::clone(&self.rmap)) }
}

#[test]
fn mdwe_set_is_immutable_after_enable_and_exact_repeats_succeed() {
    let mm = AddressSpace::new(0).unwrap();
    assert_eq!(mm.mdwe_get(), MdweRequest::Disabled);
    assert_eq!(mm.mdwe_set(MdweRequest::Disabled), Ok(()));
    assert_eq!(mm.mdwe_set(MdweRequest::RefuseExecGain), Ok(()));
    assert_eq!(mm.mdwe_get(), MdweRequest::RefuseExecGain);
    assert_eq!(mm.mdwe_set(MdweRequest::RefuseExecGain), Ok(()));
    assert_eq!(mm.mdwe_set(MdweRequest::Disabled), Err(MdweSetError::Immutable));
    assert_eq!(
        mm.mdwe_set(MdweRequest::RefuseExecGainNoInherit),
        Err(MdweSetError::Immutable),
    );
}

#[test]
fn mdwe_fork_and_exec_inherit_unless_no_inherit_was_requested() {
    let inherited = AddressSpace::new(0).unwrap();
    inherited.mdwe_set(MdweRequest::RefuseExecGain).unwrap();
    assert_eq!(inherited.fork(0).unwrap().mdwe_get(), MdweRequest::RefuseExecGain);
    assert_eq!(
        AddressSpace::new_for_exec(0, &inherited).unwrap().mdwe_get(),
        MdweRequest::RefuseExecGain,
    );

    let cleared = AddressSpace::new(0).unwrap();
    cleared.mdwe_set(MdweRequest::RefuseExecGainNoInherit).unwrap();
    assert_eq!(cleared.fork(0).unwrap().mdwe_get(), MdweRequest::Disabled);
    assert_eq!(
        AddressSpace::new_for_exec(0, &cleared).unwrap().mdwe_get(),
        MdweRequest::Disabled,
    );
}

#[test]
fn mdwe_new_mapping_policy_matches_linux_map_deny_write_exec() {
    let mm = AddressSpace::new(0).unwrap();
    mm.mdwe_set(MdweRequest::RefuseExecGain).unwrap();

    assert!(mm.mmap(Some(va(0x20_000)), PAGE, VmaProt::READ | VmaProt::EXEC,
                    private(), VmaBacking::Anonymous, true).is_ok());
    assert!(mm.mmap(Some(va(0x22_000)), PAGE, VmaProt::READ | VmaProt::WRITE,
                    private(), VmaBacking::Anonymous, true).is_ok());
    assert_eq!(
        mm.mmap(Some(va(0x24_000)), PAGE, VmaProt::WRITE | VmaProt::EXEC,
                private(), VmaBacking::Anonymous, true),
        Err(Error::Access),
    );
}

#[test]
fn mdwe_mprotect_allows_existing_exec_but_denies_exec_gain_and_write_exec() {
    let mm = AddressSpace::new(0).unwrap();
    let exec = va(0x30_000);
    let writable = va(0x32_000);
    mm.mmap_with_may(Some(exec), PAGE, VmaProt::READ | VmaProt::EXEC, ALL,
                     private(), VmaBacking::Anonymous, true).unwrap();
    mm.mmap_with_may(Some(writable), PAGE, VmaProt::READ | VmaProt::WRITE, ALL,
                     private(), VmaBacking::Anonymous, true).unwrap();
    mm.mdwe_set(MdweRequest::RefuseExecGain).unwrap();

    assert_eq!(mm.mprotect(exec, PAGE, VmaProt::READ | VmaProt::EXEC), Ok(()));
    assert_eq!(
        mm.mprotect(exec, PAGE, VmaProt::READ | VmaProt::WRITE | VmaProt::EXEC),
        Err(Error::Access),
    );
    assert_eq!(mm.mprotect(writable, PAGE, VmaProt::READ | VmaProt::EXEC),
               Err(Error::Access));
    assert_eq!(mm.mprotect(exec, PAGE, VmaProt::READ), Ok(()));
    assert_eq!(mm.mprotect(exec, PAGE, VmaProt::READ | VmaProt::EXEC),
               Err(Error::Access));
}

#[test]
fn mprotect_commits_linux_prefix_and_applies_read_implies_exec_per_vma() {
    let mm = AddressSpace::new(0).unwrap();
    let first = va(0x34_000);
    let second = va(0x35_000);
    mm.mmap_with_may(Some(first), PAGE, VmaProt::EXEC, ALL,
                     private(), VmaBacking::Anonymous, true).unwrap();
    mm.mmap_with_may(Some(second), PAGE, VmaProt::READ | VmaProt::WRITE, ALL,
                     private(), VmaBacking::Anonymous, true).unwrap();
    mm.mdwe_set(MdweRequest::RefuseExecGain).unwrap();

    let partial = mm.mprotect_user(first, 2 * PAGE, VmaProt::READ, true).unwrap();
    assert_eq!(partial.error, Some(Error::Access));
    assert_eq!(partial.steps.len(), 1);
    assert_eq!(partial.steps[0].prot, VmaProt::READ | VmaProt::EXEC);
    assert_eq!(mm.find_vma(first).unwrap().prot, VmaProt::READ | VmaProt::EXEC);
    assert_eq!(mm.find_vma(second).unwrap().prot, VmaProt::READ | VmaProt::WRITE);

    let mixed = AddressSpace::new(0).unwrap();
    mixed.mmap_with_may(Some(first), PAGE, VmaProt::READ | VmaProt::EXEC, ALL,
                        private(), VmaBacking::Anonymous, true).unwrap();
    mixed.mmap_with_may(Some(second), PAGE, VmaProt::READ, VmaProt::READ,
                        private(), VmaBacking::Anonymous, true).unwrap();
    let outcome = mixed.mprotect_user(first, 2 * PAGE, VmaProt::READ, true).unwrap();
    assert_eq!(outcome.error, None);
    assert_eq!(outcome.steps[0].prot, VmaProt::READ | VmaProt::EXEC);
    assert_eq!(outcome.steps[1].prot, VmaProt::READ);
}

#[test]
fn mdwe_precedes_mseal_and_shared_file_write_seal() {
    let mm = AddressSpace::new(0).unwrap();
    let mapped = va(0x38_000);
    mm.mmap_with_may(Some(mapped), PAGE, VmaProt::READ | VmaProt::WRITE, ALL,
                     private(), VmaBacking::Anonymous, true).unwrap();
    mm.mseal_range(mapped, va(mapped.as_u64() + PAGE as u64)).unwrap();
    mm.mdwe_set(MdweRequest::RefuseExecGain).unwrap();
    assert_eq!(
        mm.mprotect(mapped, PAGE, VmaProt::READ | VmaProt::EXEC),
        Err(Error::Access),
    );

    let rmap = FileRmap::new();
    assert_eq!(rmap.commit_write_seal(|| true), Ok(true));
    let backing: Arc<dyn FileBacking> =
        Arc::new(TestBacking { rmap: Arc::clone(&rmap) });
    assert_eq!(
        mm.mmap_with_may_at(
            MmapPlacement::Fixed(va(0x3a_000)), PAGE,
            VmaProt::WRITE | VmaProt::EXEC, ALL, VmaFlags::SHARED,
            VmaBacking::File { backing, off: 0 },
        ),
        Err(MmapError::Vmm(Error::Access)),
    );
}

#[test]
fn denied_fixed_mapping_does_not_remove_the_destination() {
    let mm = AddressSpace::new(0).unwrap();
    let dst = va(0x40_000);
    mm.mmap(Some(dst), PAGE, VmaProt::READ, private(),
            VmaBacking::Anonymous, true).unwrap();
    mm.mdwe_set(MdweRequest::RefuseExecGain).unwrap();

    assert_eq!(
        mm.mmap_with_may_at(
            MmapPlacement::Fixed(dst), PAGE, VmaProt::WRITE | VmaProt::EXEC,
            ALL, private(), VmaBacking::Anonymous,
        ),
        Err(MmapError::Vmm(Error::Access)),
    );
    assert_eq!(mm.find_vma(dst).expect("destination survives").prot, VmaProt::READ);
}

#[test]
fn no_replace_collision_precedes_mdwe_and_admission_is_owner_bound() {
    let mm = AddressSpace::new(0).unwrap();
    let other = AddressSpace::new(0).unwrap();
    let dst = va(0x50_000);
    mm.mmap(Some(dst), PAGE, VmaProt::READ, private(),
            VmaBacking::Anonymous, true).unwrap();
    mm.mdwe_set(MdweRequest::RefuseExecGain).unwrap();
    assert_eq!(
        mm.mmap_with_may_at(
            MmapPlacement::FixedNoReplace(dst), PAGE,
            VmaProt::WRITE | VmaProt::EXEC, ALL, private(),
            VmaBacking::Anonymous,
        ),
        Err(MmapError::Exists),
    );

    let admission = mm.mdwe_admit_new_mapping(VmaProt::READ).unwrap();
    assert_eq!(
        other.mmap_with_may_at_admitted(
            MmapPlacement::Fixed(va(0x52_000)), PAGE, VmaProt::READ, ALL,
            private(), VmaBacking::Anonymous, admission,
        ),
        Err(MmapError::Vmm(Error::Inval)),
    );
}

#[test]
fn mremap_preserves_preexisting_write_exec_permissions_under_mdwe() {
    let mm = AddressSpace::new(0).unwrap();
    let old = va(0x60_000);
    let new = va(0x62_000);
    mm.mmap_with_may(Some(old), PAGE, VmaProt::WRITE | VmaProt::EXEC, ALL,
                     private(), VmaBacking::Anonymous, true).unwrap();
    mm.mdwe_set(MdweRequest::RefuseExecGain).unwrap();

    assert_eq!(
        mm.mremap_full(old, PAGE, PAGE, true, true, false, Some(new)),
        Ok(new),
    );
    assert_eq!(
        mm.find_vma(new).expect("moved VMA").prot,
        VmaProt::WRITE | VmaProt::EXEC,
    );
}
