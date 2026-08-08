use alloc::collections::BTreeMap;
use alloc::sync::Weak;
use core::sync::atomic::{AtomicU32, AtomicU64};
use sync::{Spinlock, TaskList};

use super::super::file::{ShmemPage, TmpfsFileData};

#[test]
fn swapped_index_keeps_immutable_memcg_but_has_no_resident_frame() {
    let cgid = 0x61;
    let resident = ShmemPage::Resident { pa: 0x9000, cgid };
    let entry = hal::pt_walker::SwapEntry::new(1, 7).expect("representable swap entry");
    let swapped = ShmemPage::Swapped { entry, cgid, shadow: 0 };
    assert_eq!(resident.resident_pa(), Some(0x9000));
    assert_eq!(swapped.resident_pa(), None);
    assert_eq!(resident.cgid(), swapped.cgid());
}

fn migrating_fixture(pa: u64, cgid: u64) -> (TmpfsFileData, hal::pt_walker::MigrationEntry) {
    let token = vmm::migration_begin(pa).expect("test migration token");
    let mut pages = BTreeMap::new();
    pages.insert(7, ShmemPage::Migrating { pa, cgid, token });
    (TmpfsFileData {
        self_ref: Spinlock::new(Weak::new()),
        pages: Spinlock::<BTreeMap<u64, ShmemPage>, TaskList>::new(pages),
        len: AtomicU64::new(0), acct: super::super::accounting::TmpfsSb::unlimited(),
        owner: sync::Spinlock::new(Default::default()), inode: sync::Spinlock::new(alloc::sync::Weak::new()),
        seals: AtomicU32::new(0),
    }, token)
}

fn assert_failed_mapped_pageout_restores_resident(force: fn(), invoke_failure: impl FnOnce(hal::pt_walker::MigrationEntry) -> bool) {
    let (data, token) = migrating_fixture(0x70_000, 0x29);
    force();
    assert!(!invoke_failure(token), "test hook must force this transaction failure");
    super::super::reclaim::rollback_mapped_for_test(&data, 7, 0x70_000, 0x29, token);
    assert!(matches!(data.pages.lock().get(&7), Some(ShmemPage::Resident { pa: 0x70_000, cgid: 0x29 })));
    assert!(!vmm::migration_pending_then(token, || {}), "rollback must retire the migration token");
    // Synthetic state owns neither a PMM frame nor a published shmem count.
    core::mem::forget(data);
}

#[test]
fn forced_marker_and_store_failure_restore_the_same_resident_index_and_token() {
    assert_failed_mapped_pageout_restores_resident(
        super::super::reclaim::fail_next_marker_for_test,
        super::super::reclaim::attach_marker_for_test,
    );
    assert_failed_mapped_pageout_restores_resident(
        super::super::reclaim::fail_next_store_for_test,
        |token| super::super::reclaim::store_page_for_test(&[0; 1], token.token()).is_some(),
    );
}
