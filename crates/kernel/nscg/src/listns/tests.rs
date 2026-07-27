use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use namespace_identity::{NamespaceKind, NamespaceRef};

use super::*;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7100_0000);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn task(name: &'static str) -> Arc<sched::Task> {
    Arc::new(sched::Task::new(NEXT_TID.fetch_add(1, Ordering::Relaxed), name,
        sched::SchedClass::Normal { weight: 1024 }))
}

fn allocate(kind: NamespaceKind, owner: &NamespaceRef) -> NamespaceRef {
    namespace_identity::allocate(kind, owner.clone(), None).unwrap()
}

fn ids(page: &ListNsPage) -> Vec<u64> {
    (0..page.len()).map(|index| page.id(index).unwrap()).collect()
}

#[test]
fn nsfd_only_dynamic_uts_is_listed_and_retained() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let caller = task("listns-nsfd");
    let owner = allocate(NamespaceKind::Uts,
        &namespace_identity::initial(NamespaceKind::User));
    let id = owner.ns_id().as_u64();
    let weak = NamespaceRef::downgrade(&owner);

    let page = listns_page(&caller, id - 1, CLONE_NEWUTS as u32,
        ListNsOwnerFilter::All, 8).unwrap();
    assert!(ids(&page).contains(&id), "live identity must not require a task attachment");
    drop(owner);
    assert!(weak.upgrade().is_none(), "listns pin must not retain active membership");
    assert!(weak.is_alive(), "page retains exact identity lifetime through copyout");
    assert_eq!(page.id(0), Some(id));
    drop(page);
    assert!(!weak.is_alive());
}

#[test]
fn visibility_is_exact_current_or_init_privileged() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let caller = task("listns-visible");
    let init_user = namespace_identity::initial(NamespaceKind::User);
    let current = allocate(NamespaceKind::Uts, &init_user);
    let foreign = allocate(NamespaceKind::Uts, &init_user);
    let current_id = current.ns_id().as_u64();
    let foreign_id = foreign.ns_id().as_u64();
    assert!(caller.replace_namespace(current.clone()).is_ok());
    caller.creds.cap_effective.store(0, Ordering::Release);

    let page = listns_page(&caller, 0, CLONE_NEWUTS as u32,
        ListNsOwnerFilter::All, usize::MAX).unwrap();
    assert_eq!(ids(&page), [current_id]);
    assert!(!ids(&page).contains(&foreign_id));
}

#[test]
fn owner_filter_uses_direct_children_and_excludes_initial_user_self() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let caller = task("listns-owner");
    let init_user = namespace_identity::initial(NamespaceKind::User);
    let child_user = namespace_identity::allocate(NamespaceKind::User,
        init_user.clone(), Some(init_user.clone())).unwrap();
    let child_uts = allocate(NamespaceKind::Uts, &child_user);

    let init_page = listns_page(&caller, 0, 0,
        ListNsOwnerFilter::NsId(init_user.ns_id().as_u64()), usize::MAX).unwrap();
    assert!(ids(&init_page).contains(&child_user.ns_id().as_u64()));
    assert!(!ids(&init_page).contains(&init_user.ns_id().as_u64()));

    let child_page = listns_page(&caller, 0, 0,
        ListNsOwnerFilter::NsId(child_user.ns_id().as_u64()), usize::MAX).unwrap();
    assert_eq!(ids(&child_page), [child_uts.ns_id().as_u64()]);
}

#[test]
fn invalid_explicit_owner_is_typed() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let caller = task("listns-invalid-owner");
    let uts = allocate(NamespaceKind::Uts,
        &namespace_identity::initial(NamespaceKind::User));
    assert_eq!(listns_page(&caller, 0, 0,
        ListNsOwnerFilter::NsId(uts.ns_id().as_u64()), 1).err(),
        Some(ListNsError::InvalidOwner));
}

#[test]
fn inactive_user_retained_only_by_child_cannot_be_listed_or_owner_filtered() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let caller = task("listns-passive-owner");
    let init_user = namespace_identity::initial(NamespaceKind::User);
    let user = namespace_identity::allocate(NamespaceKind::User,
        init_user.clone(), Some(init_user)).unwrap();
    let user_id = user.ns_id().as_u64();
    let child = allocate(NamespaceKind::Uts, &user);
    let child_pin = child.pin();
    drop(child);
    drop(user);

    let page = listns_page(&caller, 0, 0, ListNsOwnerFilter::All, usize::MAX).unwrap();
    assert!(!ids(&page).contains(&user_id));
    assert_eq!(listns_page(&caller, 0, 0, ListNsOwnerFilter::NsId(user_id), 8).err(),
        Some(ListNsError::InvalidOwner));
    drop(child_pin);
}

#[test]
fn zero_cursor_empty_owner_tree_returns_empty_page() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let caller = task("listns-empty-owner");
    let init_user = namespace_identity::initial(NamespaceKind::User);
    let child_user = namespace_identity::allocate(NamespaceKind::User,
        init_user.clone(), Some(init_user)).unwrap();

    let page = listns_page(&caller, 0, 0,
        ListNsOwnerFilter::NsId(child_user.ns_id().as_u64()), 8).unwrap();
    assert!(page.is_empty());
}

#[test]
fn structural_no_successor_differs_from_filtered_empty_page() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let caller = task("listns-successor");
    caller.creds.cap_effective.store(0, Ordering::Release);
    let foreign = allocate(NamespaceKind::Uts,
        &namespace_identity::initial(NamespaceKind::User));
    let foreign_id = foreign.ns_id().as_u64();

    let empty = listns_page(&caller, NamespaceKind::Uts.initial_ns_id().as_u64(),
        CLONE_NEWUTS as u32, ListNsOwnerFilter::All, 8).unwrap();
    assert!(empty.is_empty(), "invisible structural successors are skipped without error");

    let last = namespace_identity::live_snapshot().into_iter()
        .filter(|owner| owner.kind() == NamespaceKind::Uts)
        .map(|owner| owner.ns_id().as_u64()).max().unwrap();
    assert!(last >= foreign_id);
    assert_eq!(listns_page(&caller, last, CLONE_NEWUTS as u32,
        ListNsOwnerFilter::All, 8).err(), Some(ListNsError::NoSuccessor));
}

#[test]
fn global_page_is_sorted_by_global_namespace_id() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let caller = task("listns-sorted");
    let init_user = namespace_identity::initial(NamespaceKind::User);
    let _uts = allocate(NamespaceKind::Uts, &init_user);
    let _ipc = allocate(NamespaceKind::Ipc, &init_user);

    let page = listns_page(&caller, 0, 0, ListNsOwnerFilter::All, usize::MAX).unwrap();
    let listed = ids(&page);
    assert!(listed.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(page.entry(0).is_some());
}

#[test]
fn maximum_cursor_wraps_to_first_structural_entry() {
    let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let caller = task("listns-cursor-wrap");
    let page = listns_page(&caller, u64::MAX, CLONE_NEWUTS as u32,
        ListNsOwnerFilter::All, 1).unwrap();
    assert_eq!(page.id(0), Some(NamespaceKind::Uts.initial_ns_id().as_u64()));
}
