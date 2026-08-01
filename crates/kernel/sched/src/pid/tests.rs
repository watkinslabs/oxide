// Per-namespace numbering contract: a PID identity carries a DISTINCT number
// in every namespace of its chain, a namespace that is not an ancestor numbers
// it not at all, and every number an identity took returns to its namespace.

use alloc::sync::Arc;
use alloc::vec::Vec;

use namespace_identity::{allocate, initial, NamespaceKind, NamespaceRef};

use super::{PidIdentity, PidMappingError};

extern crate std;

fn nested(parent: &NamespaceRef) -> NamespaceRef {
    allocate(NamespaceKind::Pid, initial(NamespaceKind::User), Some(parent.clone())).unwrap()
}

/// `initial -> mid -> inner`, the three-level nest every case below numbers in.
fn three_level() -> (NamespaceRef, NamespaceRef, NamespaceRef) {
    let root = initial(NamespaceKind::Pid);
    let mid = nested(&root);
    let inner = nested(&mid);
    (root, mid, inner)
}

fn identity(tid: u32) -> Arc<PidIdentity> { Arc::new(PidIdentity::new(tid)) }

#[test]
fn each_level_numbers_the_identity_separately() {
    let (root, mid, inner) = three_level();
    let pid = identity(1);
    let numbers: Vec<u32> = pid.alloc_mappings(&inner, &[]).unwrap().into_vec();
    assert_eq!(numbers.len(), 3);
    // A namespace's first task is its init: number 1, in both fresh namespaces.
    assert_eq!(numbers[0], 1);
    assert_eq!(numbers[1], 1);
    // The initial namespace has already numbered its own init, so the outermost
    // number is a different one drawn from that namespace.
    assert!(numbers[2] > 1);
    assert_eq!(pid.nr_in(&inner), numbers[0]);
    assert_eq!(pid.nr_in(&mid), numbers[1]);
    assert_eq!(pid.nr_in(&root), numbers[2]);
    assert_ne!(pid.nr_in(&mid), pid.nr_in(&root));
}

#[test]
fn second_task_of_a_namespace_gets_the_next_number() {
    let (_root, _mid, inner) = three_level();
    let first = identity(1);
    let second = identity(2);
    first.alloc_mappings(&inner, &[]).unwrap();
    let numbers: Vec<u32> = second.alloc_mappings(&inner, &[]).unwrap().into_vec();
    assert_eq!(numbers[0], 2);
    assert_eq!(numbers[1], 2);
}

#[test]
fn a_namespace_that_is_not_an_ancestor_numbers_nothing() {
    let (root, mid, inner) = three_level();
    let sibling = nested(&mid);
    let deeper = nested(&inner);
    let pid = identity(1);
    pid.alloc_mappings(&inner, &[]).unwrap();
    assert_eq!(pid.nr_in(&sibling), 0);
    assert_eq!(pid.nr_in(&deeper), 0);
    assert_eq!(pid.visible_tid(&sibling), None);
    assert!(pid.nr_in(&root) != 0 && pid.nr_in(&mid) != 0);
}

#[test]
fn an_intermediate_reader_sees_the_intermediate_number() {
    let (root, mid, inner) = three_level();
    let pid = identity(1);
    let numbers: Vec<u32> = pid.alloc_mappings(&inner, &[]).unwrap().into_vec();
    let seen_from_mid = pid.nr_in(&mid);
    assert_eq!(seen_from_mid, numbers[1]);
    assert_ne!(seen_from_mid, pid.nr_in(&root));
    assert_ne!(seen_from_mid, numbers[2]);
}

#[test]
fn chain_from_a_reader_runs_outermost_visible_to_own() {
    let (root, mid, inner) = three_level();
    let pid = identity(1);
    let numbers: Vec<u32> = pid.alloc_mappings(&inner, &[]).unwrap().into_vec();
    assert_eq!(pid.nr_chain_from(&root), alloc::vec![numbers[2], numbers[1], numbers[0]]);
    assert_eq!(pid.nr_chain_from(&mid), alloc::vec![numbers[1], numbers[0]]);
    assert_eq!(pid.nr_chain_from(&inner), alloc::vec![numbers[0]]);
    assert!(pid.nr_chain_from(&nested(&inner)).is_empty());
}

#[test]
fn named_numbers_are_taken_innermost_first() {
    let (root, mid, inner) = three_level();
    let pid = identity(1);
    let numbers: Vec<u32> = pid.alloc_mappings(&inner, &[7, 9]).unwrap().into_vec();
    assert_eq!(numbers[0], 7);
    assert_eq!(numbers[1], 9);
    assert_eq!(pid.nr_in(&inner), 7);
    assert_eq!(pid.nr_in(&mid), 9);
    assert!(pid.nr_in(&root) != 0);
}

#[test]
fn a_taken_number_at_an_outer_level_unwinds_every_inner_level() {
    let (_root, mid, inner) = three_level();
    let held = identity(1);
    held.alloc_mappings(&mid, &[9]).unwrap();
    let pid = identity(2);
    assert_eq!(pid.alloc_mappings(&inner, &[7, 9]), Err(PidMappingError::Exists));
    // The inner number the failed attempt took must be back in its namespace.
    assert!(!inner.pid_numbers().is_held(7));
    assert!(!pid.mappings_configured());
    assert_eq!(pid.nr_in(&inner), 0);
    // A retry that avoids the conflict succeeds and gets the released number.
    let numbers: Vec<u32> = pid.alloc_mappings(&inner, &[7, 10]).unwrap().into_vec();
    assert_eq!(numbers[0], 7);
}

#[test]
fn an_exhausted_namespace_unwinds_and_reports_exhaustion() {
    let (_root, mid, inner) = three_level();
    // Two numbers fit: 1 and 2. Give both to other identities so the third
    // allocation must fail at the OUTER level, after the inner one succeeded.
    mid.pid_numbers().set_max(3).unwrap();
    let a = identity(1);
    let b = identity(2);
    a.alloc_mappings(&mid, &[]).unwrap();
    b.alloc_mappings(&mid, &[]).unwrap();
    let pid = identity(3);
    assert_eq!(pid.alloc_mappings(&inner, &[]), Err(PidMappingError::Exhausted));
    assert_eq!(inner.pid_numbers().held(), 0);
    assert_eq!(mid.pid_numbers().held(), 2);
}

#[test]
fn dropping_an_identity_returns_every_number_it_took() {
    let (_root, mid, inner) = three_level();
    let pid = identity(1);
    let numbers: Vec<u32> = pid.alloc_mappings(&inner, &[]).unwrap().into_vec();
    assert!(inner.pid_numbers().is_held(numbers[0]));
    assert!(mid.pid_numbers().is_held(numbers[1]));
    drop(pid);
    assert!(!inner.pid_numbers().is_held(numbers[0]));
    assert!(!mid.pid_numbers().is_held(numbers[1]));
}

#[test]
fn a_freed_number_is_reissued_once_the_namespace_cycles() {
    let (_root, _mid, inner) = three_level();
    inner.pid_numbers().set_max(3).unwrap();
    let first = identity(1);
    assert_eq!(first.alloc_mappings(&inner, &[]).unwrap()[0], 1);
    let second = identity(2);
    assert_eq!(second.alloc_mappings(&inner, &[]).unwrap()[0], 2);
    drop(first);
    // Numbers run 1..max, so the cursor wraps and reissues the freed number.
    let third = identity(3);
    assert_eq!(third.alloc_mappings(&inner, &[]).unwrap()[0], 1);
}

#[test]
fn recorded_numbers_are_claimed_so_the_allocator_skips_them() {
    let (_root, mid, inner) = three_level();
    let stamped = identity(1);
    stamped.configure_mappings(&inner, &[4, 4, 4]).unwrap();
    assert!(inner.pid_numbers().is_held(4));
    assert!(mid.pid_numbers().is_held(4));
    let pid = identity(2);
    for _ in 0..4 {
        let numbers: Vec<u32> = pid.alloc_mappings(&inner, &[]).unwrap().into_vec();
        assert_ne!(numbers[0], 4);
        assert_ne!(numbers[1], 4);
        break;
    }
    assert_eq!(stamped.nr_in(&mid), 4);
}

#[test]
fn recorded_numbers_must_name_every_level() {
    let (_root, _mid, inner) = three_level();
    let pid = identity(1);
    assert_eq!(pid.configure_mappings(&inner, &[1, 2]), Err(PidMappingError::Ancestry));
    assert_eq!(pid.configure_mappings(&inner, &[]), Err(PidMappingError::Empty));
    assert_eq!(pid.configure_mappings(&inner, &[1, 0, 3]),
        Err(PidMappingError::InvalidNumber));
}

#[test]
fn numbering_publishes_once() {
    let (_root, _mid, inner) = three_level();
    let pid = identity(1);
    pid.alloc_mappings(&inner, &[]).unwrap();
    assert_eq!(pid.alloc_mappings(&inner, &[]), Err(PidMappingError::AlreadyConfigured));
    assert_eq!(pid.depth(), 3);
}

#[test]
fn more_named_numbers_than_levels_is_rejected() {
    let root = initial(NamespaceKind::Pid);
    let pid = identity(1);
    assert_eq!(pid.alloc_mappings(&root, &[5, 6]), Err(PidMappingError::InvalidNumber));
    assert!(!root.pid_numbers().is_held(5));
}
