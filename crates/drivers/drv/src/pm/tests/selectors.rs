// Every member of a driver's table is reachable from exactly one
// (depth, transition, direction) triple, and no two triples select the same
// member. A selector that returns the wrong member is invisible at runtime —
// the device suspends, just through the hibernation callback — so the pairing
// is pinned here by function-pointer identity.

use alloc::vec::Vec;

use crate::model::Device;
use crate::pm::ops::*;
use crate::KResult;

macro_rules! stub { ($n:ident) => { fn $n(_d: &Device) -> KResult<()> { Ok(()) } }; }
stub!(f_suspend); stub!(f_resume); stub!(f_freeze); stub!(f_thaw);
stub!(f_poweroff); stub!(f_restore);
stub!(f_suspend_late); stub!(f_resume_early); stub!(f_freeze_late);
stub!(f_thaw_early); stub!(f_poweroff_late); stub!(f_restore_early);
stub!(f_suspend_noirq); stub!(f_resume_noirq); stub!(f_freeze_noirq);
stub!(f_thaw_noirq); stub!(f_poweroff_noirq); stub!(f_restore_noirq);
stub!(f_prepare);
fn f_complete(_d: &Device) {}

static FULL: DevPmOps = DevPmOps {
    prepare: Some(f_prepare), complete: Some(f_complete),
    suspend: Some(f_suspend), resume: Some(f_resume),
    freeze: Some(f_freeze), thaw: Some(f_thaw),
    poweroff: Some(f_poweroff), restore: Some(f_restore),
    suspend_late: Some(f_suspend_late), resume_early: Some(f_resume_early),
    freeze_late: Some(f_freeze_late), thaw_early: Some(f_thaw_early),
    poweroff_late: Some(f_poweroff_late), restore_early: Some(f_restore_early),
    suspend_noirq: Some(f_suspend_noirq), resume_noirq: Some(f_resume_noirq),
    freeze_noirq: Some(f_freeze_noirq), thaw_noirq: Some(f_thaw_noirq),
    poweroff_noirq: Some(f_poweroff_noirq), restore_noirq: Some(f_restore_noirq),
};

fn same(a: Option<PmFn>, b: PmFn) -> bool { a.map(|f| f as usize) == Some(b as usize) }

#[test]
fn each_transition_selects_its_own_depth_one_pair() {
    use PmTransition::*;
    assert!(same(pm_op(&FULL, Suspend,   PmDir::Down), f_suspend));
    assert!(same(pm_op(&FULL, Suspend,   PmDir::Up),   f_resume));
    assert!(same(pm_op(&FULL, Freeze,    PmDir::Down), f_freeze));
    assert!(same(pm_op(&FULL, Freeze,    PmDir::Up),   f_thaw));
    assert!(same(pm_op(&FULL, Hibernate, PmDir::Down), f_poweroff));
    assert!(same(pm_op(&FULL, Hibernate, PmDir::Up),   f_restore));
}

#[test]
fn each_transition_selects_its_own_late_early_pair() {
    use PmTransition::*;
    assert!(same(pm_late_early_op(&FULL, Suspend,   PmDir::Down), f_suspend_late));
    assert!(same(pm_late_early_op(&FULL, Suspend,   PmDir::Up),   f_resume_early));
    assert!(same(pm_late_early_op(&FULL, Freeze,    PmDir::Down), f_freeze_late));
    assert!(same(pm_late_early_op(&FULL, Freeze,    PmDir::Up),   f_thaw_early));
    assert!(same(pm_late_early_op(&FULL, Hibernate, PmDir::Down), f_poweroff_late));
    assert!(same(pm_late_early_op(&FULL, Hibernate, PmDir::Up),   f_restore_early));
}

#[test]
fn each_transition_selects_its_own_noirq_pair() {
    use PmTransition::*;
    assert!(same(pm_noirq_op(&FULL, Suspend,   PmDir::Down), f_suspend_noirq));
    assert!(same(pm_noirq_op(&FULL, Suspend,   PmDir::Up),   f_resume_noirq));
    assert!(same(pm_noirq_op(&FULL, Freeze,    PmDir::Down), f_freeze_noirq));
    assert!(same(pm_noirq_op(&FULL, Freeze,    PmDir::Up),   f_thaw_noirq));
    assert!(same(pm_noirq_op(&FULL, Hibernate, PmDir::Down), f_poweroff_noirq));
    assert!(same(pm_noirq_op(&FULL, Hibernate, PmDir::Up),   f_restore_noirq));
}

#[test]
fn the_eighteen_phase_members_are_selected_exactly_once_each() {
    let mut seen: Vec<usize> = Vec::new();
    for t in [PmTransition::Suspend, PmTransition::Freeze, PmTransition::Hibernate] {
        for d in [PmDir::Down, PmDir::Up] {
            for depth in [PmDepth::Normal, PmDepth::LateEarly, PmDepth::Noirq] {
                let f = pm_op_at(&FULL, depth, t, d).expect("every member is present");
                seen.push(f as usize);
            }
        }
    }
    assert_eq!(seen.len(), 18, "eighteen triples");
    let mut sorted = seen.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 18, "two triples select the same callback");
}

#[test]
fn pm_op_at_agrees_with_the_per_depth_selectors() {
    for t in [PmTransition::Suspend, PmTransition::Freeze, PmTransition::Hibernate] {
        for d in [PmDir::Down, PmDir::Up] {
            assert_eq!(pm_op_at(&FULL, PmDepth::Normal, t, d).map(|f| f as usize),
                       pm_op(&FULL, t, d).map(|f| f as usize));
            assert_eq!(pm_op_at(&FULL, PmDepth::LateEarly, t, d).map(|f| f as usize),
                       pm_late_early_op(&FULL, t, d).map(|f| f as usize));
            assert_eq!(pm_op_at(&FULL, PmDepth::Noirq, t, d).map(|f| f as usize),
                       pm_noirq_op(&FULL, t, d).map(|f| f as usize));
        }
    }
}

#[test]
fn an_empty_table_selects_nothing_at_any_depth() {
    static NONE: DevPmOps = DevPmOps::none();
    for t in [PmTransition::Suspend, PmTransition::Freeze, PmTransition::Hibernate] {
        for d in [PmDir::Down, PmDir::Up] {
            for depth in [PmDepth::Normal, PmDepth::LateEarly, PmDepth::Noirq] {
                assert!(pm_op_at(&NONE, depth, t, d).is_none());
            }
        }
    }
    assert!(NONE.prepare.is_none());
    assert!(NONE.complete.is_none());
}
