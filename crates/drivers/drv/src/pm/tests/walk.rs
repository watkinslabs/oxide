// The phase walk's whole contract, exercised without a device model and
// without hardware: order, the four lists, and "a partial suspend resumes
// exactly the devices that suspended".
//
// The failure cases sweep EVERY position in the list, not one. A walker that
// resumes one device too many or too few is correct at the ends and wrong in
// the middle, which is exactly the shape a single-position test misses.

use alloc::rc::Rc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::pm::lists::{PmLists, PmPhase, PmTarget};
use crate::pm::ops::{PmDepth, PmDir, PmTransition};
use crate::{Error, KResult};

const T: PmTransition = PmTransition::Suspend;

type Trace = Rc<RefCell<Vec<String>>>;

struct Fake {
    name: &'static str,
    trace: Trace,
    fail_on: RefCell<Vec<PmPhase>>,
}

fn label(p: PmPhase) -> &'static str {
    match p {
        PmPhase::Prepare => "prep",
        PmPhase::Complete => "comp",
        PmPhase::Depth(PmDepth::Normal, PmDir::Down) => "susp",
        PmPhase::Depth(PmDepth::Normal, PmDir::Up) => "res",
        PmPhase::Depth(PmDepth::LateEarly, PmDir::Down) => "late",
        PmPhase::Depth(PmDepth::LateEarly, PmDir::Up) => "early",
        PmPhase::Depth(PmDepth::Noirq, PmDir::Down) => "nsusp",
        PmPhase::Depth(PmDepth::Noirq, PmDir::Up) => "nres",
    }
}

impl PmTarget for Rc<Fake> {
    fn pm_name(&self) -> &str { self.name }
    fn pm_run(&self, phase: PmPhase, _t: PmTransition) -> KResult<()> {
        let mut s = String::new();
        s.push_str(self.name);
        s.push(':');
        s.push_str(label(phase));
        self.trace.borrow_mut().push(s);
        if self.fail_on.borrow().contains(&phase) { Err(Error::Busy) } else { Ok(()) }
    }
}

struct Fixture { trace: Trace, devs: Vec<Rc<Fake>>, lists: PmLists<Rc<Fake>> }

fn fixture(names: &[&'static str]) -> Fixture {
    let trace: Trace = Rc::new(RefCell::new(Vec::new()));
    let devs: Vec<Rc<Fake>> = names.iter()
        .map(|n| Rc::new(Fake { name: n, trace: trace.clone(), fail_on: RefCell::new(Vec::new()) }))
        .collect();
    let mut lists = PmLists::new();
    lists.seed(devs.clone());
    Fixture { trace, devs, lists }
}

impl Fixture {
    fn took(&self) -> Vec<String> { self.trace.borrow().clone() }
    fn clear(&self) { self.trace.borrow_mut().clear(); }
    fn fail(&self, i: usize, p: PmPhase) { self.devs[i].fail_on.borrow_mut().push(p); }
}

fn names(prefix: &str, list: &[&str]) -> Vec<String> {
    list.iter().map(|n| alloc::format!("{n}:{prefix}")).collect()
}

const ABC: [&str; 3] = ["a", "b", "c"];
const ABCDE: [&str; 5] = ["a", "b", "c", "d", "e"];

// ---- order -------------------------------------------------------------

#[test]
fn prepare_walks_registration_order() {
    let mut f = fixture(&ABC);
    assert!(f.lists.prepare(T).is_ok());
    assert_eq!(f.took(), names("prep", &["a", "b", "c"]));
}

#[test]
fn complete_walks_reverse_registration_order() {
    let mut f = fixture(&ABC);
    assert!(f.lists.prepare(T).is_ok());
    f.clear();
    f.lists.complete(T);
    assert_eq!(f.took(), names("comp", &["c", "b", "a"]));
}

#[test]
fn suspend_walks_reverse_and_resume_walks_forward() {
    let mut f = fixture(&ABC);
    assert!(f.lists.prepare(T).is_ok());
    f.clear();
    assert!(f.lists.suspend(T).is_ok());
    assert_eq!(f.took(), names("susp", &["c", "b", "a"]));
    f.clear();
    f.lists.resume(T);
    assert_eq!(f.took(), names("res", &["a", "b", "c"]));
}

#[test]
fn suspend_late_walks_reverse_and_resume_early_walks_forward() {
    let mut f = fixture(&ABC);
    assert!(f.lists.prepare(T).is_ok());
    assert!(f.lists.suspend(T).is_ok());
    f.clear();
    assert!(f.lists.suspend_late(T).is_ok());
    assert_eq!(f.took(), names("late", &["c", "b", "a"]));
    f.clear();
    f.lists.resume_early(T);
    assert_eq!(f.took(), names("early", &["a", "b", "c"]));
}

#[test]
fn suspend_noirq_walks_reverse_and_resume_noirq_walks_forward() {
    let mut f = fixture(&ABC);
    assert!(f.lists.prepare(T).is_ok());
    assert!(f.lists.suspend(T).is_ok());
    assert!(f.lists.suspend_late(T).is_ok());
    f.clear();
    assert!(f.lists.suspend_noirq(T).is_ok());
    assert_eq!(f.took(), names("nsusp", &["c", "b", "a"]));
    f.clear();
    f.lists.resume_noirq(T);
    assert_eq!(f.took(), names("nres", &["a", "b", "c"]));
}

#[test]
fn a_complete_cycle_returns_the_lists_to_registration_order() {
    let mut f = fixture(&ABCDE);
    assert!(f.lists.prepare(T).is_ok());
    assert!(f.lists.suspend(T).is_ok());
    assert!(f.lists.suspend_late(T).is_ok());
    assert!(f.lists.suspend_noirq(T).is_ok());
    f.lists.resume_noirq(T);
    f.lists.resume_early(T);
    f.lists.resume(T);
    f.lists.complete(T);
    let order: Vec<&str> = f.lists.list.iter().map(|e| e.target.name).collect();
    assert_eq!(order, ABCDE.to_vec());
    assert!(f.lists.prepared.is_empty() && f.lists.suspended.is_empty()
            && f.lists.late_early.is_empty() && f.lists.noirq.is_empty());
}

// ---- partial failure ---------------------------------------------------

/// A suspend walk covers `[n-1, n-2, .., 0]`; a failure at list position `i`
/// means the devices AFTER `i` suspended and must resume, in registration
/// order, and nobody else may.
fn expect_partial(depth: PmDepth, down: &str, up: &str) {
    for i in 0..ABCDE.len() {
        let mut f = fixture(&ABCDE);
        assert!(f.lists.prepare(T).is_ok());
        match depth {
            PmDepth::Normal => {}
            PmDepth::LateEarly => { assert!(f.lists.suspend(T).is_ok()); }
            PmDepth::Noirq => {
                assert!(f.lists.suspend(T).is_ok());
                assert!(f.lists.suspend_late(T).is_ok());
            }
        }
        f.fail(i, PmPhase::Depth(depth, PmDir::Down));
        f.clear();
        let r = match depth {
            PmDepth::Normal => f.lists.suspend(T),
            PmDepth::LateEarly => f.lists.suspend_late(T),
            PmDepth::Noirq => f.lists.suspend_noirq(T),
        };
        assert_eq!(r, Err(Error::Busy), "position {i} must report the refusal");
        assert_eq!(f.lists.failed_device(), Some(ABCDE[i]),
                   "position {i} must record the refusing device");

        // Down leg: from the tail to `i` inclusive, then it stops.
        let mut want: Vec<String> = ABCDE[i..].iter().rev()
            .map(|n| alloc::format!("{n}:{down}")).collect();
        let suspended: Vec<&str> = ABCDE[i + 1..].to_vec();
        if depth != PmDepth::Normal {
            // The late and noirq walks resume their own partial state.
            want.extend(suspended.iter().map(|n| alloc::format!("{n}:{up}")));
        }
        assert_eq!(f.took(), want, "position {i}");

        if depth == PmDepth::Normal {
            // The sequence owns this undo (`32a§5` step 6).
            f.clear();
            f.lists.resume(T);
            assert_eq!(f.took(), names(up, &suspended), "position {i} resume set");
        }

        // Either way, resuming again must not run a second time anywhere.
        f.clear();
        match depth {
            PmDepth::Normal => f.lists.resume(T),
            PmDepth::LateEarly => f.lists.resume_early(T),
            PmDepth::Noirq => f.lists.resume_noirq(T),
        }
        assert!(f.took().is_empty(), "position {i} double-resumed");
    }
}

#[test]
fn a_suspend_failure_at_every_position_resumes_exactly_what_suspended() {
    expect_partial(PmDepth::Normal, "susp", "res");
}

#[test]
fn a_suspend_late_failure_at_every_position_resumes_exactly_what_suspended() {
    expect_partial(PmDepth::LateEarly, "late", "early");
}

#[test]
fn a_suspend_noirq_failure_at_every_position_resumes_exactly_what_suspended() {
    expect_partial(PmDepth::Noirq, "nsusp", "nres");
}

#[test]
fn a_prepare_failure_at_every_position_completes_exactly_what_prepared() {
    for i in 0..ABCDE.len() {
        let mut f = fixture(&ABCDE);
        f.fail(i, PmPhase::Prepare);
        assert_eq!(f.lists.prepare(T), Err(Error::Busy));
        assert_eq!(f.lists.failed_device(), Some(ABCDE[i]));
        assert_eq!(f.took(), names("prep", &ABCDE[..=i]), "position {i}");
        f.clear();
        f.lists.complete(T);
        let mut want: Vec<&str> = ABCDE[..i].to_vec();
        want.reverse();
        assert_eq!(f.took(), names("comp", &want), "position {i} complete set");
    }
}

#[test]
fn a_failed_suspend_still_leaves_every_device_on_one_list() {
    let mut f = fixture(&ABCDE);
    assert!(f.lists.prepare(T).is_ok());
    f.fail(2, PmPhase::Depth(PmDepth::Normal, PmDir::Down));
    assert!(f.lists.suspend(T).is_err());
    assert_eq!(f.lists.prepared.len(), 0);
    assert_eq!(f.lists.suspended.len(), ABCDE.len());
    let order: Vec<&str> = f.lists.suspended.iter().map(|e| e.target.name).collect();
    assert_eq!(order, ABCDE.to_vec(), "the resume walk must see registration order");
    f.lists.resume(T);
    f.lists.complete(T);
    assert!(f.lists.is_idle() || f.lists.list.len() == ABCDE.len());
}

#[test]
fn the_failing_device_name_survives_until_the_next_failure() {
    let mut f = fixture(&ABC);
    assert_eq!(f.lists.failed_device(), None);
    f.fail(1, PmPhase::Prepare);
    assert!(f.lists.prepare(T).is_err());
    assert_eq!(f.lists.failed_device(), Some("b"));
    f.lists.complete(T);
    assert_eq!(f.lists.failed_device(), Some("b"), "complete must not clear the record");
}

#[test]
fn an_empty_device_list_walks_every_phase_without_incident() {
    let mut f = fixture(&[]);
    assert!(f.lists.prepare(T).is_ok());
    assert!(f.lists.suspend(T).is_ok());
    assert!(f.lists.suspend_late(T).is_ok());
    assert!(f.lists.suspend_noirq(T).is_ok());
    f.lists.resume_noirq(T);
    f.lists.resume_early(T);
    f.lists.resume(T);
    f.lists.complete(T);
    assert!(f.took().is_empty());
    assert!(f.lists.is_idle());
}

#[test]
fn reset_returns_every_entry_to_the_registration_list() {
    let mut f = fixture(&ABC);
    assert!(f.lists.prepare(T).is_ok());
    assert!(f.lists.suspend(T).is_ok());
    f.lists.reset();
    assert_eq!(f.lists.list.len(), ABC.len());
    assert!(f.lists.prepared.is_empty() && f.lists.suspended.is_empty());
    assert_eq!(f.lists.failed_device(), None);
}

#[test]
fn a_resume_callback_never_runs_for_a_device_whose_suspend_refused() {
    // The refusing device itself is the one most easily double-counted: its
    // callback ran but did not complete, so it must not be resumed.
    let mut f = fixture(&ABC);
    assert!(f.lists.prepare(T).is_ok());
    f.fail(1, PmPhase::Depth(PmDepth::Normal, PmDir::Down));
    assert!(f.lists.suspend(T).is_err());
    f.clear();
    f.lists.resume(T);
    assert_eq!(f.took(), names("res", &["c"]));
}
