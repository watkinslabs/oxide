// The device PM phase walk: four phase lists and the ordering contract of
// `32a§5` steps 5-11.
//
// Why four lists rather than one list plus a phase counter: a suspend that
// fails partway must resume *exactly* the devices that suspended, and nothing
// else. A device is moved onto the next phase's list before its callback runs
// and carries a flag saying whether that callback actually succeeded; the
// matching resume walk runs the callback only for entries whose flag is set.
// That makes "resumed exactly what suspended" a property of the data, not of a
// control-flow ladder nobody can check.
//
// The move direction is load-bearing. A suspend walk pops the tail of its
// source list and pushes the FRONT of its target, so a reverse walk lands the
// entries back in registration order; the resume walk then reads its list front
// to back and is in registration order for free.
//
// Generic over the target so the whole walk is exercised hosted, with no
// device model and no hardware: `06`-style state machines are tested where the
// decisions live (`53`).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::KResult;
use super::ops::{PmDepth, PmDir, PmTransition};

/// Which walk is running, for a target to select its callback.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PmPhase {
    Prepare,
    Complete,
    /// The three depths of the suspend half, and their resume counterparts.
    Depth(PmDepth, PmDir),
}

/// What the phase walk needs of a device.
pub trait PmTarget {
    /// Name recorded when this target's callback refuses. # C: O(1)
    fn pm_name(&self) -> &str;
    /// Run this target's callback for `phase`; absent callbacks succeed.
    /// # C: driver-defined
    fn pm_run(&self, phase: PmPhase, t: PmTransition) -> KResult<()>;
}

/// One device's place in the walk, with the flags that decide whether its
/// resume callback runs.
pub struct PmEntry<T> {
    pub target: T,
    pub prepared: bool,
    pub suspended: bool,
    pub late_suspended: bool,
    pub noirq_suspended: bool,
}

impl<T> PmEntry<T> {
    /// A freshly-listed device, nothing done to it yet. # C: O(1)
    pub fn new(target: T) -> Self {
        PmEntry { target, prepared: false, suspended: false,
                  late_suspended: false, noirq_suspended: false }
    }
}

/// The four phase lists plus the registration-order list they drain from.
pub struct PmLists<T> {
    /// Registration order; devices not yet prepared.
    pub list: Vec<PmEntry<T>>,
    pub prepared: Vec<PmEntry<T>>,
    pub suspended: Vec<PmEntry<T>>,
    pub late_early: Vec<PmEntry<T>>,
    pub noirq: Vec<PmEntry<T>>,
    failed: Option<String>,
}

impl<T: PmTarget> Default for PmLists<T> {
    fn default() -> Self { Self::new() }
}

impl<T: PmTarget> PmLists<T> {
    /// Empty lists. # C: O(1)
    pub fn new() -> Self {
        PmLists { list: Vec::new(), prepared: Vec::new(), suspended: Vec::new(),
                  late_early: Vec::new(), noirq: Vec::new(), failed: None }
    }

    /// Whether no device is held anywhere, the state between transitions.
    /// # C: O(1)
    pub fn is_idle(&self) -> bool {
        self.list.is_empty() && self.prepared.is_empty() && self.suspended.is_empty()
            && self.late_early.is_empty() && self.noirq.is_empty()
    }

    /// The device whose callback refused most recently, for the statistics
    /// record (`32a§11`). # C: O(1)
    pub fn failed_device(&self) -> Option<&str> { self.failed.as_deref() }

    /// Seed the registration-order list. Callers hand over the canonical
    /// registry snapshot; these lists are per-transition working state, never
    /// a second registry. # C: O(N)
    pub fn seed(&mut self, targets: impl IntoIterator<Item = T>) {
        self.list = targets.into_iter().map(PmEntry::new).collect();
    }

    /// Return every entry to the registration-order list, whatever phase it
    /// reached. Used to abandon a transition whose lists are inconsistent.
    /// # C: O(N)
    pub fn reset(&mut self) {
        let mut all = Vec::new();
        for l in [&mut self.noirq, &mut self.late_early, &mut self.suspended,
                  &mut self.prepared, &mut self.list] {
            all.append(l);
        }
        self.list = all;
        self.failed = None;
    }

    fn note_failure(&mut self, name: &str) { self.failed = Some(name.to_string()); }

    /// Step 5: `prepare` in registration order.
    ///
    /// A refusing device stays on the registration list and is not prepared,
    /// so the matching `complete` walk cannot reach it.
    /// # C: O(N)
    pub fn prepare(&mut self, t: PmTransition) -> KResult<()> {
        while !self.list.is_empty() {
            let mut e = self.list.remove(0);
            match e.target.pm_run(PmPhase::Prepare, t) {
                Ok(()) => { e.prepared = true; self.prepared.push(e); }
                Err(err) => {
                    let name = e.target.pm_name().to_string();
                    self.list.insert(0, e);
                    self.note_failure(&name);
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    /// Undo of step 5: `complete` in reverse, then the registration list is
    /// whole again and in registration order.
    /// # C: O(N)
    pub fn complete(&mut self, t: PmTransition) {
        let mut back = Vec::new();
        while let Some(mut e) = self.prepared.pop() {
            if e.prepared { let _ = e.target.pm_run(PmPhase::Complete, t); }
            e.prepared = false;
            back.insert(0, e);
        }
        back.append(&mut self.list);
        self.list = back;
    }

    /// One suspend-side depth: drain `src` from the tail, push the head of
    /// `dst`, and record success per entry.
    ///
    /// On refusal the untouched remainder of `src` moves across too, so every
    /// device is on the resume walk's list and the per-entry flag — not the
    /// list membership — decides who gets a callback.
    fn suspend_depth(&mut self, depth: PmDepth, t: PmTransition) -> KResult<()> {
        let (src, dst) = Self::pair(depth);
        loop {
            let Some(mut e) = self.lists_mut(src).pop() else { return Ok(()) };
            let r = e.target.pm_run(PmPhase::Depth(depth, PmDir::Down), t);
            let name = if r.is_err() { Some(e.target.pm_name().to_string()) } else { None };
            if r.is_ok() { Self::set_flag(&mut e, depth, true); }
            self.lists_mut(dst).insert(0, e);
            if let Some(name) = name {
                let mut rest: Vec<PmEntry<T>> = core::mem::take(self.lists_mut(src));
                rest.append(self.lists_mut(dst));
                *self.lists_mut(dst) = rest;
                self.note_failure(&name);
                return Err(r.unwrap_err());
            }
        }
    }

    /// One resume-side depth: drain `dst` from the head back into `src`,
    /// running the callback only where the suspend-side flag is set.
    fn resume_depth(&mut self, depth: PmDepth, t: PmTransition) {
        let (src, dst) = Self::pair(depth);
        loop {
            let l = self.lists_mut(dst);
            if l.is_empty() { return; }
            let mut e = l.remove(0);
            if Self::flag(&e, depth) {
                Self::set_flag(&mut e, depth, false);
                let _ = e.target.pm_run(PmPhase::Depth(depth, PmDir::Up), t);
            }
            self.lists_mut(src).push(e);
        }
    }

    /// Step 6: `suspend`, reverse registration order. # C: O(N)
    pub fn suspend(&mut self, t: PmTransition) -> KResult<()> {
        self.suspend_depth(PmDepth::Normal, t)
    }
    /// Step 8: `suspend_late`, reverse. Resumes its own partial state before
    /// reporting failure, which is what `32a§5`'s unwind table assumes.
    /// # C: O(N)
    pub fn suspend_late(&mut self, t: PmTransition) -> KResult<()> {
        let r = self.suspend_depth(PmDepth::LateEarly, t);
        if r.is_err() { self.resume_depth(PmDepth::LateEarly, t); }
        r
    }
    /// Step 10: `suspend_noirq`, reverse. Resumes its own partial state before
    /// reporting failure.
    /// # C: O(N)
    /// # Ctx: IRQ-off
    pub fn suspend_noirq(&mut self, t: PmTransition) -> KResult<()> {
        let r = self.suspend_depth(PmDepth::Noirq, t);
        if r.is_err() { self.resume_depth(PmDepth::Noirq, t); }
        r
    }
    /// Undo of step 10: `resume_noirq`, registration order.
    /// # C: O(N)
    /// # Ctx: IRQ-off
    pub fn resume_noirq(&mut self, t: PmTransition) { self.resume_depth(PmDepth::Noirq, t); }
    /// Undo of step 8: `resume_early`, registration order. # C: O(N)
    pub fn resume_early(&mut self, t: PmTransition) { self.resume_depth(PmDepth::LateEarly, t); }
    /// Undo of step 6: `resume`, registration order. # C: O(N)
    pub fn resume(&mut self, t: PmTransition) { self.resume_depth(PmDepth::Normal, t); }

    /// Source and target list for a depth's suspend walk.
    fn pair(depth: PmDepth) -> (ListId, ListId) {
        match depth {
            PmDepth::Normal    => (ListId::Prepared, ListId::Suspended),
            PmDepth::LateEarly => (ListId::Suspended, ListId::LateEarly),
            PmDepth::Noirq     => (ListId::LateEarly, ListId::Noirq),
        }
    }

    fn lists_mut(&mut self, id: ListId) -> &mut Vec<PmEntry<T>> {
        match id {
            ListId::Prepared  => &mut self.prepared,
            ListId::Suspended => &mut self.suspended,
            ListId::LateEarly => &mut self.late_early,
            ListId::Noirq     => &mut self.noirq,
        }
    }

    fn flag(e: &PmEntry<T>, depth: PmDepth) -> bool {
        match depth {
            PmDepth::Normal    => e.suspended,
            PmDepth::LateEarly => e.late_suspended,
            PmDepth::Noirq     => e.noirq_suspended,
        }
    }

    fn set_flag(e: &mut PmEntry<T>, depth: PmDepth, v: bool) {
        match depth {
            PmDepth::Normal    => e.suspended = v,
            PmDepth::LateEarly => e.late_suspended = v,
            PmDepth::Noirq     => e.noirq_suspended = v,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ListId { Prepared, Suspended, LateEarly, Noirq }
