//! The out-of-memory victim decision, as pure data.
//
// ONE scan and ONE policy. The global entry and the control-group entry both
// build a candidate list and hand it here; neither owns a second copy of the
// rules, so a change to the ordering cannot apply to one scope and not the
// other.
//
// Ungated on purpose: this is the decision, and it is `cargo test -p sched`
// provable without a runqueue, a registry or an address space. The candidate
// CONSTRUCTION (which touches live tasks) is in `kill.rs`; only the choice
// lives here.
//
// Rule order matters and is the reference's own:
//
//   1. A never-killable process (the protected init task, a kernel thread) is
//      skipped outright. It cannot be chosen and it cannot abort the scan —
//      init being marked a victim must not stop the machine choosing one.
//   2. A process already marked a victim by an earlier event ABORTS the scan.
//      It has been sent its fatal signal and has not finished exiting; the
//      memory it is about to release is the memory this pass would look for.
//      Choosing a second victim here is how one pressure spike turns into
//      every process on the box being killed.
//   3. Only then is the score consulted. A process with no user memory to
//      release, or one pinned by the minimum score adjustment, is skipped.
//   4. Highest score wins. Equal scores resolve to the later candidate, which
//      keeps the scan a single forward pass with no tie-break policy of its
//      own.
//
// Rule 2 outranking rule 3 is deliberate: a task pinned at the minimum
// adjustment that is nevertheless already a victim (it was killed by scope
// that ignores the pin, or by something other than this path) still aborts the
// scan, because the thing that matters is that memory is on its way back.

/// One process as the selector sees it. Every field is a fact the caller
/// established about a live task; this module applies no policy to gather them.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Candidate {
    /// The protected init task or a kernel thread: skipped, never aborts.
    pub unkillable: bool,
    /// Marked by an earlier out-of-memory event and not yet gone.
    pub already_victim: bool,
    /// Badness in PSS fixed-point units, or `None` for a process that cannot
    /// be scored at all — no user mm left, or pinned at the minimum score
    /// adjustment.
    pub badness: Option<i128>,
}

/// The outcome of one scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selection {
    /// Index of the chosen candidate.
    Victim(usize),
    /// A previous victim is still exiting; kill nothing and let it finish.
    InProgress,
    /// Nothing in this scope may be killed.
    None,
}

/// Apply the rules above to one candidate list.
/// # C: O(N)
pub fn select_victim<I: IntoIterator<Item = Candidate>>(candidates: I) -> Selection {
    let mut chosen: Option<(usize, i128)> = None;
    for (index, candidate) in candidates.into_iter().enumerate() {
        if candidate.unkillable { continue; }
        if candidate.already_victim { return Selection::InProgress; }
        let Some(points) = candidate.badness else { continue; };
        if chosen.is_some_and(|(_, best)| points < best) { continue; }
        chosen = Some((index, points));
    }
    match chosen { Some((index, _)) => Selection::Victim(index), None => Selection::None }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scored(points: i128) -> Candidate { Candidate { badness: Some(points), ..Candidate::default() } }
    fn unscorable() -> Candidate { Candidate::default() }
    fn protected(points: i128) -> Candidate { Candidate { unkillable: true, badness: Some(points), ..Candidate::default() } }
    fn victim(points: i128) -> Candidate { Candidate { already_victim: true, badness: Some(points), ..Candidate::default() } }

    #[test]
    fn the_highest_score_is_the_one_chosen() {
        assert_eq!(select_victim([scored(10), scored(900), scored(30)]), Selection::Victim(1));
        // ... and position carries no weight of its own, in either direction.
        assert_eq!(select_victim([scored(900), scored(10), scored(30)]), Selection::Victim(0));
        assert_eq!(select_victim([scored(10), scored(30), scored(900)]), Selection::Victim(2));
    }

    #[test]
    fn a_negative_adjustment_can_lose_to_a_smaller_process() {
        // The adjustment is folded into the score by the caller, so a large
        // process biased downwards must be beaten by a small unbiased one.
        assert_eq!(select_victim([scored(-500), scored(1)]), Selection::Victim(1));
    }

    #[test]
    fn a_protected_process_is_never_chosen_however_large_it_is() {
        assert_eq!(select_victim([protected(i128::MAX), scored(1)]), Selection::Victim(1));
        // Alone, it leaves the scope with nothing to kill rather than being
        // chosen as a last resort.
        assert_eq!(select_victim([protected(i128::MAX)]), Selection::None);
    }

    #[test]
    fn a_protected_process_that_is_already_a_victim_does_not_abort_the_scan() {
        // Rule 1 before rule 2: init carrying the mark must not stop the
        // machine from choosing someone it may actually kill.
        let init = Candidate { unkillable: true, already_victim: true, badness: Some(i128::MAX) };
        assert_eq!(select_victim([init, scored(5)]), Selection::Victim(1));
    }

    #[test]
    fn an_existing_victim_stops_a_second_process_being_chosen() {
        assert_eq!(select_victim([scored(10), victim(1), scored(900)]), Selection::InProgress);
        // Whatever its own score, and wherever it sits in the scan.
        assert_eq!(select_victim([victim(0), scored(900)]), Selection::InProgress);
        assert_eq!(select_victim([scored(900), victim(0)]), Selection::InProgress);
    }

    #[test]
    fn an_unscorable_victim_still_aborts_the_scan() {
        // The mark is checked before the score, so a process that has already
        // dropped its mm on the way out still buys the machine time.
        let dying = Candidate { unkillable: false, already_victim: true, badness: None };
        assert_eq!(select_victim([dying, scored(900)]), Selection::InProgress);
    }

    #[test]
    fn a_process_with_nothing_to_release_is_skipped_not_chosen() {
        assert_eq!(select_victim([unscorable(), scored(1)]), Selection::Victim(1));
        assert_eq!(select_victim([unscorable(), unscorable()]), Selection::None);
    }

    #[test]
    fn an_empty_scope_selects_nobody() {
        assert_eq!(select_victim([]), Selection::None);
    }

    #[test]
    fn a_zero_scored_process_is_still_a_candidate() {
        // Zero badness is a real score — a process holding no resident pages
        // is choosable, unlike one that cannot be scored at all.
        assert_eq!(select_victim([scored(0)]), Selection::Victim(0));
    }

    #[test]
    fn equal_scores_resolve_without_rescanning() {
        assert_eq!(select_victim([scored(7), scored(7)]), Selection::Victim(1));
    }

    #[test]
    fn a_second_pass_after_a_kill_terminates_instead_of_choosing_again() {
        // The termination argument for the fault path, in miniature: pass one
        // picks a victim, the caller marks it, pass two over the SAME scope
        // reports the kill already in progress and picks nobody. The loop is
        // therefore bounded by one kill per victim, not by one per re-fault.
        let mut scope = [scored(10), scored(900)];
        let Selection::Victim(index) = select_victim(scope) else { panic!("first pass must choose") };
        scope[index].already_victim = true;
        for _ in 0..8 { assert_eq!(select_victim(scope), Selection::InProgress); }
        // And once the victim is gone from the scope, selection resumes.
        let survivors = [scope[1 - index]];
        assert_eq!(select_victim(survivors), Selection::Victim(0));
    }
}
