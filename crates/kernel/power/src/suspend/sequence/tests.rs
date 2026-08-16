use super::*;

#[test]
fn deep_forward_order_is_the_spec_table() {
    let want = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let got: [u8; 16] = core::array::from_fn(|i| DEEP_STEPS[i] as u8);
    assert_eq!(got, want);
}

#[test]
fn freeze_stops_before_the_cpu_and_platform_steps() {
    let steps = forward_steps(SuspendState::ToIdle);
    assert_eq!(steps.last(), Some(&Step::S2idleLoop));
    for bad in [Step::CpusOff, Step::IrqsOff, Step::SyscoreSuspend, Step::PlatformEnter] {
        assert!(!steps.contains(&bad), "{bad:?} reachable from freeze");
    }
    // The prefix up to the noirq platform hook is shared with the deep states.
    assert_eq!(&steps[..12], &DEEP_STEPS[..12]);
}

#[test]
fn deep_states_share_one_step_list() {
    assert_eq!(forward_steps(SuspendState::Mem), &DEEP_STEPS);
    assert_eq!(forward_steps(SuspendState::Standby), &DEEP_STEPS);
}

#[test]
fn the_unwind_is_the_forward_order_reversed() {
    // Every undo in UNWIND_ORDER pairs with a forward step, and the pairing
    // order is strictly decreasing in the forward numbering. That is what
    // "runs in exactly reverse order" means, checked rather than asserted.
    let mut previous: Option<u8> = None;
    for u in UNWIND_ORDER {
        let step = undo_pairs_with(u).expect("undo with no forward step");
        let n = step as u8;
        if let Some(p) = previous { assert!(n < p, "{u:?} out of reverse order"); }
        previous = Some(n);
    }
}

#[test]
fn every_undoable_forward_step_has_exactly_one_undo() {
    for step in DEEP_STEPS {
        // The sync, the platform enter, and the kernel-thread freeze have no
        // undo at this layer; every other step must have exactly one.
        let expected =
            !matches!(step, Step::Sync | Step::PlatformEnter | Step::FreezeKernelThreads);
        let found = UNWIND_ORDER.iter().filter(|u| undo_pairs_with(**u) == Some(step)).count();
        assert_eq!(found, usize::from(expected), "{step:?} has {found} undos");
    }
}

#[test]
fn a_completed_cycle_unwinds_everything() {
    assert_eq!(unwind_from(Step::PlatformEnter), &UNWIND_ORDER[..]);
    assert_eq!(unwind_from(Step::S2idleLoop).len(), 10);
}

#[test]
fn a_failure_undoes_a_suffix_of_the_unwind_and_never_a_gap() {
    for step in DEEP_STEPS.iter().chain(IDLE_STEPS.iter()) {
        let got = unwind_from(*step);
        if got.is_empty() { continue; }
        let start = UNWIND_ORDER.len() - got.len();
        assert_eq!(got, &UNWIND_ORDER[start..], "{step:?} unwind is not a suffix");
    }
}

#[test]
fn a_deeper_failure_never_undoes_less_than_a_shallower_one() {
    // Monotonicity: the further the sequence got, the more there is to undo.
    let mut previous = 0usize;
    for step in DEEP_STEPS {
        let n = unwind_from(step).len();
        if matches!(step, Step::Sync | Step::FreezeUser | Step::FreezeKernelThreads) {
            assert_eq!(n, 0, "{step:?} unwinds at this layer");
            continue;
        }
        assert!(n >= previous, "{step:?} undoes {n}, less than the step before ({previous})");
        previous = n;
    }
}

#[test]
fn the_freezer_unwinds_below_this_layer() {
    assert!(unwind_from(Step::Sync).is_empty());
    assert!(unwind_from(Step::FreezeUser).is_empty());
    assert!(unwind_from(Step::FreezeKernelThreads).is_empty());
}

#[test]
fn a_failing_platform_hook_runs_its_own_undo() {
    assert_eq!(unwind_from(Step::PlatformPrepare)[0], Undo::PlatformFinish);
    assert_eq!(unwind_from(Step::PlatformPrepareNoirq)[0], Undo::PlatformWake);
}

#[test]
fn a_failing_device_phase_does_not_run_its_own_undo() {
    // The device core has already resumed what it suspended; repeating the
    // resume here would resume every device twice.
    assert!(!unwind_from(Step::DevSuspendNoirq).contains(&Undo::DevResumeNoirq));
    assert!(!unwind_from(Step::DevSuspendLate).contains(&Undo::DevResumeEarly));
    // ...except the outermost pair: the transition-closing resume covers both
    // the prepared and the suspended lists, so it is the sequence's job.
    assert_eq!(unwind_from(Step::DevSuspend)[0], Undo::DevResume);
}

#[test]
fn platform_recover_runs_only_for_the_device_suspend_phase() {
    for step in DEEP_STEPS {
        let want = matches!(step, Step::DevPrepare | Step::DevSuspend);
        assert_eq!(runs_platform_recover(step), want, "{step:?}");
    }
}

#[test]
fn every_failure_that_began_the_platform_ends_it() {
    for step in DEEP_STEPS.iter().chain(IDLE_STEPS.iter()) {
        let after_begin = (*step as u8) > (Step::PlatformBegin as u8);
        if !after_begin { continue; }
        assert!(unwind_from(*step).contains(&Undo::PlatformEnd),
            "{step:?} leaves the platform transition open");
    }
}

#[test]
fn every_failure_after_the_console_resumes_it() {
    for step in DEEP_STEPS.iter().chain(IDLE_STEPS.iter()) {
        if (*step as u8) <= (Step::ConsoleSuspend as u8) { continue; }
        assert!(unwind_from(*step).contains(&Undo::ConsoleResume),
            "{step:?} leaves the console suspended");
    }
}

#[test]
fn interrupts_and_cpus_come_back_in_the_right_order() {
    let u = unwind_from(Step::PlatformEnter);
    let irqs = u.iter().position(|x| *x == Undo::IrqsOn).unwrap();
    let cpus = u.iter().position(|x| *x == Undo::CpusOn).unwrap();
    let syscore = u.iter().position(|x| *x == Undo::SyscoreResume).unwrap();
    // Core callbacks run with interrupts still off and one CPU online, so they
    // must resume before either comes back.
    assert!(syscore < irqs, "interrupts came back before the core callbacks");
    assert!(irqs < cpus, "secondary CPUs came back with interrupts off");
}

#[test]
fn stats_name_the_step_group_that_failed() {
    use crate::suspend::stats::StatStep;
    assert_eq!(stat_step(Step::FreezeUser), Some(StatStep::Freeze));
    assert_eq!(stat_step(Step::FreezeKernelThreads), Some(StatStep::Freeze));
    assert_eq!(stat_step(Step::DevPrepare), Some(StatStep::Prepare));
    assert_eq!(stat_step(Step::DevSuspend), Some(StatStep::Suspend));
    assert_eq!(stat_step(Step::DevSuspendLate), Some(StatStep::SuspendLate));
    assert_eq!(stat_step(Step::DevSuspendNoirq), Some(StatStep::SuspendNoirq));
    assert_eq!(stat_step(Step::PlatformEnter), None);
}
