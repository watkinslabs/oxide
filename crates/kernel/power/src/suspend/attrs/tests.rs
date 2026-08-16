use super::*;
use crate::suspend::state::{mem_sleep_states, pm_states};
use crate::suspend::ops::PlatformSuspendOps;
use crate::decide::KResult;

fn ok_enter(_s: SuspendState) -> KResult<()> { Ok(()) }
fn valid_mem(s: SuspendState) -> bool { s == SuspendState::Mem }
fn valid_both(s: SuspendState) -> bool { s != SuspendState::ToIdle }

fn ops(valid: fn(SuspendState) -> bool) -> PlatformSuspendOps {
    let mut o = PlatformSuspendOps::none();
    o.valid = Some(valid); o.enter = Some(ok_enter);
    o
}

#[test]
fn state_renders_space_separated_with_a_trailing_newline() {
    assert_eq!(render_state(pm_states(None)), "freeze mem\n");
    let o = ops(valid_both);
    assert_eq!(render_state(pm_states(Some(&o))), "freeze standby mem\n");
}

#[test]
fn an_empty_state_set_renders_nothing() {
    assert_eq!(render_state(StateSet::empty()), "");
}

#[test]
fn mem_sleep_brackets_the_selection_and_nothing_else() {
    let o = ops(valid_mem);
    let set = mem_sleep_states(Some(&o));
    assert_eq!(render_mem_sleep(set, SuspendState::ToIdle), "[s2idle] deep\n");
    assert_eq!(render_mem_sleep(set, SuspendState::Mem), "s2idle [deep]\n");
    // A selection outside the set brackets nothing.
    assert_eq!(render_mem_sleep(set, SuspendState::Standby), "s2idle deep\n");
}

#[test]
fn mem_sleep_with_one_mechanism_still_terminates() {
    assert_eq!(render_mem_sleep(mem_sleep_states(None), SuspendState::ToIdle), "[s2idle]\n");
}

#[test]
fn mem_sleep_lists_all_three_in_order() {
    let o = ops(valid_both);
    let set = mem_sleep_states(Some(&o));
    assert_eq!(render_mem_sleep(set, SuspendState::Standby), "s2idle [shallow] deep\n");
}

#[test]
fn numbers_render_with_a_newline_and_no_padding() {
    assert_eq!(render_u64(0), "0\n");
    assert_eq!(render_u64(1), "1\n");
    assert_eq!(render_u64(4_294_967_296), "4294967296\n");
    assert_eq!(render_u64(u64::MAX), "18446744073709551615\n");
}

#[test]
fn signed_numbers_render_their_sign() {
    assert_eq!(render_i32(0), "0\n");
    assert_eq!(render_i32(-16), "-16\n");
    assert_eq!(render_i32(i32::MIN), "-2147483648\n");
}

#[test]
fn booleans_render_as_zero_and_one() {
    assert_eq!(render_bool(false), "0\n");
    assert_eq!(render_bool(true), "1\n");
}

#[test]
fn every_stats_attribute_renders() {
    let s = SuspendStats::new();
    for name in STATS_ATTRS {
        assert!(render_stat(&s, name).is_some(), "{name} does not render");
    }
    assert!(render_stat(&s, "nonesuch").is_none());
    assert!(render_stat(&s, "failed_nonesuch").is_none());
}

#[test]
fn the_stats_attribute_list_matches_the_step_names() {
    for i in 0..NR_STEPS {
        let step = StatStep::from_index(i).unwrap();
        let attr = alloc::format!("failed_{}", step.name());
        assert!(STATS_ATTRS.contains(&attr.as_str()), "{attr} missing from the group");
        assert_eq!(step_by_name(step.name()), Some(step));
    }
}

#[test]
fn stats_render_the_recorded_values() {
    let s = SuspendStats::new();
    s.save_errno(0);
    s.save_errno(-16);
    s.save_failed_step(StatStep::SuspendNoirq);
    s.save_failed_dev("virtio1");
    assert_eq!(render_stat(&s, "success").unwrap(), "1\n");
    assert_eq!(render_stat(&s, "fail").unwrap(), "1\n");
    assert_eq!(render_stat(&s, "last_failed_errno").unwrap(), "-16\n");
    assert_eq!(render_stat(&s, "last_failed_step").unwrap(), "suspend_noirq\n");
    assert_eq!(render_stat(&s, "last_failed_dev").unwrap(), "virtio1\n");
    assert_eq!(render_stat(&s, "failed_suspend_noirq").unwrap(), "1\n");
    assert_eq!(render_stat(&s, "failed_freeze").unwrap(), "0\n");
}

#[test]
fn a_machine_that_never_failed_names_no_step() {
    let s = SuspendStats::new();
    assert_eq!(render_stat(&s, "last_failed_step").unwrap(), "\n");
}

#[test]
fn rendered_attributes_are_what_the_read_returns() {
    assert_eq!(bytes(render_bool(true)), b"1\n".to_vec());
}
