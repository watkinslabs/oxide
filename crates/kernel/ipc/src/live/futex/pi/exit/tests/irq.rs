#[test]
fn exit_empty_owner_site_preserves_irq_state() {
    let task = sched::Task::new(9504, 9504);
    for enabled in [true, false] {
        crate::irq_probe::check(&task, enabled, || super::exit_pi_state_list(&task));
    }
}
