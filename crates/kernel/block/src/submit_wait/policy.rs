/// Idle remains current after runqueue installation but must never park.
/// Missing tasks and atomic contexts must also poll completion.
/// # C: O(1)
pub(super) fn can_sleep(task: Option<&sched::Task>, atomic: bool) -> bool {
    !atomic && task.is_some_and(|task| task.sched_class() != sched::SchedClass::Idle)
}
