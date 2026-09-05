use crate::Task;

/// Native debug notifications emitted on behalf of one task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDebugEvent { ThreadCreate, ThreadExit, Exception }

/// Apply NT debugger hiding at the native debug publication boundary.
/// Linux ptrace visibility remains independent of this NT-only state.
/// # C: O(1)
pub fn native_debug_event_visible(task: &Task, _event: NativeDebugEvent) -> bool {
    !task.is_nt_personality() || !task.nt_thread_info.debugger_hidden()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SchedClass;

    #[test]
    fn hidden_nt_task_suppresses_native_events_only() {
        let task = Task::new(8201, "debug-event", SchedClass::Normal { weight: 1024 });
        task.set_nt_personality(true);
        assert!(native_debug_event_visible(&task, NativeDebugEvent::Exception));
        task.nt_thread_info.hide_from_debugger();
        assert!(!native_debug_event_visible(&task, NativeDebugEvent::Exception));
        task.set_nt_personality(false);
        assert!(native_debug_event_visible(&task, NativeDebugEvent::Exception));
    }
}
