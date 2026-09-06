use super::*;
use crate::{Task, SchedClass};

fn child() -> Child {
    Child { creator: 701, generation: 1, phase: Phase::Preparing,
        stack: 0x10000, size: 0x10000, start: 0x400000, parameter: 9 }
}

#[test]
fn attachment_readiness_is_not_implied_by_teb_or_native_identity() {
    let task = Task::new(702, "native-child", SchedClass::Normal { weight: 1024 });
    task.set_nt_teb(0x70000);
    let mut state = task.nt_native_thread.lock();
    assert!(!state.advance(Phase::Preparing, Phase::Ready));
    state.child = Some(child());
    assert!(!state.callbacks_ready());
    assert!(!state.advance(Phase::Ready, Phase::Published));
    assert!(!state.advance(Phase::Preparing, Phase::Running));
    assert!(state.advance(Phase::Preparing, Phase::Ready));
    assert!(!state.advance(Phase::Preparing, Phase::Ready));
    assert!(state.advance(Phase::Ready, Phase::Published));
    assert!(!state.callbacks_ready());
    assert!(state.advance(Phase::Published, Phase::Running));
    assert!(state.callbacks_ready());
    assert!(state.advance(Phase::Running, Phase::Returning));
    assert!(!state.callbacks_ready());
    assert!(state.returning());
    assert!(!state.advance(Phase::Returning, Phase::Running));
    assert_eq!(task.tid, 702);
    assert_eq!(task.nt_teb(), 0x70000);
}

#[test]
fn native_resume_and_terminal_status_remain_on_the_same_task() {
    let task = Task::new(703, "native-return", SchedClass::Normal { weight: 1024 });
    let mut state = task.nt_native_thread.lock();
    state.child = Some(child());
    assert!(state.advance(Phase::Preparing, Phase::Ready));
    assert!(state.advance(Phase::Ready, Phase::Published));
    assert!(state.advance(Phase::Published, Phase::Running));
    state.resume = Some([0x12345678; 40]);
    assert!(state.request_termination(0xc0000005));
    assert!(state.request_termination(42));
    assert!(!state.termination_ready(false));
    assert!(state.termination_ready(true));
    state.request = Some(Request { generation: 2, output: 0, start: 0, parameter: 0,
        stack_size: 0x10000, suspended: false, child: None });
    assert!(!state.termination_ready(true));
    state.request = None;
    let (frame, status) = state.finish(0).unwrap();
    assert_eq!(frame[0], 0x12345678);
    assert_eq!(status, 0xc0000005);
    assert!(state.finish(0).is_none());
    assert_eq!(state.result, Some(0xc0000005));
    assert!(state.resume.is_none());
    assert!(!state.termination_ready(true));
    assert_eq!(task.tid, 703);
}
