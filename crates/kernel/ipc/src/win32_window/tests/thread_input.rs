use super::*;

#[test]
fn an_unattached_thread_is_its_own_input() {
    let inputs = ThreadInputs::new();
    assert_eq!(inputs.input_of(11), 11);
    assert!(!inputs.attached(11));
}

#[test]
fn attaching_moves_a_thread_onto_the_target_input_and_detaching_restores_it() {
    let mut inputs = ThreadInputs::new();
    let queued = |tid| tid == 1 || tid == 2;
    assert_eq!(inputs.set(1, 2, true, queued), Ok(()));
    assert_eq!(inputs.input_of(1), 2);
    assert_eq!(inputs.set(1, 2, false, queued), Ok(()));
    assert_eq!(inputs.input_of(1), 1);
}

#[test]
fn a_thread_cannot_attach_to_itself() {
    let mut inputs = ThreadInputs::new();
    assert_eq!(inputs.set(1, 1, true, |_| true), Err(AttachError::AccessDenied));
    assert_eq!(inputs.set(1, 1, false, |_| true), Err(AttachError::AccessDenied));
}

#[test]
fn attaching_needs_both_queues_and_detaching_needs_a_shared_input() {
    let mut inputs = ThreadInputs::new();
    assert_eq!(inputs.set(1, 2, true, |tid| tid == 1), Err(AttachError::InvalidParameter));
    assert_eq!(inputs.set(1, 2, false, |_| true), Err(AttachError::AccessDenied));
}

#[test]
fn a_chain_of_attachments_lands_on_one_input() {
    let mut inputs = ThreadInputs::new();
    inputs.set(1, 2, true, |_| true).unwrap();
    inputs.set(2, 3, true, |_| true).unwrap();
    assert_eq!(inputs.input_of(1), 3);
    assert_eq!(inputs.input_of(2), 3);
}

#[test]
fn the_manager_admits_an_attach_only_between_threads_that_hold_queues() {
    let mut manager = crate::win32_window::WindowManager::new();
    assert_eq!(manager.attach_thread_input(1, 2, true), Err(AttachError::InvalidParameter));
    manager.post_quit(1, 0);
    manager.post_quit(2, 0);
    assert_eq!(manager.attach_thread_input(1, 2, true), Ok(()));
    assert_eq!(manager.thread_input(1), 2);
}
