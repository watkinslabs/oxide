use alloc::sync::Arc;
use alloc::vec::Vec;
use std::thread;

use super::*;
use crate::SchedClass;

fn units(value: &str) -> Vec<u16> { value.encode_utf16().collect() }

#[test]
fn canonical_nt_description_is_not_replaced_by_comm_writes() {
    let task = Task::new(9101, "seed", SchedClass::Normal { weight: 1024 });
    let name = units("λ-windows-worker");
    task.set_nt_description(&name);
    assert_eq!(task.nt_thread_info.description(), name);
    task.set_comm_raw(b"diagnostic-only");
    assert_eq!(task.nt_thread_info.description(), units("λ-windows-worker"));
}

#[test]
fn concurrent_snapshots_are_whole_descriptions() {
    let state = Arc::new(State::new());
    let first = units("first-工作者");
    let second = units("second-λβγ");
    state.replace_description(&first);
    let writer_state = Arc::clone(&state);
    let writer_first = first.clone();
    let writer_second = second.clone();
    let writer = thread::spawn(move || for i in 0..20_000 {
        writer_state.replace_description(if i & 1 == 0 { &writer_first } else { &writer_second });
    });
    for _ in 0..20_000 {
        let seen = state.description();
        assert!(seen == first || seen == second);
    }
    writer.join().unwrap();
}

#[test]
fn debugger_hidden_is_a_one_way_latch() {
    let state = State::new();
    assert!(!state.debugger_hidden());
    state.hide_from_debugger();
    assert!(state.debugger_hidden());
    state.hide_from_debugger();
    assert!(state.debugger_hidden());
}
