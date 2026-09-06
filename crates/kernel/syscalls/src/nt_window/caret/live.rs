// Live per-message-queue caret operations. The canonical state is owned by
// WindowManager's owner-TID message queue, not by GuiEntry. GUI is held only
// for the state transaction; Curie's renderer is called afterwards with the
// committed transition and generation.

use alloc::sync::Arc;

use super::{publish_transition, CaretRenderSink};
use ipc::win32_window::{CaretCommit, WindowId};
use crate::nt_window::GUI;

fn current() -> Option<(Arc<sched::thread_group::ThreadGroup>, u64)> {
    let current = sched::live::current()?;
    if !current.is_nt_personality() { return None; }
    Some((Arc::clone(&current.thread_group), current.tid as u64))
}

fn window_id(hwnd: u64) -> Option<WindowId> {
    u32::try_from(hwnd).ok().and_then(WindowId::from_raw)
}

fn entry_index(entries: &[super::super::GuiEntry], group: &Arc<sched::thread_group::ThreadGroup>) -> Option<usize> {
    entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, group)))
}

fn publish_commit<S: CaretRenderSink + ?Sized>(sink: &mut S, tid: u64, commit: ipc::win32_window::CaretCommit) -> u64 {
    publish_transition(sink, tid, commit.transition, commit.generation) as u64
}

#[derive(Copy, Clone)]
enum BlinkSync { Arm, Clear, Preserve }

fn sync_blink(state: &mut ipc::win32_window::WindowManager, tid: u64, commit: CaretCommit, action: BlinkSync, interval_ms: u32) {
    match action {
    BlinkSync::Arm => {
        if let Some(hwnd) = commit.transition.hwnd {
            let _ = state.arm_current_caret_blink(tid, hwnd, commit.generation, timekeeper::monotonic_ns(), interval_ms);
        }
    }
    BlinkSync::Clear => {
        let _ = state.clear_current_caret_blink(tid, None);
    }
    BlinkSync::Preserve => {
        if let Some(hwnd) = commit.transition.hwnd {
            let _ = state.refresh_current_caret_blink_generation(tid, hwnd, commit.generation);
        }
    }
    }
}

pub(crate) fn create_caret_for_current<S: CaretRenderSink + ?Sized>(hwnd: u64, width: i32, height: i32, sink: &mut S) -> u64 {
    let Some(window) = window_id(hwnd) else { return 0; };
    let Some((group, tid)) = current() else { return 0; };
    let interval_ms = super::super::settings::snapshot_caret_blink_time();
    let commit = { let mut entries = GUI.lock(); let Some(index) = entry_index(&entries, &group) else { return 0; }; let commit = entries[index].state.create_caret(tid, window, width, height).ok(); if let Some(commit) = commit { sync_blink(&mut entries[index].state, tid, commit, BlinkSync::Clear, interval_ms); Some(commit) } else { None } };
    commit.map_or(0, |commit| publish_commit(sink, tid, commit))
}

pub(crate) fn destroy_caret_for_current<S: CaretRenderSink + ?Sized>(sink: &mut S) -> u64 {
    let Some((group, tid)) = current() else { return 0; };
    let interval_ms = super::super::settings::snapshot_caret_blink_time();
    let commit = { let mut entries = GUI.lock(); let Some(index) = entry_index(&entries, &group) else { return 0; }; let commit = entries[index].state.destroy_caret(tid).ok(); if let Some(commit) = commit { sync_blink(&mut entries[index].state, tid, commit, BlinkSync::Clear, interval_ms); Some(commit) } else { None } };
    commit.map_or(0, |commit| publish_commit(sink, tid, commit))
}

pub(crate) fn set_caret_pos_for_current<S: CaretRenderSink + ?Sized>(x: i32, y: i32, sink: &mut S) -> u64 {
    let Some((group, tid)) = current() else { return 0; };
    let interval_ms = super::super::settings::snapshot_caret_blink_time();
    let commit = { let mut entries = GUI.lock(); let Some(index) = entry_index(&entries, &group) else { return 0; }; let commit = entries[index].state.set_caret_pos(tid, x, y).ok(); if let Some(commit) = commit { let moved = commit.transition.old_rect != commit.transition.new_rect; let action = if !commit.transition.new_visible { BlinkSync::Clear } else if moved { BlinkSync::Arm } else { BlinkSync::Preserve }; sync_blink(&mut entries[index].state, tid, commit, action, interval_ms); Some(commit) } else { None } };
    commit.map_or(0, |commit| publish_commit(sink, tid, commit))
}

pub(crate) fn show_caret_for_current<S: CaretRenderSink + ?Sized>(hwnd: u64, sink: &mut S) -> u64 {
    let window = if hwnd == 0 { None } else { let Some(window) = window_id(hwnd) else { return 0; }; Some(window) };
    let Some((group, tid)) = current() else { return 0; };
    let interval_ms = super::super::settings::snapshot_caret_blink_time();
    let commit = { let mut entries = GUI.lock(); let Some(index) = entry_index(&entries, &group) else { return 0; }; let commit = entries[index].state.show_caret(tid, window).ok(); if let Some(commit) = commit { let action = if !commit.transition.old_visible && commit.transition.new_visible { BlinkSync::Arm } else if !commit.transition.new_visible { BlinkSync::Clear } else { BlinkSync::Preserve }; sync_blink(&mut entries[index].state, tid, commit, action, interval_ms); Some(commit) } else { None } };
    commit.map_or(0, |commit| publish_commit(sink, tid, commit))
}

pub(crate) fn hide_caret_for_current<S: CaretRenderSink + ?Sized>(hwnd: u64, sink: &mut S) -> u64 {
    let window = if hwnd == 0 { None } else { let Some(window) = window_id(hwnd) else { return 0; }; Some(window) };
    let Some((group, tid)) = current() else { return 0; };
    let interval_ms = super::super::settings::snapshot_caret_blink_time();
    let commit = { let mut entries = GUI.lock(); let Some(index) = entry_index(&entries, &group) else { return 0; }; let commit = entries[index].state.hide_caret(tid, window).ok(); if let Some(commit) = commit { sync_blink(&mut entries[index].state, tid, commit, BlinkSync::Clear, interval_ms); Some(commit) } else { None } };
    commit.map_or(0, |commit| publish_commit(sink, tid, commit))
}
