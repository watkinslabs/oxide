//! Canonical uniform caret snapshots enter the existing compositor connection.
use alloc::sync::Arc;
use super::CaretRenderSink;
use super::super::{GUI, valid_window};
use syscall::nt_compositor::{caret::Snapshot, Rect};

pub(crate) struct Current;
impl Current {
    fn publish(tid: u64, hwnd: u64, rect: (i32, i32, i32, i32), generation: u64, visible: bool) -> bool {
        let Some(current) = sched::live::current().filter(|current| current.is_nt_personality() && current.tid as u64 == tid) else { return false; };
        let Some(window) = valid_window(hwnd) else { return false; };
        let offset = {
            let entries = GUI.lock();
            let Some(entry) = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))) else { return false; };
            let Some(record) = entry.state.get(window).filter(|record| record.owner_tid == tid) else { return false; };
            let Some(bounds) = entry.state.rect(window) else { return false; };
            let client = record.client_rect.unwrap_or(bounds);
            (client.left.checked_sub(bounds.left), client.top.checked_sub(bounds.top))
        };
        let (Some(dx), Some(dy)) = offset else { return false; };
        let (Some(x), Some(y), Some(width), Some(height)) = (rect.0.checked_add(dx), rect.1.checked_add(dy), rect.2.checked_sub(rect.0), rect.3.checked_sub(rect.1)) else { return false; };
        let (Ok(width), Ok(height)) = (u32::try_from(width), u32::try_from(height)) else { return false; };
        let Ok(snapshot) = Snapshot::solid(generation, Rect { x, y, width, height }, visible) else { return false; };
        crate::nt_compositor::caret::publish_current(hwnd, &snapshot)
    }
}
impl CaretRenderSink for Current {
    fn erase_caret_pixels(&mut self, tid: u64, hwnd: u64, rect: (i32,i32,i32,i32), generation: u64) -> bool {
        Self::publish(tid, hwnd, rect, generation, false)
    }
    fn paint_caret_pixels(&mut self, tid: u64, hwnd: u64, rect: (i32,i32,i32,i32), generation: u64) -> bool {
        Self::publish(tid, hwnd, rect, generation, true)
    }
}
