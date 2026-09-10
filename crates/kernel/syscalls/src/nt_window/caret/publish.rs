//! Canonical caret pattern snapshots enter the existing compositor connection.
use alloc::sync::Arc;
use super::CaretRenderSink;
use super::super::{GUI, valid_window};
use syscall::nt_compositor::{caret::Snapshot, Rect};

pub(crate) struct Current;
impl Current {
    fn publish(tid: u64, hwnd: u64, rect: (i32, i32, i32, i32), generation: u64, visible: bool, pattern:ipc::win32_window::CaretPattern) -> bool {
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
        // Equal signed source/destination extents crop a negative axis at bitmap origin to one pixel.
        let width=if width<0{1}else{width as u32};let height=if height<0{1}else{height as u32};
        let Ok(mut snapshot) = Snapshot::solid(generation, Rect { x, y, width, height }, visible) else { return false; };
        if pattern==ipc::win32_window::CaretPattern::Gray {
            for (index,pixel) in snapshot.mask.iter_mut().enumerate(){
                // Pattern origin is the caret bitmap, independent of client/frame position.
                if (index/width as usize+index%width as usize)&1==0{*pixel=0;}
            }
        }
        crate::nt_compositor::caret::publish_current(hwnd, &snapshot)
    }
}
impl CaretRenderSink for Current {
    fn erase_caret_pixels(&mut self, tid: u64, hwnd: u64, rect: (i32,i32,i32,i32), generation: u64) -> bool {
        Self::publish(tid, hwnd, rect, generation, false, ipc::win32_window::CaretPattern::Solid)
    }
    fn paint_caret_pixels(&mut self, tid: u64, hwnd: u64, rect: (i32,i32,i32,i32), generation: u64, pattern:ipc::win32_window::CaretPattern) -> bool {
        Self::publish(tid, hwnd, rect, generation, true, pattern)
    }
}
