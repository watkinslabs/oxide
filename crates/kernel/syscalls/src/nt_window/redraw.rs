//! Synchronous UpdateWindow scan and per-GUI-entry continuation ownership.
use alloc::vec::Vec;
use ipc::win32_window::{PaintChildren, WindowId};

const MAX_REDRAWS: usize = 64;
const RDW_UPDATENOW: u32 = 0x0100;
const RDW_ALLCHILDREN: u32 = 0x0080;
const RDW_NOCHILDREN: u32 = 0x0040;
const RDW_ERASENOW: u32 = 0x0200;
pub(crate) const ORDINAL: u64 = 0x14e9;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Scan { pub root: WindowId, pub after: Option<WindowId>, pub mode: PaintChildren, pub erase: bool }
struct Pending { token: u64, tid: u64, scan: Scan, driving: bool, completed: Option<Result<u64, ()>> }
pub(crate) struct Queue { next: u64, pending: Vec<Pending> }
impl Queue {
    pub(crate) fn new() -> Self { Self { next: 1, pending: Vec::new() } }
    pub(crate) fn admit(&mut self, tid: u64, root: WindowId, mode: PaintChildren) -> Option<u64> {
        if self.pending.len() >= MAX_REDRAWS { return None; }
        let next = self.next.checked_add(1)?;
        self.pending.try_reserve(1).ok()?;
        let token = self.next;
        self.pending.push(Pending { token, tid, scan: Scan { root, after: None, mode, erase: false }, driving: false, completed: None });
        self.next = next;
        Some(token)
    }
    pub(crate) fn scan(&self, tid: u64, token: u64) -> Option<Scan> {
        self.pending.iter().find(|entry| entry.tid == tid && entry.token == token).map(|entry| entry.scan)
    }
    pub(crate) fn set_erase(&mut self, tid: u64, token: u64) {
        if let Some(p) = self.pending.iter_mut().find(|p| p.tid == tid && p.token == token) { p.scan.erase = true; }
    }
    pub(crate) fn defer_if_driving(&mut self, tid: u64, token: u64, result: Result<u64, ()>) -> bool {
        let Some(p) = self.pending.iter_mut().find(|p| p.tid == tid && p.token == token && p.driving) else { return false; };
        p.completed = Some(result); true
    }
    pub(crate) fn drive_erase(&mut self, tid: u64, token: u64) {
        if let Some(p) = self.pending.iter_mut().find(|p| p.tid == tid && p.token == token) { p.driving = true; }
    }
    pub(crate) fn end_drive(&mut self, tid: u64, token: u64) -> Option<Result<u64, ()>> {
        let p = self.pending.iter_mut().find(|p| p.tid == tid && p.token == token)?;
        p.driving = false; p.completed.take()
    }
    pub(crate) fn advance(&mut self, tid: u64, token: u64, window: WindowId) -> bool {
        let Some(entry) = self.pending.iter_mut().find(|entry| entry.tid == tid && entry.token == token) else { return false; };
        entry.scan.after = Some(window); true
    }
    pub(crate) fn finish(&mut self, tid: u64, token: u64) -> bool {
        let Some(index) = self.pending.iter().position(|entry| entry.tid == tid && entry.token == token) else { return false; };
        self.pending.remove(index); true
    }
    pub(crate) fn cancel_thread(&mut self, tid: u64) { self.pending.retain(|entry| entry.tid != tid); }
    pub(crate) fn cancel_window(&mut self, hwnd: WindowId) { self.pending.retain(|entry| entry.scan.root != hwnd); }
}

pub(crate) fn mode(rect: u64, region: u64, flags: u32) -> Option<PaintChildren> {
    let _ = (rect, region);
    Some(if flags & RDW_NOCHILDREN != 0 { PaintChildren::None }
        else if flags & RDW_ALLCHILDREN != 0 { PaintChildren::All } else { PaintChildren::Default })
}

#[path = "redraw/input.rs"]
mod input;
pub(crate) use input::{read_rect, read_region};

#[path = "redraw/erase.rs"]
pub(crate) mod erase;
pub(crate) use erase::ErasePrepared;

#[cfg(target_os = "oxide-kernel")]
#[path = "redraw/live.rs"]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::{for_current, resume};

#[cfg(test)]
#[path = "redraw/tests.rs"]
mod tests;
