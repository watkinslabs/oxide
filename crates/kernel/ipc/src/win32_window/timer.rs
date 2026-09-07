//! Window-timer arming, id allocation and expiry (`31t§4`).
//!
//! A timer is identified by the triple (window, message, id). `WM_TIMER` and
//! `WM_SYSTIMER` therefore occupy separate id spaces on the same window, and a
//! windowless timer whose id the caller did not name is assigned one from the
//! owning queue's descending allocator.
use super::queue_status::QS_TIMER;
use super::{MessageQueue, WinMessage, WindowError, WindowId, WindowManager, WindowTimer};

/// Timeout clamp applied before the timer reaches the queue.
pub const USER_TIMER_MINIMUM: u32 = 0x0000_000a;
pub const USER_TIMER_MAXIMUM: u32 = 0x7fff_ffff;
/// Windowless timer ids run down from this bound and wrap above the reserved low ids.
pub const TIMER_ID_FIRST: u64 = 0x7fff;
pub const TIMER_ID_LAST: u64 = 0x100;

/// # C: O(1)
pub const fn clamp_timeout(timeout_ms: u32) -> u32 {
    if timeout_ms < USER_TIMER_MINIMUM { return USER_TIMER_MINIMUM; }
    if timeout_ms > USER_TIMER_MAXIMUM { return USER_TIMER_MAXIMUM; }
    timeout_ms
}

impl MessageQueue {
    /// Step the descending windowless-timer allocator, wrapping at the reserved bound. # C: O(1)
    pub(super) fn step_timer_id(&mut self) -> u64 {
        if self.next_timer_id == 0 { self.next_timer_id = TIMER_ID_FIRST; }
        let id = self.next_timer_id;
        self.next_timer_id = if id.saturating_sub(1) <= TIMER_ID_LAST { TIMER_ID_FIRST } else { id - 1 };
        id
    }
    pub(super) fn peek_timer_id(&self) -> u64 { if self.next_timer_id == 0 { TIMER_ID_FIRST } else { self.next_timer_id } }
}

impl WindowManager {
    fn timer_index(&self, hwnd: Option<WindowId>, message: u32, id: u64) -> Option<usize> {
        self.timers.iter().position(|timer| timer.hwnd == hwnd && timer.message == message && timer.id == id)
    }

    /// Arm or replace one timer. A windowless request whose id names no live
    /// timer takes a freshly allocated id, which is what the call reports.
    /// # C: O(N_timers)
    pub fn set_timer(&mut self, owner_tid: u64, hwnd: Option<WindowId>, message: u32, id: u64,
        timeout_ms: u32, proc: u64, now_ns: u64) -> Result<u64, WindowError> {
        if let Some(window) = hwnd { if self.get(window).is_none() { return Err(WindowError::NoSuchWindow); } }
        let period_ns = (clamp_timeout(timeout_ms) as u64).saturating_mul(1_000_000);
        let owner = hwnd.and_then(|window| self.get(window)).map_or(owner_tid, |record| record.owner_tid);
        self.ensure_queue(owner);
        let id = match self.timer_index(hwnd, message, id) {
            Some(index) => { self.timers.remove(index); id }
            None if hwnd.is_some() => id,
            None => self.allocate_timer_id(owner, message)?,
        };
        self.timers.try_reserve(1).map_err(|_| WindowError::NoMemory)?;
        self.timers.push(WindowTimer { owner_tid: owner, hwnd, message, id, period_ns, due_ns: now_ns.saturating_add(period_ns), proc });
        Ok(id)
    }

    fn ensure_queue(&mut self, tid: u64) {
        if self.queues.iter().all(|(owner, _)| *owner != tid) { self.queues.push((tid, MessageQueue::default())); }
    }

    /// Walk the queue allocator until a windowless id in this message space is
    /// free; a full sweep without one is the user-handle exhaustion the call reports.
    /// # C: O(id space * N_timers)
    fn allocate_timer_id(&mut self, tid: u64, message: u32) -> Result<u64, WindowError> {
        let end = self.queues.iter().find(|(owner, _)| *owner == tid).map_or(TIMER_ID_FIRST, |(_, queue)| queue.peek_timer_id());
        loop {
            let Some(queue) = self.queues.iter_mut().find(|(owner, _)| *owner == tid).map(|(_, queue)| queue) else { return Err(WindowError::NoSuchWindow); };
            let id = queue.step_timer_id();
            let next = queue.peek_timer_id();
            if self.timer_index(None, message, id).is_none() { return Ok(id); }
            if next == end { return Err(WindowError::QueueFull); }
        }
    }

    /// Disarm one timer by its (window, message, id) identity. # C: O(N_timers)
    pub fn kill_timer(&mut self, hwnd: Option<WindowId>, message: u32, id: u64) -> bool {
        let Some(index) = self.timer_index(hwnd, message, id) else { return false; };
        self.timers.remove(index);
        true
    }

    /// Post one message per elapsed deadline and re-arm from the current instant.
    /// # C: O(N_timers + N_queues)
    pub fn expire_timers(&mut self, now_ns: u64) -> usize {
        let mut fired = 0;
        for index in 0..self.timers.len() {
            let timer = self.timers[index];
            if now_ns < timer.due_ns { continue; }
            let owner = timer.hwnd.and_then(|window| self.get(window)).map_or(timer.owner_tid, |record| record.owner_tid);
            let Some(queue) = self.queues.iter_mut().find(|(tid, _)| *tid == owner).map(|(_, queue)| queue) else { continue; };
            if queue.post_with_bits(WinMessage { hwnd: timer.hwnd, message: timer.message, wparam: timer.id, lparam: timer.proc as i64 }, QS_TIMER).is_ok() { fired += 1; }
            self.timers[index].due_ns = now_ns.saturating_add(timer.period_ns);
        }
        fired
    }
}

#[cfg(test)]
#[path = "tests/timer.rs"]
mod tests;
