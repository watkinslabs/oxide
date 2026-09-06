//! Canonical per-queue caret blink deadlines (`31fl`).

use super::{CaretCommit, CaretState, CaretTransition, MessageQueue, WindowId, WindowManager};

pub const DEFAULT_CARET_BLINK_MS: u32 = 500;
const NS_PER_MS: u64 = 1_000_000;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExpiredCaretCommit { pub owner_tid: u64, pub hwnd: WindowId, pub generation: u64 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CaretBlink { pub hwnd: Option<WindowId>, pub owner_tid: u64, pub generation: u64, pub interval_ms: u32, pub deadline_ns: Option<u64> }

impl Default for CaretBlink { fn default() -> Self { Self::new() } }

impl CaretBlink {
    pub const fn new() -> Self { Self { hwnd: None, owner_tid: 0, generation: 0, interval_ms: DEFAULT_CARET_BLINK_MS, deadline_ns: None } }

    /// Arm or replace the queue's one canonical caret deadline.
    /// # C: O(1)
    pub fn arm(&mut self, owner_tid: u64, hwnd: WindowId, generation: u64, now_ns: u64, interval_ms: u32) {
        let delta = u64::from(interval_ms).saturating_mul(NS_PER_MS);
        self.hwnd = Some(hwnd); self.owner_tid = owner_tid; self.generation = generation;
        self.interval_ms = interval_ms; self.deadline_ns = Some(now_ns.saturating_add(delta));
    }

    /// Clear the deadline only for the matching queue caret identity.
    /// # C: O(1)
    pub fn clear(&mut self, owner_tid: u64, hwnd: Option<WindowId>) -> bool {
        if self.owner_tid != owner_tid || hwnd.is_some() && self.hwnd != hwnd { return false; }
        let was_armed = self.deadline_ns.is_some();
        self.hwnd = None; self.deadline_ns = None; was_armed
    }

    /// Return the next wake deadline for GetMessage readiness.
    /// # C: O(1)
    pub const fn deadline(&self) -> Option<u64> { self.deadline_ns }

    /// Retag an armed deadline after a non-blink caret commit.
    ///
    /// The caret generation advances for every canonical caret transition.  A
    /// visible ShowCaret or a same-position SetCaretPos must not restart the
    /// timer, but its expiry must still carry the new generation.
    pub fn refresh_generation(&mut self, owner_tid: u64, hwnd: WindowId, generation: u64) -> bool {
        if self.owner_tid != owner_tid || self.hwnd != Some(hwnd) || self.deadline_ns.is_none() { return false; }
        self.generation = generation;
        true
    }

    /// Convert one elapsed deadline into a typed toggle commit and re-arm it.
    /// # C: O(1)
    fn expire(&mut self, now_ns: u64) -> Option<ExpiredCaretCommit> {
        let deadline = self.deadline_ns?;
        let hwnd = self.hwnd?;
        if now_ns < deadline { return None; }
        let commit = ExpiredCaretCommit { owner_tid: self.owner_tid, hwnd, generation: self.generation };
        let delta = u64::from(self.interval_ms).saturating_mul(NS_PER_MS);
        self.deadline_ns = Some(now_ns.saturating_add(delta));
        Some(commit)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CaretBlinkError { NoQueue, InvalidWindow, WrongThread }

impl MessageQueue {
    /// Arm the queue-owned deadline without changing canonical caret state.
    /// # C: O(1)
    pub fn arm_caret_blink(&mut self, owner_tid: u64, hwnd: WindowId, generation: u64, now_ns: u64, interval_ms: u32) {
        self.caret_blink.arm(owner_tid, hwnd, generation, now_ns, interval_ms);
    }

    /// Clear the queue deadline for the matching caret identity.
    /// # C: O(1)
    pub fn clear_caret_blink(&mut self, owner_tid: u64, hwnd: Option<WindowId>) -> bool { self.caret_blink.clear(owner_tid, hwnd) }

    /// Preserve the current deadline while advancing its canonical generation.
    pub fn refresh_caret_blink_generation(&mut self, owner_tid: u64, hwnd: WindowId, generation: u64) -> bool {
        self.caret_blink.refresh_generation(owner_tid, hwnd, generation)
    }

    /// Apply one elapsed blink to canonical caret phase and return its transition.
    /// # C: O(1)
    pub fn expire_caret_blink_commit(&mut self, now_ns: u64) -> Option<CaretCommit> {
        let expired = self.caret_blink.expire(now_ns)?;
        if self.caret.hwnd != Some(expired.hwnd) || self.caret_generation != expired.generation || self.caret.hide_depth != 0 {
            self.caret_blink.clear(expired.owner_tid, Some(expired.hwnd));
            return None;
        }
        let old = self.caret;
        self.caret.on = !self.caret.on;
        let rect = |state: CaretState| (state.x, state.y, state.x.saturating_add(state.width), state.y.saturating_add(state.height));
        let transition = CaretTransition { old_hwnd: old.hwnd, hwnd: self.caret.hwnd.or(old.hwnd), old_visible: old.visible(), new_visible: self.caret.visible(), old_rect: rect(old), new_rect: rect(self.caret) };
        self.caret_generation = self.caret_generation.wrapping_add(1);
        self.caret_blink.generation = self.caret_generation;
        Some(CaretCommit { transition, generation: self.caret_generation })
    }

    /// Return the queue's next caret wake deadline.
    /// # C: O(1)
    pub const fn caret_blink_deadline(&self) -> Option<u64> { self.caret_blink.deadline() }
}

impl WindowManager {
    /// Arm the caller queue's caret deadline after a visible-state transition.
    /// # C: O(N_windows + N_queues)
    pub fn arm_current_caret_blink(&mut self, tid: u64, hwnd: WindowId, generation: u64, now_ns: u64, interval_ms: u32) -> Result<(), CaretBlinkError> {
        if self.get(hwnd).ok_or(CaretBlinkError::InvalidWindow)?.owner_tid != tid { return Err(CaretBlinkError::WrongThread); }
        self.queues.iter_mut().find(|(owner, _)| *owner == tid).map(|(_, queue)| queue.arm_caret_blink(tid, hwnd, generation, now_ns, interval_ms)).ok_or(CaretBlinkError::NoQueue)
    }

    /// Clear the caller queue's caret deadline during hide/destroy/teardown.
    /// # C: O(N_queues)
    pub fn clear_current_caret_blink(&mut self, tid: u64, hwnd: Option<WindowId>) -> Result<bool, CaretBlinkError> {
        self.queues.iter_mut().find(|(owner, _)| *owner == tid).map(|(_, queue)| queue.clear_caret_blink(tid, hwnd)).ok_or(CaretBlinkError::NoQueue)
    }

    /// Preserve the caller queue's deadline across a non-blink caret commit.
    pub fn refresh_current_caret_blink_generation(&mut self, tid: u64, hwnd: WindowId, generation: u64) -> Result<bool, CaretBlinkError> {
        self.queues.iter_mut().find(|(owner, _)| *owner == tid).map(|(_, queue)| queue.refresh_caret_blink_generation(tid, hwnd, generation)).ok_or(CaretBlinkError::NoQueue)
    }

    /// Return and re-arm an elapsed caller queue deadline.
    /// # C: O(N_queues)
    pub fn expire_current_caret_blink(&mut self, tid: u64, now_ns: u64) -> Result<Option<CaretCommit>, CaretBlinkError> {
        self.queues.iter_mut().find(|(owner, _)| *owner == tid).map(|(_, queue)| queue.expire_caret_blink_commit(now_ns)).ok_or(CaretBlinkError::NoQueue)
    }

    /// Return the caller queue's next caret deadline for GetMessage waiting.
    /// # C: O(N_queues)
    pub fn current_caret_blink_deadline(&self, tid: u64) -> Result<Option<u64>, CaretBlinkError> {
        self.queues.iter().find(|(owner, _)| *owner == tid).map(|(_, queue)| queue.caret_blink_deadline()).ok_or(CaretBlinkError::NoQueue)
    }

    /// Return the next canonical `WM_TIMER` deadline owned by `tid`.
    ///
    /// This is a read-only view of the existing `timers` vector. It does not
    /// create a second timer registry and does not advance or enqueue timers.
    /// # C: O(N_timers)
    pub fn next_timer_deadline(&self, tid: u64) -> Option<u64> {
        self.timers.iter().filter(|timer| {
            timer.hwnd.and_then(|hwnd| self.get(hwnd).map(|window| window.owner_tid)).unwrap_or(timer.owner_tid) == tid
        }).map(|timer| timer.due_ns).min()
    }

    /// Return the canonical deadline that can make this queue's retrieval
    /// wait run again. `None` means an unbounded wait.
    pub fn next_retrieval_deadline(&self, tid: u64) -> Option<u64> {
        [self.queues.iter().find(|(owner, _)| *owner == tid).and_then(|(_, queue)| queue.caret_blink_deadline()), self.next_timer_deadline(tid)].into_iter().flatten().min()
    }

    /// Return the canonical current caret client position for `tid`.
    /// # C: O(N_queues)
    pub fn current_caret_position(&self, tid: u64) -> Option<(i32, i32)> {
        self.queues.iter().find(|(owner, _)| *owner == tid).and_then(|(_, queue)| queue.caret.hwnd.map(|_| (queue.caret.x, queue.caret.y)))
    }

    /// Update the interval used by future queue deadline arms without
    /// replacing an already-derived runtime deadline.
    /// # C: O(queues)
    pub fn set_current_caret_blink_interval(&mut self, tid: u64, interval_ms: u32) -> Result<(), CaretBlinkError> {
        self.queues.iter_mut().find(|(owner, _)| *owner == tid).map(|(_, queue)| { queue.caret_blink.interval_ms = interval_ms; }).ok_or(CaretBlinkError::NoQueue)
    }

    /// Return the queue's current configured interval.
    /// # C: O(queues)
    pub fn current_caret_blink_interval(&self, tid: u64) -> Result<u32, CaretBlinkError> {
        self.queues.iter().find(|(owner, _)| *owner == tid).map(|(_, queue)| queue.caret_blink.interval_ms).ok_or(CaretBlinkError::NoQueue)
    }
}

#[cfg(test)]
#[path = "blink/tests.rs"]
mod tests;
