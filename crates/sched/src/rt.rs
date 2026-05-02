// RT runqueue per `13§3` / `13§7`: 100 priority buckets (`1..=99` plus
// the unused 0 slot) + a `nonempty` bitmap for O(1) `pick_highest`.
// `pick_next` returns the highest-priority task at the front of its
// bucket; FIFO order within priority. SCHED_RR is identical at the
// runqueue level — quantum exhaustion is the timer-tick's concern
// (out of scope here).

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::task::{SchedClass, Task};

/// RT priorities per `13§3`: 1..=99. Slot 0 is unused; keeps indexing
/// trivial and reserves room for a future "Idle-RT" class.
pub const RT_PRIO_COUNT: usize = 100;

/// O(1) RT runqueue.
pub struct RtRunqueue {
    /// FIFO per priority. `Arc<Task>` so the same task can sit across
    /// runqueue boundaries during migration without aliasing concerns.
    queues: Vec<VecDeque<Arc<Task>>>,
    /// `bit i` set iff `queues[i]` non-empty.
    nonempty: u128, // 100 bits comfortably fits
    nr_running: u32,
}

impl RtRunqueue {
    /// # C: O(RT_PRIO_COUNT)
    pub fn new() -> Self {
        let mut queues = Vec::with_capacity(RT_PRIO_COUNT);
        queues.resize_with(RT_PRIO_COUNT, VecDeque::new);
        Self { queues, nonempty: 0, nr_running: 0 }
    }

    /// # C: O(1)
    pub fn nr_running(&self) -> u32 { self.nr_running }

    /// # C: O(1)
    pub fn has_runnable(&self) -> bool { self.nonempty != 0 }

    /// Insert at the tail of the priority's FIFO per `SCHED_FIFO`/`RR`
    /// semantics (`13§3`).
    /// # C: O(1)
    pub fn enqueue(&mut self, task: Arc<Task>) {
        let prio = match task.class {
            SchedClass::Rt { prio, .. } => prio as usize,
            _ => panic!("RtRunqueue::enqueue: non-RT task"),
        };
        debug_assert!(prio < RT_PRIO_COUNT);
        self.queues[prio].push_back(task);
        self.nonempty |= 1u128 << prio;
        self.nr_running += 1;
    }

    /// Pick + remove the highest-priority FIFO head. `None` if empty.
    /// # C: O(1) — bitmap leading-zero scan.
    pub fn pick_highest(&mut self) -> Option<Arc<Task>> {
        if self.nonempty == 0 { return None; }
        let prio = (u128::BITS - 1 - self.nonempty.leading_zeros()) as usize;
        let q = &mut self.queues[prio];
        let t = q.pop_front().expect("nonempty bit ⇒ queue non-empty");
        if q.is_empty() {
            self.nonempty &= !(1u128 << prio);
        }
        self.nr_running -= 1;
        Some(t)
    }

    /// Peek at the highest-priority head without removing.
    /// # C: O(1)
    pub fn peek_highest(&self) -> Option<&Arc<Task>> {
        if self.nonempty == 0 { return None; }
        let prio = (u128::BITS - 1 - self.nonempty.leading_zeros()) as usize;
        self.queues[prio].front()
    }

    /// Remove a specific task by `tid`; used by SMP migration and
    /// `sched_setscheduler` class changes. Returns the `Arc` if found.
    /// # C: O(N) within the priority bucket
    pub fn remove(&mut self, tid: u32) -> Option<Arc<Task>> {
        for (prio, q) in self.queues.iter_mut().enumerate() {
            if let Some(pos) = q.iter().position(|t| t.tid == tid) {
                let t = q.remove(pos).unwrap();
                if q.is_empty() {
                    self.nonempty &= !(1u128 << prio);
                }
                self.nr_running -= 1;
                return Some(t);
            }
        }
        None
    }
}

impl Default for RtRunqueue {
    fn default() -> Self { Self::new() }
}
