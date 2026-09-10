//! Canonical hook registry and suspended notification walks under one owner lock.
use alloc::vec::Vec;
use ipc::win32_hook::{ChainLease, Hook, HookRegistry, HookThread, WH_WINEVENT};
use super::hook_event::Notification;
use crate::nt_window::send::Continuation;

pub(super) struct State { pub registry: HookRegistry, next: u64, events: Vec<Pending> }
struct Pending { token: u64, caller: HookThread, event: Notification, after: Option<u32>, lease: ChainLease, resume: Option<Continuation> }
pub(super) enum Step { Call(Hook, Notification), Done(Option<Continuation>) }

impl State {
    /// # C: O(1)
    pub const fn new() -> Self { Self { registry: HookRegistry::new(), next: 1, events: Vec::new() } }

    /// Retain the canonical chain before any client callback. # C: O(N_threads + allocation)
    pub fn begin(&mut self, caller: HookThread, event: Notification, resume: Option<Continuation>) -> Option<u64> {
        let next = self.next.checked_add(1)?;
        self.events.try_reserve(1).ok()?;
        let lease = self.registry.hold_chain(WH_WINEVENT, caller).ok()?;
        let token = self.next; self.next = next;
        self.events.push(Pending { token, caller, event, after: None, lease, resume });
        Some(token)
    }

    /// Continue past the saved cursor, including a removed hook. # C: O(N_notifications + N_threads + N_hooks)
    pub fn step(&mut self, token: u64, thread: u64) -> Option<Step> {
        let index = self.events.iter().position(|pending| pending.token == token && pending.caller.thread == thread)?;
        let pending = &mut self.events[index];
        if let Some(next) = self.registry.next_hook(WH_WINEVENT, pending.after, pending.caller, pending.event.event) {
            let hook = self.registry.get(next.handle)?.clone();
            pending.after = Some(next.handle);
            return Some(Step::Call(hook, pending.event));
        }
        let pending = self.events.remove(index);
        self.registry.release_chain(pending.lease);
        Some(Step::Done(pending.resume))
    }

    /// Release walks before removing the exiting thread's hook tables. # C: O(N_notifications * N_hooks)
    pub fn forget_thread(&mut self, thread: u64) {
        while let Some(index) = self.events.iter().position(|pending| pending.caller.thread == thread) {
            let pending = self.events.remove(index);
            self.registry.release_chain(pending.lease);
        }
        self.registry.cleanup_thread(thread);
    }
}
