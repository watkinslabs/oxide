//! Chain storage: newest hook first, removal by handle or by identifier and
//! procedure, and the ordered walk a hook call follows.
use super::*;

impl HookTable {
    /// Create an empty table. # C: O(1)
    pub const fn new() -> Self { Self { hooks: Vec::new(), next_handle: 1 } }

    /// Install one hook at the head of its chain, answering its handle. A new
    /// hook precedes the ones already installed, so the most recent runs first.
    /// # C: O(N_hooks)
    pub fn install(&mut self, request: &HookRequest<'_>) -> Result<u32, HookError> {
        if chain_index(request.id).is_none() { return Err(HookError::InvalidParameter); }
        let mut module = Vec::new();
        module.try_reserve_exact(request.module.len()).map_err(|_| HookError::NoMemory)?;
        module.extend_from_slice(request.module);
        self.hooks.try_reserve(1).map_err(|_| HookError::NoMemory)?;
        let handle = self.next_handle;
        self.next_handle = self.next_handle.checked_add(1).ok_or(HookError::NoMemory)?;
        self.hooks.insert(0, Hook { handle, id: request.id, process: request.process, thread: request.thread,
            owner: request.owner, event_min: request.event_min, event_max: request.event_max,
            flags: request.flags, proc_address: request.proc_address, unicode: request.unicode, module });
        Ok(handle)
    }

    /// Remove one hook by handle. # C: O(N_hooks)
    pub fn remove(&mut self, handle: u32) -> Result<Hook, HookError> {
        let index = self.hooks.iter().position(|hook| hook.handle == handle).ok_or(HookError::InvalidHandle)?;
        Ok(self.hooks.remove(index))
    }

    /// Remove the first hook in one chain with a given procedure; the caller-
    /// facing identifier-and-procedure form of removal. # C: O(N_hooks)
    pub fn remove_by_proc(&mut self, id: i32, proc_address: u64) -> Result<Hook, HookError> {
        if proc_address == 0 || chain_index(id).is_none() { return Err(HookError::InvalidParameter); }
        let index = self.hooks.iter().position(|hook| hook.id == id && hook.proc_address == proc_address)
            .ok_or(HookError::InvalidParameter)?;
        Ok(self.hooks.remove(index))
    }

    /// One hook by handle, without removing it. # C: O(N_hooks)
    pub fn get(&self, handle: u32) -> Option<&Hook> { self.hooks.iter().find(|hook| hook.handle == handle) }

    /// Hooks in one chain, newest first. # C: O(N_hooks)
    pub fn chain(&self, id: i32) -> impl Iterator<Item = &Hook> { self.hooks.iter().filter(move |hook| hook.id == id) }

    /// Count of hooks in one chain; a thread with a zero count skips the call
    /// entirely. # C: O(N_hooks)
    pub fn chain_count(&self, id: i32) -> usize { self.chain(id).count() }

    /// First hook in a chain that runs in `thread`, at or after `after`.
    /// Passing `None` starts the walk; passing a handle continues past it.
    /// # C: O(N_hooks)
    pub fn next_hook(&self, id: i32, after: Option<u32>, thread: HookThread, event: u32) -> Option<&Hook> {
        let mut seen = after.is_none();
        for hook in self.hooks.iter().filter(|hook| hook.id == id) {
            if !seen { seen = Some(hook.handle) == after; continue; }
            if !runs_in_thread(hook, thread) { continue; }
            if event < hook.event_min || event > hook.event_max { continue; }
            return Some(hook);
        }
        None
    }
}

/// Identity of the thread a chain walk runs in. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HookThread { pub thread: u64, pub process: u64 }

/// Whether one hook runs for a given thread: a process- or thread-bound hook
/// only matches its target, and the skip flags exclude the installer's own.
/// # C: O(1)
pub fn runs_in_thread(hook: &Hook, target: HookThread) -> bool {
    if hook.process.is_some_and(|process| process != target.process) { return false; }
    if hook.flags & WINEVENT_SKIPOWNPROCESS != 0 && hook.process == Some(target.process) { return false; }
    if hook.thread.is_some_and(|thread| thread != target.thread) { return false; }
    if hook.flags & WINEVENT_SKIPOWNTHREAD != 0 && hook.thread == Some(target.thread) { return false; }
    true
}

/// A low-level hook runs in the thread that installed it, not in the hooked
/// thread; every other hook runs in the hooked thread. # C: O(1)
pub fn runs_in_owner_thread(hook: &Hook, current: u64) -> bool {
    matches!(hook.id, WH_KEYBOARD_LL | WH_MOUSE_LL) && hook.owner != current
}
