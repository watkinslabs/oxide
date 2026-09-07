//! Desktop-wide hook registry: one global table plus a table per thread, and
//! the chain walk that visits the calling thread's hooks before the global ones.
use super::*;
use alloc::vec::Vec;

/// Where one installed hook lives.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HookLocation { pub handle: u32, pub global: bool }

#[derive(Default)]
pub struct HookRegistry { global: HookTable, threads: Vec<(u64, HookTable)>, next_handle: u32 }

impl HookRegistry {
    /// # C: O(1)
    pub const fn new() -> Self { Self { global: HookTable::new(), threads: Vec::new(), next_handle: 1 } }

    fn table_mut(&mut self, scope: HookScope) -> Result<&mut HookTable, HookError> {
        let HookScope::Thread(thread) = scope else { return Ok(&mut self.global) };
        if let Some(index) = self.threads.iter().position(|(owner, _)| *owner == thread) {
            return Ok(&mut self.threads[index].1);
        }
        self.threads.try_reserve(1).map_err(|_| HookError::NoMemory)?;
        self.threads.push((thread, HookTable::new()));
        Ok(&mut self.threads.last_mut().expect("just pushed").1)
    }

    /// Install one hook into the scope its admission chose. Handles are unique
    /// across both scopes so a removal by handle never has to guess.
    /// # C: O(N_threads + N_hooks)
    pub fn install(&mut self, scope: HookScope, request: &HookRequest<'_>) -> Result<u32, HookError> {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.checked_add(1).ok_or(HookError::NoMemory)?;
        let table = self.table_mut(scope)?;
        let installed = table.install(request)?;
        table.rename(installed, handle)?;
        Ok(handle)
    }

    /// Remove one hook by handle from whichever scope holds it. # C: O(N_threads + N_hooks)
    pub fn remove(&mut self, handle: u32) -> Result<Hook, HookError> {
        if let Ok(hook) = self.global.remove(handle) { return Ok(hook); }
        for (_, table) in &mut self.threads {
            if let Ok(hook) = table.remove(handle) { return Ok(hook); }
        }
        Err(HookError::InvalidHandle)
    }

    /// Remove the calling thread's hook with a given identifier and procedure.
    /// # C: O(N_threads + N_hooks)
    pub fn remove_by_proc(&mut self, thread: u64, id: i32, proc_address: u64) -> Result<Hook, HookError> {
        let index = self.threads.iter().position(|(owner, _)| *owner == thread).ok_or(HookError::InvalidParameter)?;
        self.threads[index].1.remove_by_proc(id, proc_address)
    }

    /// One hook by handle. # C: O(N_threads + N_hooks)
    pub fn get(&self, handle: u32) -> Option<&Hook> {
        self.global.get(handle).or_else(|| self.threads.iter().find_map(|(_, table)| table.get(handle)))
    }

    /// Count of hooks one thread would run for an identifier, across both
    /// scopes. A zero count lets the caller skip the hook call entirely.
    /// # C: O(N_threads + N_hooks)
    pub fn chain_count(&self, id: i32, thread: HookThread) -> usize {
        let counts = |table: &HookTable| table.chain(id).filter(|hook| runs_in_thread(hook, thread)).count();
        counts(&self.global) + self.threads.iter().map(|(_, table)| counts(table)).sum::<usize>()
    }

    /// Walk one chain: the calling thread's own hooks first, then the global
    /// ones. `after` continues past a hook already called. # C: O(N_threads + N_hooks)
    pub fn next_hook(&self, id: i32, after: Option<u32>, thread: HookThread, event: u32) -> Option<HookLocation> {
        let own = self.threads.iter().find(|(owner, _)| *owner == thread.thread).map(|(_, table)| table);
        let in_own = after.is_some_and(|handle| own.is_some_and(|table| table.get(handle).is_some()));
        if let Some(table) = own {
            if after.is_none() || in_own {
                let resume = if in_own { after } else { None };
                if let Some(hook) = table.next_hook(id, resume, thread, event) {
                    return Some(HookLocation { handle: hook.handle, global: false });
                }
            }
        }
        let resume = if in_own { None } else { after };
        self.global.next_hook(id, resume, thread, event)
            .map(|hook| HookLocation { handle: hook.handle, global: true })
    }

    /// Drop every hook an exiting thread installed or targeted. # C: O(N_threads + N_hooks)
    pub fn cleanup_thread(&mut self, thread: u64) {
        self.threads.retain(|(owner, _)| *owner != thread);
        while let Some(handle) = self.global.chain_handles().into_iter()
            .find(|handle| self.global.get(*handle).is_some_and(|hook| hook.owner == thread || hook.thread == Some(thread))) {
            let _ = self.global.remove(handle);
        }
    }
}

#[cfg(test)]
#[path = "tests/registry.rs"]
mod tests;
