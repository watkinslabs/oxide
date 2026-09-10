//! Active chain walks retain removed cursor records until the last walker finishes.
use super::*;

impl HookTable {
    pub(super) fn retain_chain(&mut self, index: usize) -> Result<(), HookError> {
        self.active[index] = self.active[index].checked_add(1).ok_or(HookError::NoMemory)?;
        Ok(())
    }

    pub(super) fn release_chain(&mut self, index: usize) {
        if self.active[index] == 0 { return; }
        self.active[index] -= 1;
        if self.active[index] == 0 {
            self.hooks.retain(|hook| chain_index(hook.id) != Some(index) || hook.proc_address != 0);
        }
    }

    pub(super) fn retire(&mut self, index: usize) -> Hook {
        let hook = &self.hooks[index];
        if self.active[chain_index(hook.id).expect("installed hook identifier")] == 0 { return self.hooks.remove(index); }
        let cursor = Hook { handle: hook.handle, id: hook.id, process: hook.process, thread: hook.thread,
            owner: hook.owner, event_min: hook.event_min, event_max: hook.event_max, flags: hook.flags,
            proc_address: 0, unicode: hook.unicode, module: Vec::new() };
        core::mem::replace(&mut self.hooks[index], cursor)
    }
}

impl HookRegistry {
    /// Retain both scopes a caller's walk can visit. # C: O(N_threads)
    pub fn hold_chain(&mut self, id: i32, caller: HookThread) -> Result<ChainLease, HookError> {
        let index = chain_index(id).ok_or(HookError::InvalidParameter)?;
        self.global.retain_chain(index)?;
        let local = self.threads.iter_mut().find(|(thread, _)| *thread == caller.thread);
        let held_local = local.is_some();
        if let Some((_, table)) = local {
            if let Err(error) = table.retain_chain(index) { self.global.release_chain(index); return Err(error); }
        }
        Ok(ChainLease { index, thread: caller.thread, local: held_local })
    }

    /// Release a completed walk; reclaim deleted hooks after its last peer.
    /// # C: O(N_threads + N_hooks)
    pub fn release_chain(&mut self, lease: ChainLease) {
        self.global.release_chain(lease.index);
        if lease.local {
            if let Some((_, table)) = self.threads.iter_mut().find(|(thread, _)| *thread == lease.thread) {
                table.release_chain(lease.index);
            }
        }
    }
}
