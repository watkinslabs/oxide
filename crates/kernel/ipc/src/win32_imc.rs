//! Input contexts (HIMC): user objects owned by the thread that created them,
//! associated with windows one at a time. The reference keeps one object per
//! context in the user handle table under the input-context object type, one
//! lazily created default context per thread, and the association on the
//! window record itself; this module owns exactly that state.

use alloc::vec::Vec;

/// `NtUserQueryInputContext` / `NtUserUpdateInputContext` attribute selectors.
pub const INPUT_CONTEXT_CLIENT_PTR: u32 = 0;
pub const INPUT_CONTEXT_THREAD_ID: u32 = 1;

/// `NtUserAssociateInputContext` results.
pub const AICR_OK: u32 = 0;
pub const AICR_FOCUS_CHANGED: u32 = 1;
pub const AICR_FAILED: u32 = 2;

/// `NtUserAssociateInputContext` flags.
pub const IACE_CHILDREN: u32 = 0x0001;
pub const IACE_DEFAULT: u32 = 0x0010;
pub const IACE_IGNORENOCONTEXT: u32 = 0x0020;

/// `NtUserDisableThreadIme` selector disabling every thread in the session.
pub const DISABLE_IME_ALL_THREADS: u64 = 0xffff_ffff;

/// A handle the input-context object type owns. Zero is never a handle.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ImcId(u32);

impl ImcId {
    /// # C: O(1)
    pub const fn from_raw(raw: u32) -> Option<Self> { if raw == 0 { None } else { Some(Self(raw)) } }
    /// # C: O(1)
    pub const fn raw(self) -> u32 { self.0 }
}

/// The two fields an input-context object carries.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InputContext { pub thread_id: u64, pub client_ptr: u64 }

/// A handle the object type does not own; the caller reports invalid-handle.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InvalidHandle;

/// Per-process input-context objects, thread defaults, and IME disable state.
#[derive(Default)]
pub struct InputContexts {
    next: u32,
    contexts: Vec<(ImcId, InputContext)>,
    defaults: Vec<(u64, ImcId)>,
    disabled_threads: Vec<u64>,
    all_threads_disabled: bool,
}

impl InputContexts {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { next: 1, contexts: Vec::new(), defaults: Vec::new(), disabled_threads: Vec::new(), all_threads_disabled: false }
    }

    /// Allocate one input-context object owned by `thread_id`. # C: O(1) amortised
    pub fn create(&mut self, thread_id: u64, client_ptr: u64) -> Option<ImcId> {
        if self.next == 0 { self.next = 1; }
        let id = ImcId::from_raw(self.next)?;
        self.next = self.next.checked_add(1)?;
        self.contexts.push((id, InputContext { thread_id, client_ptr }));
        Some(id)
    }

    /// Free one input-context object; an unknown handle fails. # C: O(N_contexts)
    pub fn destroy(&mut self, id: ImcId) -> bool {
        let Some(index) = self.contexts.iter().position(|(handle, _)| *handle == id) else { return false; };
        self.contexts.remove(index);
        self.defaults.retain(|(_, default)| *default != id);
        true
    }

    /// # C: O(N_contexts)
    pub fn get(&self, id: ImcId) -> Option<InputContext> {
        self.contexts.iter().find(|(handle, _)| *handle == id).map(|(_, context)| *context)
    }

    /// An attribute the object type does not name reads zero, matching the
    /// reference's unknown-attribute arm. # C: O(N_contexts)
    pub fn query(&self, id: ImcId, attr: u32) -> Result<u64, InvalidHandle> {
        let context = self.get(id).ok_or(InvalidHandle)?;
        Ok(match attr {
            INPUT_CONTEXT_CLIENT_PTR => context.client_ptr,
            INPUT_CONTEXT_THREAD_ID => context.thread_id,
            _ => 0,
        })
    }

    /// Ok(false) is an attribute the object type does not name, which the
    /// reference refuses without touching the object. # C: O(N_contexts)
    pub fn update(&mut self, id: ImcId, attr: u32, value: u64) -> Result<bool, InvalidHandle> {
        let Some((_, context)) = self.contexts.iter_mut().find(|(handle, _)| *handle == id) else { return Err(InvalidHandle); };
        match attr {
            INPUT_CONTEXT_CLIENT_PTR => { context.client_ptr = value; Ok(true) }
            _ => Ok(false),
        }
    }

    /// Handles owned by one thread, in allocation order, capped at `count`.
    /// # C: O(N_contexts)
    pub fn list(&self, thread_id: u64, count: usize) -> Vec<ImcId> {
        self.contexts.iter().filter(|(_, context)| context.thread_id == thread_id).map(|(handle, _)| *handle).take(count).collect()
    }

    /// The thread's default context, created on first use. # C: O(N_contexts)
    pub fn default_context(&mut self, thread_id: u64) -> Option<ImcId> {
        if let Some((_, id)) = self.defaults.iter().find(|(owner, _)| *owner == thread_id) { return Some(*id); }
        let id = self.create(thread_id, 0)?;
        self.defaults.push((thread_id, id));
        Some(id)
    }

    /// The thread's default context without creating one. # C: O(N_threads)
    pub fn existing_default(&self, thread_id: u64) -> Option<ImcId> {
        self.defaults.iter().find(|(owner, _)| *owner == thread_id).map(|(_, id)| *id)
    }

    /// `NtUserDisableThreadIme`: the all-threads selector disables the session,
    /// zero and the calling thread disable the caller, and any other thread is
    /// refused. # C: O(N_disabled_threads)
    pub fn disable_thread_ime(&mut self, current_tid: u64, thread_id: u64) -> bool {
        if thread_id == DISABLE_IME_ALL_THREADS { self.all_threads_disabled = true; }
        else if thread_id == 0 || thread_id == current_tid {
            if !self.disabled_threads.contains(&current_tid) { self.disabled_threads.push(current_tid); }
        }
        else { return false; }
        true
    }

    /// # C: O(N_disabled_threads)
    pub fn ime_disabled(&self, thread_id: u64) -> bool {
        self.all_threads_disabled || self.disabled_threads.contains(&thread_id)
    }

    /// Thread teardown destroys the thread's default context and forgets its
    /// IME-disable state, as the reference's thread cleanup does; contexts the
    /// client created explicitly are the client's to destroy. # C: O(N_contexts)
    pub fn cleanup_thread(&mut self, thread_id: u64) {
        if let Some(default) = self.existing_default(thread_id) { self.destroy(default); }
        self.disabled_threads.retain(|owner| *owner != thread_id);
    }
}

#[path = "win32_imc/associate.rs"]
mod associate;
pub use associate::{AssociateFacts, AssociateOutcome, WindowFacts, associate};

#[cfg(test)]
#[path = "win32_imc/tests.rs"]
mod tests;
