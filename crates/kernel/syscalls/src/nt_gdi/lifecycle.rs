//! Sleepable canonical GDI/client lifetime transactions (`31gf`).

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::client::{self, ClientBinding, ClientError};
use ipc::win32_gdi::TextState;

#[path = "lifecycle/transaction.rs"]
mod transaction;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError<E> { Gate, Client(ClientError), Canonical(E), Rollback(E) }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialObject {
    Handle { handle: u32, process_id: u16 },
    Dc { handle: u32, process_id: u16, state: TextState },
}

/// Main builds this transiently from the canonical owner while its GDI lock is
/// held, then drops that lock before calling initialization. It is not an
/// object registry and is mandatory: initialization fails rather than
/// publishing a PEB that omits existing canonical objects.
#[derive(Clone, Debug, Default)]
pub struct InitialProjectionPlan { objects: Vec<InitialObject> }

impl InitialProjectionPlan {
    pub fn new(objects: Vec<InitialObject>) -> Self { Self { objects } }
    pub fn objects(&self) -> &[InitialObject] { &self.objects }
}

/// Per-process sleepable lifetime gate. Do not call while holding GDI's
/// spinlock; canonical closures acquire that lock only for their owner step.
pub struct ClientGate { group: Arc<sched::thread_group::ThreadGroup>, tid: u64 }

impl ClientGate {
    pub fn acquire_current() -> Result<Self, ClientError> {
        let current = sched::live::current().ok_or(ClientError::NoCurrentProcess)?;
        if !current.is_nt_personality() || current.tid == 0 { return Err(ClientError::NoCurrentProcess); }
        let tid = current.tid as u64;
        let outcome = unsafe { current.thread_group.nt_peb_lock.wait(tid, 0, timekeeper::monotonic_ns) };
        if outcome != sched::WaitOutcome::Ready { return Err(ClientError::InvalidBinding); }
        Ok(Self { group: Arc::clone(&current.thread_group), tid })
    }

}

impl Drop for ClientGate {
    fn drop(&mut self) { let _ = self.group.nt_peb_lock.release(self.tid); }
}

pub(super) fn entry_for_current(entries: &mut Vec<super::GdiEntry>, group: &Arc<sched::thread_group::ThreadGroup>) -> Result<usize, ClientError> {
    if let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, group))) {
        return Ok(index);
    }
    entries.push(super::new_entry(group));
    Ok(entries.len() - 1)
}

pub fn create_dc_for_current(width: i32, height: i32) -> Result<u32, LifecycleError<ipc::win32_gdi::GdiError>> {
    let gate = ClientGate::acquire_current().map_err(LifecycleError::Client)?;
    let current = sched::live::current().ok_or(LifecycleError::Client(ClientError::NoCurrentProcess))?;
    let group = Arc::clone(&current.thread_group);
    let bound = {
        let mut entries = super::GDI.lock();
        let index = entry_for_current(&mut entries, &group).map_err(LifecycleError::Client)?;
        entries[index].client.is_some()
    };
    let pid = bound.then(|| client::current_process_id()).transpose().map_err(LifecycleError::Client)?;
    let (binding, handle, state) = {
        let mut entries = super::GDI.lock();
        let index = entry_for_current(&mut entries, &group).map_err(LifecycleError::Client)?;
        let binding = entries[index].client;
        let handle = entries[index].state.create_dc(width, height).map_err(LifecycleError::Canonical)?;
        let state = entries[index].state.text_state(handle).map_err(LifecycleError::Canonical)?;
        (binding, handle, state)
    };
    if let (Some(binding), Some(pid)) = (binding, pid) {
      if let Err(error) = publish_or_rollback(
          binding, handle,
          || binding.publish_dc_state(handle, pid, state),
          || { let mut entries = super::GDI.lock(); let index = entry_for_current(&mut entries, &group).map_err(|_| ipc::win32_gdi::GdiError::NoSuchObject)?; entries[index].state.delete_object(handle) }) {
        return Err(error);
      }
    }
    drop(gate);
    Ok(handle)
}

enum RollbackFailure<E> { Projection(ClientError), Canonical(E) }

pub(super) fn publish_or_rollback<E>(binding: ClientBinding, handle: u32,
    publish: impl FnOnce() -> Result<(), ClientError>, canonical_rollback: impl FnOnce() -> Result<(), E>) -> Result<(), LifecycleError<E>> {
    let rollback = || {
        let projection = binding.delete_handle(handle);
        let canonical = canonical_rollback();
        match (projection, canonical) {
            (Err(error), _) => Err(RollbackFailure::Projection(error)),
            (Ok(()), Err(error)) => Err(RollbackFailure::Canonical(error)),
            (Ok(()), Ok(())) => Ok(()),
        }
    };
    match transaction::publish_or_rollback(publish, rollback) {
        Ok(()) => Ok(()),
        Err(transaction::TransactionError::Publish(error)) => Err(LifecycleError::Client(error)),
        Err(transaction::TransactionError::Rollback(RollbackFailure::Projection(error))) => Err(LifecycleError::Client(error)),
        Err(transaction::TransactionError::Rollback(RollbackFailure::Canonical(error))) => Err(LifecycleError::Rollback(error)),
    }
}

pub fn create_font_for_current(font: ipc::win32_gdi::Font) -> Result<u32, LifecycleError<ipc::win32_gdi::GdiError>> {
    let record = ipc::win32_gdi::FontRecord::from_font(font).map_err(LifecycleError::Canonical)?;
    create_font_record_for_current(record)
}

pub fn create_font_record_for_current(record: ipc::win32_gdi::FontRecord) -> Result<u32, LifecycleError<ipc::win32_gdi::GdiError>> {
    let gate = ClientGate::acquire_current().map_err(LifecycleError::Client)?;
    let current = sched::live::current().ok_or(LifecycleError::Client(ClientError::NoCurrentProcess))?;
    let group = Arc::clone(&current.thread_group);
    let bound = {
        let mut entries = super::GDI.lock();
        let index = entry_for_current(&mut entries, &group).map_err(LifecycleError::Client)?;
        entries[index].client.is_some()
    };
    let pid = bound.then(|| client::current_process_id()).transpose().map_err(LifecycleError::Client)?;
    let (binding, handle) = {
        let mut entries = super::GDI.lock();
        let index = entry_for_current(&mut entries, &group).map_err(LifecycleError::Client)?;
        let binding = entries[index].client;
        let handle = entries[index].state.create_font_record(record).map_err(LifecycleError::Canonical)?;
        (binding, handle)
    };
    if let (Some(binding), Some(pid)) = (binding, pid) {
        if let Err(error) = publish_or_rollback(
            binding, handle,
            || binding.publish_handle(handle, pid),
            || { let mut entries = super::GDI.lock(); let index = entry_for_current(&mut entries, &group).map_err(|_| ipc::win32_gdi::GdiError::NoSuchObject)?; entries[index].state.delete_font(handle) }) {
            return Err(error);
        }
    }
    drop(gate);
    Ok(handle)
}

pub fn select_font_for_current(dc: u32, font: u32) -> Result<u32, LifecycleError<ipc::win32_gdi::GdiError>> {
    let gate = ClientGate::acquire_current().map_err(LifecycleError::Client)?;
    let current = sched::live::current().ok_or(LifecycleError::Client(ClientError::NoCurrentProcess))?;
    let group = Arc::clone(&current.thread_group);
    let (binding, previous, removed) = {
        let mut entries = super::GDI.lock();
        let index = entry_for_current(&mut entries, &group).map_err(LifecycleError::Client)?;
        let binding = entries[index].client;
        let before = entries[index].state.live_handles();
        let previous = entries[index].state.select_font(dc, font).map_err(LifecycleError::Canonical)?;
        let after = entries[index].state.live_handles();
        let removed = before.into_iter().filter(|candidate| !after.contains(candidate)).collect::<Vec<_>>();
        (binding, previous, removed)
    };
    if let Some(binding) = binding {
        for handle in removed { binding.delete_handle(handle).map_err(LifecycleError::Client)?; }
    }
    drop(gate);
    Ok(previous)
}

pub fn acquire_window_dc_for_current(hwnd: u32, width: i32, height: i32) -> Result<u32, LifecycleError<ipc::win32_gdi::GdiError>> {
    let gate = ClientGate::acquire_current().map_err(LifecycleError::Client)?;
    let current = sched::live::current().ok_or(LifecycleError::Client(ClientError::NoCurrentProcess))?;
    let group = Arc::clone(&current.thread_group);
    let bound = {
        let mut entries = super::GDI.lock();
        let index = entry_for_current(&mut entries, &group).map_err(LifecycleError::Client)?;
        entries[index].client.is_some()
    };
    let pid = bound.then(|| client::current_process_id()).transpose().map_err(LifecycleError::Client)?;
    let (binding, prior, handle, state) = {
        let mut entries = super::GDI.lock();
        let index = entry_for_current(&mut entries, &group).map_err(LifecycleError::Client)?;
        let binding = entries[index].client;
        let prior = entries[index].state.window_dc(hwnd);
        let handle = entries[index].state.acquire_window_dc(hwnd, width, height).map_err(LifecycleError::Canonical)?;
        let state = entries[index].state.text_state(handle).map_err(LifecycleError::Canonical)?;
        (binding, prior, handle, state)
    };
    if let Some(binding) = binding {
      if prior.is_some() {
        if prior != Some(handle) { return Err(LifecycleError::Client(ClientError::InvalidBinding)); }
        binding.update_dc_dimensions(handle, state.width, state.height).map_err(LifecycleError::Client)?;
      } else {
        let pid = pid.ok_or(LifecycleError::Client(ClientError::InvalidBinding))?;
        if let Err(error) = publish_or_rollback(
            binding,
            handle,
            || binding.publish_dc_state(handle, pid, state),
            || {
                let mut entries = super::GDI.lock();
                let index = entry_for_current(&mut entries, &group)
                    .map_err(|_| ipc::win32_gdi::GdiError::NoSuchObject)?;
                entries[index].state.destroy_window_dc(hwnd)
            },
        ) {
            return Err(error);
        }
      }
    }
    drop(gate);
    Ok(handle)
}

pub fn delete_object_for_current(handle: u32) -> Result<(), LifecycleError<ipc::win32_gdi::GdiError>> {
    let gate = ClientGate::acquire_current().map_err(LifecycleError::Client)?;
    let current = sched::live::current().ok_or(LifecycleError::Client(ClientError::NoCurrentProcess))?;
    let group = Arc::clone(&current.thread_group);
    let (binding, removed) = {
        let mut entries = super::GDI.lock();
        let index = entry_for_current(&mut entries, &group).map_err(LifecycleError::Client)?;
        let binding = entries[index].client;
        let before = entries[index].state.live_handles();
        entries[index].state.delete_object(handle).map_err(LifecycleError::Canonical)?;
        let after = entries[index].state.live_handles();
        let removed = before.into_iter().filter(|candidate| !after.contains(candidate)).collect::<Vec<_>>();
        (binding, removed)
    };
    if let Some(binding) = binding {
        for removed_handle in removed { binding.delete_handle(removed_handle).map_err(LifecycleError::Client)?; }
    }
    drop(gate);
    Ok(())
}

pub fn destroy_window_dc_for_current(hwnd: u32, handle: u32) -> Result<(), LifecycleError<ipc::win32_gdi::GdiError>> {
    let gate = ClientGate::acquire_current().map_err(LifecycleError::Client)?;
    let current = sched::live::current().ok_or(LifecycleError::Client(ClientError::NoCurrentProcess))?;
    let group = Arc::clone(&current.thread_group);
    let (binding, removed) = {
        let mut entries = super::GDI.lock();
        let index = entry_for_current(&mut entries, &group).map_err(LifecycleError::Client)?;
        let binding = entries[index].client;
        if entries[index].state.window_dc(hwnd) != Some(handle) {
            return Err(LifecycleError::Canonical(ipc::win32_gdi::GdiError::NoSuchObject));
        }
        let before = entries[index].state.live_handles();
        entries[index].state.destroy_window_dc(hwnd).map_err(LifecycleError::Canonical)?;
        let after = entries[index].state.live_handles();
        let removed = before.into_iter().filter(|candidate| !after.contains(candidate)).collect::<Vec<_>>();
        (binding, removed)
    };
    if let Some(binding) = binding {
        for removed_handle in removed { binding.delete_handle(removed_handle).map_err(LifecycleError::Client)?; }
    }
    drop(gate);
    Ok(())
}

/// Collect the canonical owner snapshot, publish every live object (including
/// stocks), then install the binding in the one `GdiEntry` before releasing
/// the process gate. The client table is never used to decide liveness.
pub fn initialize_for_current() -> Result<(), ClientError> {
    let gate = ClientGate::acquire_current()?;
    let current = sched::live::current().ok_or(ClientError::NoCurrentProcess)?;
    let group = Arc::clone(&current.thread_group);
    let process_id = client::current_process_id()?;
    let peb = current.nt_peb();
    let peb_slot = peb.checked_add(syscall::nt_gdi_client::PEB_TABLE_OFFSET).ok_or(ClientError::InvalidBinding)?;
    let pointer = uaccess::get_user_u64(peb_slot).map_err(|_| ClientError::UserCopy)?;
    let plan = {
        let mut entries = super::GDI.lock();
        let index = match entry_for_current(&mut entries, &group) {
            Ok(index) => index,
            Err(_) => { entries.push(super::new_entry(&group)); entries.len() - 1 }
        };
        if let Some(binding) = entries[index].client {
            if pointer != binding.table_base { return Err(ClientError::ForeignTable); }
            return Ok(());
        }
        if pointer != 0 { return Err(ClientError::ForeignTable); }
        let handles = entries[index].state.live_handles();
        let mut objects = Vec::new();
        for handle in handles {
            let base_type = ((handle & syscall::nt_gdi_client::HANDLE_TYPE_MASK) >> 16) & 0x1f;
            if base_type == 1 {
                let state = entries[index].state.text_state(handle).map_err(|_| ClientError::InvalidBinding)?;
                objects.push(InitialObject::Dc { handle, process_id, state });
            } else {
                objects.push(InitialObject::Handle { handle, process_id });
            }
        }
        InitialProjectionPlan::new(objects)
    };
    let binding = initialize_client_for_current_with_gate(&gate, &plan)?;
    {
        let mut entries = super::GDI.lock();
        let index = entry_for_current(&mut entries, &group)?;
        if entries[index].client.is_some() { return Err(ClientError::ForeignTable); }
        entries[index].client = Some(binding);
    }
    drop(gate);
    Ok(())
}

/// Use this when the caller already owns the process PEB gate. It never waits
/// recursively on `nt_peb_lock`.
fn initialize_client_for_current_with_gate(_gate: &ClientGate, plan: &InitialProjectionPlan) -> Result<ClientBinding, ClientError> {
    if plan.objects().is_empty() { return Err(ClientError::InvalidBinding); }
    let current = sched::live::current().ok_or(ClientError::NoCurrentProcess)?;
    if current.nt_peb() == 0 { return Err(ClientError::NoCurrentProcess); }
    let peb_slot = current.nt_peb().checked_add(syscall::nt_gdi_client::PEB_TABLE_OFFSET).ok_or(ClientError::InvalidBinding)?;
    if uaccess::get_user_u64(peb_slot).map_err(|_| ClientError::UserCopy)? != 0 { return Err(ClientError::ForeignTable); }
    let binding = allocate_unpublished()?;
    for object in plan.objects() {
        let result = match *object {
            InitialObject::Handle { handle, process_id } => binding.publish_handle_unchecked(handle, process_id),
            InitialObject::Dc { handle, process_id, state } => binding.publish_dc_unchecked(handle, process_id, state.width, state.height,
                syscall::nt_gdi_client::DcText { foreground: state.attributes.foreground, background: state.attributes.background,
                    alignment: state.attributes.alignment, background_mode: state.attributes.background_mode,
                    current_position: state.attributes.current_position }),
        };
        if let Err(error) = result {
            let _ = free_unpublished(&binding, current);
            return Err(error);
        }
    }
    if let Err(error) = binding.claim_peb() {
        let _ = free_unpublished(&binding, current);
        return Err(error);
    }
    Ok(binding)
}

fn allocate_unpublished() -> Result<ClientBinding, ClientError> {
    let current = sched::live::current().ok_or(ClientError::NoCurrentProcess)?;
    let mm = current.clone_mm().ok_or(ClientError::NoAddressSpace)?;
    let table = super::client::memory::allocate(&mm, syscall::nt_gdi_client::TABLE_BYTES)?;
    let attrs = match super::client::memory::allocate(&mm, syscall::nt_gdi_client::DC_ATTR_BYTES) {
        Ok(value) => value,
        Err(error) => { let _ = super::client::memory::free(&mm, table, syscall::nt_gdi_client::TABLE_BYTES); return Err(error); }
    };
    if let Err(error) = super::client::memory::zero(table, syscall::nt_gdi_client::TABLE_BYTES)
        .and_then(|_| super::client::memory::zero(attrs, syscall::nt_gdi_client::DC_ATTR_BYTES)) {
        let _ = super::client::memory::free(&mm, attrs, syscall::nt_gdi_client::DC_ATTR_BYTES);
        let _ = super::client::memory::free(&mm, table, syscall::nt_gdi_client::TABLE_BYTES);
        return Err(error);
    }
    Ok(ClientBinding { table_base: table, attr_base: attrs, table_bytes: syscall::nt_gdi_client::TABLE_BYTES,
        attr_bytes: syscall::nt_gdi_client::DC_ATTR_BYTES, attr_stride: syscall::nt_gdi_client::DC_ATTR_SIZE })
}

fn free_unpublished(binding: &ClientBinding, current: &sched::Task) -> Result<(), ClientError> {
    let mm = current.clone_mm().ok_or(ClientError::NoAddressSpace)?;
    super::client::memory::free(&mm, binding.attr_base, binding.attr_bytes)?;
    super::client::memory::free(&mm, binding.table_base, binding.table_bytes)
}
