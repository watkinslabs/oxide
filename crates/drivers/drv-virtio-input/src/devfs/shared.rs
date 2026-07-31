use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as NodesLockClass};
use vfs::{File, Ino, Inode};

use crate::evdev_queue::{EvdevClientQueue, EventTimes, MAX_EVDEV};

pub(crate) const EVDEV_INO_BASE: Ino = 0x7400_0000;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvdevIdentity {
    pub device_key: input::VirtioChildDeviceKey,
    pub input_id: u32,
    pub evdev_id: u32,
    pub generation: u64,
}

/// Backend-private identity for one published `/dev/input/eventN` inode.
pub(crate) struct EvdevData {
    pub endpoint: Arc<EvdevEndpoint>,
}

struct ClientSlot {
    id: u64,
    queue: Arc<EvdevClientQueue>,
}

struct EndpointState {
    clients: Vec<ClientSlot>,
    grab: Option<u64>,
}

/// One Linux evdev object generation. Open files retain this exact object.
pub(crate) struct EvdevEndpoint {
    identity: EvdevIdentity,
    alive: AtomicBool,
    state: Spinlock<EndpointState, NodesLockClass>,
}

/// `file->private_data` for one evdev open file description.
pub(crate) struct EvdevOpen {
    endpoint: Arc<EvdevEndpoint>,
    client_id: u64,
    queue: Arc<EvdevClientQueue>,
}

static NEXT_ENDPOINT_GENERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) static EVDEV_ENDPOINTS: Spinlock<[Option<Arc<EvdevEndpoint>>; MAX_EVDEV], NodesLockClass> =
    Spinlock::new([const { None }; MAX_EVDEV]);

/// `id -> drv::Device` for model-owned evdev publication.
pub(crate) static EVDEV_DEVICES: Spinlock<[Option<Arc<drv::Device>>; MAX_EVDEV], NodesLockClass> =
    Spinlock::new([const { None }; MAX_EVDEV]);

impl EvdevEndpoint {
    /// # C: O(1)
    pub(crate) fn new(
        device_key: input::VirtioChildDeviceKey,
        input_id: u32,
        evdev_id: u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            identity: EvdevIdentity {
                device_key,
                input_id,
                evdev_id,
                generation: NEXT_ENDPOINT_GENERATION.fetch_add(1, Ordering::Relaxed),
            },
            alive: AtomicBool::new(true),
            state: Spinlock::new(EndpointState { clients: Vec::new(), grab: None }),
        })
    }

    /// # C: O(1)
    pub(crate) fn identity(&self) -> EvdevIdentity { self.identity }

    /// # C: O(1)
    pub(crate) fn is_alive(&self) -> bool { self.alive.load(Ordering::Acquire) }

    /// # C: O(open clients)
    pub(crate) fn open(self: &Arc<Self>) -> Option<EvdevOpen> {
        let queue = EvdevClientQueue::new();
        let id = NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed);
        let mut state = self.state.lock();
        if !self.alive.load(Ordering::Acquire) { return None; }
        state.clients.push(ClientSlot { id, queue: Arc::clone(&queue) });
        Some(EvdevOpen { endpoint: Arc::clone(self), client_id: id, queue })
    }

    /// # C: O(open clients × packet values)
    pub(crate) fn push_packet(&self, values: &[input::InputValue], times: EventTimes) {
        let state = self.state.lock();
        if !self.alive.load(Ordering::Acquire) { return; }
        if let Some(owner) = state.grab {
            if let Some(client) = state.clients.iter().find(|client| client.id == owner) {
                client.queue.push_packet(values, times);
            }
        } else {
            for client in state.clients.iter() {
                client.queue.push_packet(values, times);
            }
        }
    }

    /// # C: O(open clients)
    pub(crate) fn disconnect(&self) {
        let queues = {
            let mut state = self.state.lock();
            if !self.alive.load(Ordering::Acquire) { return; }
            state.grab = None;
            let queues = state.clients.drain(..).map(|client| client.queue).collect::<Vec<_>>();
            for queue in queues.iter() { queue.disconnect(); }
            self.alive.store(false, Ordering::Release);
            queues
        };
        drop(queues);
    }

    fn detach(&self, id: u64) {
        let mut state = self.state.lock();
        state.clients.retain(|client| client.id != id);
        if state.grab == Some(id) { state.grab = None; }
    }

    fn try_grab(&self, id: u64) -> bool {
        let mut state = self.state.lock();
        if !self.alive.load(Ordering::Acquire)
            || !state.clients.iter().any(|client| client.id == id)
            || state.grab.is_some()
        {
            return false;
        }
        state.grab = Some(id);
        true
    }

    fn ungrab(&self, id: u64) -> bool {
        let mut state = self.state.lock();
        if state.grab != Some(id) { return false; }
        state.grab = None;
        true
    }
}

impl EvdevOpen {
    /// # C: O(1)
    pub(crate) fn identity(&self) -> EvdevIdentity { self.endpoint.identity() }

    /// # C: O(1)
    pub(crate) fn is_live(&self) -> bool {
        self.endpoint.is_alive()
            && !self.queue.is_revoked()
            && !self.queue.is_disconnected()
    }

    /// # C: O(1)
    pub(crate) fn has_pending(&self) -> bool { !self.queue.is_empty() }

    /// # C: O(min(queued, dst / input-event size))
    pub(crate) fn try_pop_bytes(&self, dst: &mut [u8]) -> Option<usize> {
        self.queue.try_pop_bytes(dst)
    }

    /// # C: O(1)
    pub(crate) fn queue(&self) -> &EvdevClientQueue { &self.queue }

    /// # C: O(open clients)
    pub(crate) fn try_grab(&self) -> bool { self.endpoint.try_grab(self.client_id) }

    /// # C: O(1)
    pub(crate) fn ungrab(&self) -> bool { self.endpoint.ungrab(self.client_id) }

    /// # C: O(open clients)
    pub(crate) fn revoke(&self) {
        self.queue.revoke();
        self.endpoint.detach(self.client_id);
    }

    /// # C: O(bits + queued)
    pub(crate) fn copy_state_and_flush(
        &self,
        ev_type: u16,
        bits: &[u8],
        out: &mut [u8],
    ) -> usize {
        self.queue.copy_state_and_flush(ev_type, bits, out)
    }

    /// # C: O(queued)
    pub(crate) fn set_clock(&self, clock_id: i32) -> bool { self.queue.set_clock(clock_id) }

    /// # C: O(out)
    pub(crate) fn mask_get(&self, ev_type: u32, out: &mut [u8]) -> Option<usize> {
        self.queue.mask_get(ev_type, out)
    }

    /// # C: O(mask bytes)
    pub(crate) fn mask_set(&self, ev_type: u32, bytes: &[u8]) -> bool {
        self.queue.mask_set(ev_type, bytes)
    }
}

impl Drop for EvdevOpen {
    fn drop(&mut self) {
        self.endpoint.detach(self.client_id);
    }
}

/// Exact current endpoint for dispatch; old generations are never returned.
/// # C: O(1)
pub(crate) fn current_endpoint(id: u32) -> Option<Arc<EvdevEndpoint>> {
    EVDEV_ENDPOINTS.lock().get(id as usize)?.clone()
}

/// Reserve the eventN slot for one endpoint generation.
/// # C: O(1)
pub(crate) fn publish_endpoint(endpoint: Arc<EvdevEndpoint>) -> bool {
    let slot = endpoint.identity.evdev_id as usize;
    if slot >= MAX_EVDEV { return false; }
    let mut endpoints = EVDEV_ENDPOINTS.lock();
    if endpoints[slot].is_some() { return false; }
    endpoints[slot] = Some(endpoint);
    true
}

/// Remove and kill only the current endpoint generation.
/// # C: O(open clients)
pub(crate) fn unpublish_endpoint(id: u32) -> Option<Arc<EvdevEndpoint>> {
    let endpoint = EVDEV_ENDPOINTS.lock().get_mut(id as usize)?.take()?;
    endpoint.disconnect();
    Some(endpoint)
}

/// Roll back only the endpoint object supplied by the failed publisher.
/// # C: O(open clients)
pub(crate) fn unpublish_exact(endpoint: &Arc<EvdevEndpoint>) -> bool {
    let slot = endpoint.identity.evdev_id as usize;
    let removed = {
        let mut endpoints = EVDEV_ENDPOINTS.lock();
        let Some(current) = endpoints.get(slot).and_then(Option::as_ref) else {
            return false;
        };
        if !Arc::ptr_eq(current, endpoint) { return false; }
        endpoints[slot].take()
    };
    if let Some(removed) = removed { removed.disconnect(); }
    true
}

pub(crate) fn evdev_endpoint(inode: &Inode) -> Option<&Arc<EvdevEndpoint>> {
    inode.private::<EvdevData>().map(|data| &data.endpoint)
}

pub(crate) fn install_open(file: &File, opened: EvdevOpen) {
    let raw = Box::into_raw(Box::new(opened)) as u64;
    file.set_private_data(raw);
}

/// Borrow the exact evdev client owned by this open file description.
/// # C: O(1)
pub(crate) fn evdev_open(file: &File) -> Option<&EvdevOpen> {
    let raw = file.private_data();
    if raw == 0 { return None; }
    // SAFETY: install_open stores one live Box<EvdevOpen> until final File release.
    Some(unsafe { &*(raw as *const EvdevOpen) })
}

pub(crate) fn release_open(file: &File) {
    let raw = file.private_data();
    file.set_private_data(0);
    if raw == 0 { return; }
    // SAFETY: final File release consumes the unique Box installed by install_open.
    unsafe { drop(Box::from_raw(raw as *mut EvdevOpen)); }
}

#[cfg(test)]
const TEST_DEVICE_KEY_BASE_RAW: u32 = 0x7e00_0000;

#[cfg(test)]
pub(crate) fn test_endpoint(id: u32, input_id: u32) -> Arc<EvdevEndpoint> {
    EvdevEndpoint::new(
        input::VirtioChildDeviceKey::from_raw(TEST_DEVICE_KEY_BASE_RAW + id),
        input_id,
        id,
    )
}
