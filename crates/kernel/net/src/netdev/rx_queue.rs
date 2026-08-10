// A device's receive queues, and the memory provider one of them can be bound
// to.
//
// The binding is a property of the QUEUE, not of whoever asked for it: the
// queue holds the provider, the queue is what a close clears, and the queue's
// own lifetime — an `Arc` the binder keeps — is what stops a device
// unregistering out from under a live binding. That is why `RxQueues` is
// reference-counted and handed out rather than reached through the interface
// registry: a binder that had to re-look-up its interface could find the row
// gone and be left holding a provider nothing will ever release.
//
// Binding a queue restarts it, because the buffers already posted to the
// device came from the old allocator and the device must be made to re-post
// from the new one.

use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as SocketLockClass};

use super::{NetDev, NetError, NetResult};
use crate::page_pool::{MpParams, PagePool};

/// Device header/data split state — Linux `ETHTOOL_TCP_DATA_SPLIT_*`. A
/// provider can only be bound to a queue that puts payload in its own buffers,
/// because a provider buffer holding protocol headers would expose them to
/// whoever the provider hands the buffer to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HdsConfig { Unknown, Disabled, Enabled }

/// What the admission ladder needs to know about a device.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct QueueCaps {
    /// Whether the device can stop, re-provision and restart one queue.
    pub queue_mgmt: bool,
    /// `real_num_rx_queues`.
    pub nr_rx_queues: u32,
    pub hds: HdsConfig,
    pub hds_thresh: u32,
    /// Programs attached to the device's receive hook.
    pub xdp_progs: u32,
    /// Whether the device accepts a caller-chosen receive buffer size.
    pub rx_page_size_ok: bool,
}

/// Admit, or refuse, binding a provider to queue `idx` — the reference's
/// ladder, in its order, which is what decides WHICH errno a caller gets when
/// more than one rung would fail:
///
/// | rung | errno |
/// |---|---|
/// | device cannot manage its queues | `EOPNOTSUPP` |
/// | queue index past the device's queues | `ERANGE` |
/// | header/data split not enabled | `EINVAL` |
/// | a non-zero split threshold | `EINVAL` |
/// | a program attached to the receive hook | `EEXIST` |
/// | a buffer size asked of a device that cannot be told | `EOPNOTSUPP` |
/// | the queue already has a provider | `EEXIST` |
/// # C: O(1)
pub fn admit_mp_open(caps: &QueueCaps, idx: u32, want_rx_page_size: bool, already_bound: bool)
    -> NetResult<()>
{
    if !caps.queue_mgmt { return Err(NetError::Eopnotsupp); }
    if idx >= caps.nr_rx_queues { return Err(NetError::Erange); }
    if caps.hds != HdsConfig::Enabled { return Err(NetError::Einval); }
    if caps.hds_thresh != 0 { return Err(NetError::Einval); }
    if caps.xdp_progs != 0 { return Err(NetError::Eexist); }
    if want_rx_page_size && !caps.rx_page_size_ok { return Err(NetError::Eopnotsupp); }
    if already_bound { return Err(NetError::Eexist); }
    Ok(())
}

/// One receive queue.
pub struct RxQueue {
    bound: Spinlock<Option<Binding>, SocketLockClass>,
}

struct Binding {
    params: MpParams,
    pool: Arc<PagePool>,
}

impl RxQueue {
    /// # C: O(1)
    fn new() -> Self { Self { bound: Spinlock::new(None) } }

    /// The pool this queue draws buffers from, if a provider is bound.
    /// # C: O(1)
    pub fn pool(&self) -> Option<Arc<PagePool>> {
        self.bound.lock().as_ref().map(|b| Arc::clone(&b.pool))
    }

    /// Whether a provider is bound — Linux `netif_rxq_has_mp`. # C: O(1)
    pub fn has_mp(&self) -> bool { self.bound.lock().is_some() }
}

/// A device's whole receive-queue array.
pub struct RxQueues {
    queues: Vec<RxQueue>,
}

impl RxQueues {
    /// # C: O(n)
    pub fn new(n: u32) -> Self {
        let mut queues = Vec::new();
        let n = n.max(1) as usize;
        queues.reserve_exact(n);
        for _ in 0..n { queues.push(RxQueue::new()); }
        Self { queues }
    }

    /// # C: O(1)
    pub fn len(&self) -> u32 { self.queues.len() as u32 }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.queues.is_empty() }
    /// # C: O(1)
    pub fn get(&self, idx: u32) -> Option<&RxQueue> { self.queues.get(idx as usize) }
}

/// Read a device's queue capabilities. # C: O(1)
pub fn caps_of(dev: &Arc<dyn NetDev>) -> QueueCaps {
    QueueCaps {
        queue_mgmt: dev.rx_queue_mgmt(),
        nr_rx_queues: dev.rx_queue_count(),
        hds: dev.hds_config(),
        hds_thresh: dev.hds_thresh(),
        xdp_progs: dev.rx_hook_prog_count(),
        rx_page_size_ok: dev.rx_page_size_supported(),
    }
}

/// Bind `p` to queue `idx` — Linux `netif_mp_open_rxq`.
///
/// Nothing is published until the pool exists: the provider's own `init` is
/// the last rung that can refuse, and a refused init leaves the queue exactly
/// as it was. The queue restart runs with the binding in place, because the
/// device re-provisions from the new pool. A restart that fails un-binds, so a
/// device that could not be re-provisioned is never left claiming a provider
/// it does not draw from. # C: O(1) plus the device's restart
pub fn mp_open_rxq(dev: &Arc<dyn NetDev>, qs: &Arc<RxQueues>, idx: u32, p: &MpParams)
    -> NetResult<Arc<PagePool>>
{
    let caps = caps_of(dev);
    let q = qs.get(idx).ok_or(NetError::Erange)?;
    let already = q.has_mp();
    admit_mp_open(&caps, idx, p.rx_page_size != 0, already)?;

    let pool = PagePool::create(p)?;
    {
        let mut g = q.bound.lock();
        // Re-checked under the lock the install uses: the test above and this
        // are the same rule, and only this one is race-free.
        if g.is_some() { drop(g); pool.destroy(); return Err(NetError::Eexist); }
        *g = Some(Binding { params: p.clone(), pool: Arc::clone(&pool) });
    }
    if let Err(e) = dev.rx_queue_restart(idx) {
        let _ = q.bound.lock().take();
        pool.destroy();
        return Err(e);
    }
    Ok(pool)
}

/// Unbind `old` from queue `idx` — Linux `netif_mp_close_rxq`.
///
/// The identity check is load-bearing: a binder that raced a device teardown
/// can arrive after the queue was already cleared and re-bound by someone
/// else, and clearing the queue then would strand the new binding.
/// # C: O(1) plus the device's restart
pub fn mp_close_rxq(dev: &Arc<dyn NetDev>, qs: &Arc<RxQueues>, idx: u32, old: &MpParams) {
    let Some(q) = qs.get(idx) else { return };
    let taken = {
        let mut g = q.bound.lock();
        match g.as_ref() {
            Some(b) if b.params.same(old) => g.take(),
            _ => None,
        }
    };
    let Some(b) = taken else { return };
    // The device stops drawing from the pool before the pool is torn down.
    let _ = dev.rx_queue_restart(idx);
    b.pool.destroy();
    old.ops.uninstall();
}

/// Clear every binding on a device that is going away, telling each provider
/// its queue is gone — Linux `dev_memory_provider_uninstall`. A provider that
/// outlives its device learns it here rather than by finding an empty queue
/// later. # C: O(N_queues)
pub fn uninstall_all(qs: &Arc<RxQueues>) {
    for q in qs.queues.iter() {
        let taken = q.bound.lock().take();
        if let Some(b) = taken { b.pool.destroy(); b.params.ops.uninstall(); }
    }
}

#[cfg(test)]
#[path = "rx_queue/tests.rs"]
mod tests;
