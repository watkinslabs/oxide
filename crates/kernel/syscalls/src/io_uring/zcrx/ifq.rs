// One zero-copy receive instance: the area, the refill queue, the device
// binding if there is one, and the notifications the caller armed.
//
// The instance holds the device's receive queues by `Arc`, and the queue holds
// the instance back through its memory-provider binding. That cycle is broken
// exactly once, by unbinding — which is why the ring's teardown unregisters
// every instance rather than relying on the instance being dropped.

use alloc::sync::{Arc, Weak};

use sync::{Spinlock, TaskList as RingLockClass};

use net::netdev::{NetDev, RxQueues};
use net::page_pool::{MemoryProvider, MpParams};

use crate::io_uring::ctx::IoUringInode;
use crate::io_uring_abi::zcrx::*;

use super::area::ZcrxArea;
use super::rq::ZcrxRq;

/// A live device receive-queue binding.
pub struct Binding {
    pub dev: Arc<dyn NetDev>,
    pub queues: Arc<RxQueues>,
    pub rxq: u32,
    pub params: MpParams,
}

/// Notification state — which types the caller armed, which have fired, and
/// the user data every notification carries.
#[derive(Clone, Copy, Default)]
pub struct NotifState {
    pub allowed: u32,
    pub fired: u32,
    pub user_data: u64,
}

pub struct ZcrxIfq {
    pub id: u32,
    pub area: ZcrxArea,
    pub rq: ZcrxRq,
    /// The queue this instance was registered against, or `u32::MAX` when it
    /// has no device.
    pub if_rxq: u32,
    pub binding: Spinlock<Option<Binding>, RingLockClass>,
    pub notif: Spinlock<NotifState, RingLockClass>,
    /// Rings still receiving through this instance. Distinct from the handle
    /// count that keeps the object allocated: an exported instance can be
    /// reachable through an open descriptor after every ring has let go, and
    /// closing its device queue then is what must NOT happen twice.
    pub users: UserHold,
    /// The ring notifications are posted to. Weak so the ring's own reference
    /// to this instance is the only strong one.
    pub ring: Weak<IoUringInode>,
}

impl ZcrxIfq {
    /// # C: O(1)
    pub fn new(id: u32, area: ZcrxArea, rq: ZcrxRq, ring: &Arc<IoUringInode>) -> Self {
        Self {
            id, area, rq, if_rxq: u32::MAX,
            binding: Spinlock::new(None),
            notif: Spinlock::new(NotifState::default()),
            users: UserHold::new(),
            ring: Arc::downgrade(ring),
        }
    }

    /// Record one more ring using this instance. False when the instance has
    /// already been let go by everyone — its queue is closed and its buffers
    /// reclaimed, so adopting it would hand a ring something that can never
    /// deliver a packet. # C: O(1)
    pub fn get_user(&self) -> bool { self.users.get() }

    /// One ring is finished with this instance. The LAST one closes the device
    /// queue and takes back every buffer the caller was still holding; the
    /// others change nothing, so an instance a second ring adopted survives its
    /// exporter going away. # C: O(1) plus the scrub on the last release
    pub fn put_user(&self) {
        if !self.users.put() { return; }
        self.close_queue();
        self.area.scrub();
    }

    /// Bytes one buffer spans. # C: O(1)
    pub fn rx_buf_len(&self) -> u32 { self.area.buf_len() as u32 }

    /// Arm the notification types the registration asked for. # C: O(1)
    pub fn set_notif(&self, allowed: u32, user_data: u64) {
        let mut g = self.notif.lock();
        g.allowed = allowed;
        g.user_data = user_data;
    }

    /// Post one notification, at most once per arming — Linux
    /// `zcrx_send_notif`. A notification that has already fired and not been
    /// re-armed is dropped rather than repeated: a caller that could not keep
    /// up would otherwise get one completion per failed allocation.
    /// # C: O(1)
    pub fn send_notif(&self, ty: u32) {
        let (send, user_data) = {
            let mut g = self.notif.lock();
            let bit = 1u32 << ty;
            if g.allowed & bit == 0 || g.fired & bit != 0 { (false, 0) } else {
                g.fired |= bit;
                (true, g.user_data)
            }
        };
        if !send { return; }
        let Some(ring) = self.ring.upgrade() else { return };
        ring.post_cqe(crate::io_uring::cqe::Cqe::big32(user_data, ty as i32, 0, [0; 2]));
    }

    /// Re-arm one notification type — Linux `zcrx_arm_notif`. A type that has
    /// not fired cannot be re-armed: the caller would be acknowledging
    /// something it was never told. # C: O(1)
    pub fn arm_notif(&self, ty: u32) -> Result<(), syscall::errno::Errno> {
        let mut g = self.notif.lock();
        let bit = 1u32 << ty;
        if bit & !g.fired != 0 { return Err(syscall::errno::Errno::Einval); }
        g.fired &= !bit;
        Ok(())
    }

    /// Return one buffer named by a refill entry, if the caller really held
    /// it and this was its last reference anywhere — Linux
    /// `zcrx_return_buffers`.
    ///
    /// The two counts are consumed in this order and no other: a caller
    /// reference is spent first, and only its loss lets the pool reference be
    /// touched. Reversed, a caller could return a buffer it had already
    /// returned and take it off the freelist while the stack still held it.
    /// # C: O(1)
    pub fn return_rqe(&self, rqe: &Rqe) -> bool {
        let Some(idx) = parse_rqe(rqe, self.area.niov_shift, self.area.num_niovs()) else {
            return false;
        };
        if self.area.refill(idx) != Refill::Freed { return false; }
        self.area.put_free(idx);
        true
    }

    /// Drain the refill queue, returning every buffer it names — Linux
    /// `zcrx_flush_rq`. # C: O(N_entries)
    pub fn flush_rq(&self) -> usize {
        const BATCH: usize = 32;
        let mut total = 0usize;
        loop {
            let n = self.rq.take(BATCH, |rqe| { self.return_rqe(&rqe); });
            total += n;
            if n < BATCH || total >= self.rq.nr_entries as usize { break; }
        }
        total
    }

    /// Take a buffer for the copy path — Linux `io_alloc_fallback_niov`. The
    /// buffer starts with exactly one pool reference, which the caller's own
    /// reference will outlive until a refill entry drops it. # C: O(1)
    pub fn alloc_fallback(&self) -> Option<u32> {
        let idx = self.area.get_free()?;
        self.area.nia.niovs[idx as usize].fragment(1);
        Some(idx)
    }

    /// Unbind the device queue, if one is bound. Idempotent: the ring's
    /// teardown and an explicit unregistration both reach it. # C: O(1)
    pub fn close_queue(&self) {
        let b = self.binding.lock().take();
        if let Some(b) = b {
            net::netdev::rx_queue::mp_close_rxq(&b.dev, &b.queues, b.rxq, &b.params);
        }
    }
}

impl Drop for ZcrxIfq {
    /// # C: O(1)
    fn drop(&mut self) { self.close_queue(); }
}

/// The provider handle a binding installs — an owning reference to the
/// instance, which is what the queue holds while it draws buffers from it.
/// # C: O(1)
pub fn provider_of(ifq: &Arc<ZcrxIfq>) -> Arc<dyn MemoryProvider> {
    Arc::clone(ifq) as Arc<dyn MemoryProvider>
}
