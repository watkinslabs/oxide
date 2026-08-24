// The virtio face of a FUSE connection.
//
// virtiofs is FUSE with a different courier. One request occupies one
// descriptor chain: the encoded `fuse_in_header` plus body as a device-READABLE
// run, then the reply staging buffer as a device-WRITABLE run. Nothing here
// knows what a FUSE opcode means — the connection above the seam owns all of
// that, and owns it exactly once for both transports.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Weak;
use alloc::vec::Vec;

use fuse_transport::{FuseReplySink, FuseTransportOps};
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::consts::{BUFFER_BYTES, COMPLETION_POLL_BUDGET, REQUEST_QUEUE};
use crate::registry::{self, DeviceHandle};

/// Bytes of a `fuse_out_header`: `len[4] error[4] unique[8]`. A reply shorter
/// than this carries no `unique` and can be matched to nothing.
const FUSE_OUT_HEADER_SIZE: usize = 16;

/// Which queue a message goes on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd)]
enum Lane {
    /// Ordinary request; a reply is expected.
    Request,
    /// FORGET or INTERRUPT: no reply, and it must not queue behind a request a
    /// caller is blocked on.
    HiPrio,
}

/// A FUSE connection bound to one virtiofs device.
pub struct VirtioFsTransport {
    device_key: virtio::VirtioChildDeviceKey,
    dev: DeviceHandle,
    sink: Spinlock<Option<Weak<dyn FuseReplySink>>, DriverLockClass>,
    /// Serialises only queue publication and used-ring retirement. Request
    /// buffers are private, so the device wait happens outside it.
    queue: Spinlock<(), DriverLockClass>,
    inflight: Spinlock<InFlight, DriverLockClass>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct RequestKey { queue: u16, lane: Lane, head: u16 }

struct InFlight {
    pending: BTreeMap<RequestKey, registry::RequestStaging>,
    completed: BTreeMap<RequestKey, Vec<u8>>,
}

enum Polled { None, Other, Complete(Option<Vec<u8>>), Failed }

impl VirtioFsTransport {
    /// Claim the device named `tag`. `None` when no device carries that tag or
    /// a mount already holds it. # C: O(N_devices)
    pub fn claim(tag: &str) -> Option<alloc::sync::Arc<Self>> {
        let dev = registry::claim(tag)?;
        let device_key = dev.lock().device_key;
        Some(alloc::sync::Arc::new(Self {
            device_key, dev, sink: Spinlock::new(None),
            queue: Spinlock::new(()),
            inflight: Spinlock::new(InFlight { pending: BTreeMap::new(), completed: BTreeMap::new() }),
        }))
    }

    /// The device this connection speaks to. # C: O(1)
    pub fn device_key(&self) -> virtio::VirtioChildDeviceKey { self.device_key }

    /// Place `out` on `lane` and, for a lane that expects one, collect the
    /// reply frame. Each descriptor owns private DMA buffers until its own
    /// used entry retires, so concurrent requests do not overwrite one another.
    fn exchange(&self, out: &[u8], lane: Lane) -> Option<Vec<u8>> {
        if out.len() > BUFFER_BYTES { return None; }
        let staging = registry::alloc_request_staging(self.device_key)?;
        let queue_index = if lane == Lane::HiPrio { 0 } else { self.select_request_queue() };
        let key = {
            let _queue = self.queue.lock();
            let mut s = self.dev.lock();
            if s.shutdown { registry::free_request_staging(staging); return None; }
            let hhdm = s.hhdm;

            let tx = hhdm.wrapping_add(staging.tx_pa) as *mut u8;
            // SAFETY: this request owns its private staging frame until the
            // matching used entry retires; `out` was size-checked above.
            unsafe { for (i, b) in out.iter().enumerate() { core::ptr::write_volatile(tx.add(i), *b); } }
            virtio::dma::clean_to_device(hhdm.wrapping_add(staging.tx_pa), out.len());

            let q = match lane {
                Lane::Request => s.requestq.iter_mut().find(|(index, _)| *index == queue_index).map(|(_, q)| q),
                Lane::HiPrio => s.hiprioq.as_mut(),
            };
            let Some(q) = q else { registry::free_request_staging(staging); return None; };
            let readable = virtio::SplitQueueSeg { dma: staging.tx_dma, len: out.len() as u32, device_writes: false };
            let writable = virtio::SplitQueueSeg { dma: staging.rx_dma, len: BUFFER_BYTES as u32, device_writes: true };
            let head = match lane {
                Lane::Request => q.submit(&[readable, writable]),
                Lane::HiPrio => q.submit(&[readable]),
            };
            let Ok(head) = head else { registry::free_request_staging(staging); return None; };
            let key = RequestKey { queue: queue_index, lane, head };
            self.inflight.lock().pending.insert(key, staging);
            key
        };

        #[cfg(target_os = "oxide-kernel")]
        let deadline = registry::now_ns().saturating_add(5_000_000_000);
        for _ in 0..COMPLETION_POLL_BUDGET {
            match self.poll_one(key) {
                Polled::Complete(frame) => return frame,
                Polled::Other => core::hint::spin_loop(),
                Polled::None => {
                    #[cfg(target_os = "oxide-kernel")]
                    if !self.wait_for_used(key.lane, key.queue, deadline) { return None; }
                    #[cfg(not(target_os = "oxide-kernel"))]
                    core::hint::spin_loop();
                }
                Polled::Failed => return None,
            }
        }
        // Keep pending ownership until the device retires the descriptor.
        None
    }

    fn poll_one(&self, wanted: RequestKey) -> Polled {
        let _queue = self.queue.lock();
        if let Some(frame) = self.inflight.lock().completed.remove(&wanted) {
            return Polled::Complete(Some(frame));
        }
        let (hhdm, used) = {
            let mut s = self.dev.lock();
            let hhdm = s.hhdm;
            let q = match wanted.lane {
                Lane::Request => s.requestq.iter_mut().find(|(index, _)| *index == wanted.queue).map(|(_, q)| q),
                Lane::HiPrio => s.hiprioq.as_mut(),
            };
            let Some(q) = q else { return Polled::Failed; };
            match q.pop_used() {
                Ok(Some(used)) => (hhdm, used),
                Ok(None) => return Polled::None,
                Err(_) => return Polled::Failed,
            }
        };
        let key = RequestKey { queue: wanted.queue, lane: wanted.lane, head: used.head };
        let staging = self.inflight.lock().pending.remove(&key);
        let Some(staging) = staging else { return Polled::Failed; };
        let frame = if key.lane == Lane::HiPrio {
            Ok(None)
        } else {
            virtio::dma::invalidate_from_device(hhdm.wrapping_add(staging.rx_pa), BUFFER_BYTES);
            match Self::read_reply(hhdm, &staging, used.len as usize) {
                Some(frame) => Ok(Some(frame)),
                None => Err(()),
            }
        };
        registry::free_request_staging(staging);
        match frame {
            Ok(frame) if key != wanted => {
                if let Some(frame) = frame { self.inflight.lock().completed.insert(key, frame); }
                Polled::Other
            }
            Ok(frame) => Polled::Complete(frame),
            Err(_) => Polled::Failed,
        }
    }

    fn select_request_queue(&self) -> u16 {
        let s = self.dev.lock();
        let count = s.requestq.len();
        if count == 0 { return REQUEST_QUEUE; }
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
        {
            use hal::CpuOps;
            return s.requestq[hal_x86_64::X86CpuOps::current_cpu() as usize % count].0;
        }
        #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
        {
            use hal::CpuOps;
            return s.requestq[hal_aarch64::ArmCpuOps::current_cpu() as usize % count].0;
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        { s.requestq[0].0 }
    }

    #[cfg(target_os = "oxide-kernel")]
    fn any_used(&self, lane: Lane, queue: u16) -> bool {
        let s = self.dev.lock();
        match lane {
            Lane::Request => s.requestq.iter().find(|(index, _)| *index == queue).map_or(true, |(_, q)| q.has_used()),
            Lane::HiPrio => s.hiprioq.as_ref().map_or(true, |q| q.has_used()),
        }
    }

    #[cfg(target_os = "oxide-kernel")]
    fn wait_for_used(&self, lane: Lane, queue: u16, deadline: u64) -> bool {
        if sched::live::global().is_none() || sched::live::current().is_none() {
            core::hint::spin_loop();
            return true;
        }
        // SAFETY: process context, no queue/device lock held; the IRQ handler
        // only wakes this list and never takes either transport lock.
        let outcome = unsafe {
            sched::live::wait_event_uninterruptible_until(
                registry::completion_waiters(), deadline, registry::now_ns,
                || self.any_used(lane, queue),
            )
        };
        !matches!(outcome, sched::WaitOutcome::TimedOut)
    }

    fn read_reply(hhdm: u64, staging: &registry::RequestStaging, written: usize) -> Option<Vec<u8>> {
        // The device-reported length is clamped before it bounds any access,
        // and the header's own `len` is checked against it.
        let avail = written.min(BUFFER_BYTES);
        if avail < FUSE_OUT_HEADER_SIZE { return None; }
        let rx = hhdm.wrapping_add(staging.rx_pa) as *const u8;
        let mut head = [0u8; 4];
        for (i, slot) in head.iter_mut().enumerate() {
            // SAFETY: this request owns the private reply buffer;
            // `i < 4 <= FUSE_OUT_HEADER_SIZE <= avail <= BUFFER_BYTES`.
            *slot = unsafe { core::ptr::read_volatile(rx.add(i)) };
        }
        let declared = u32::from_le_bytes(head) as usize;
        if declared < FUSE_OUT_HEADER_SIZE || declared > avail { return None; }
        let mut frame = Vec::new();
        frame.try_reserve_exact(declared).ok()?;
        for i in 0..declared {
            // SAFETY: `i < declared <= avail <= BUFFER_BYTES`.
            frame.push(unsafe { core::ptr::read_volatile(rx.add(i)) });
        }
        Some(frame)
    }

    fn deliver(&self, frame: &[u8]) {
        let sink = self.sink.lock().clone();
        if let Some(s) = sink.and_then(|w| w.upgrade()) { s.deliver(frame); }
    }
}

impl FuseTransportOps for VirtioFsTransport {
    /// # C: O(1)
    fn attach_sink(&self, sink: Weak<dyn FuseReplySink>) { *self.sink.lock() = Some(sink); }

    /// # C: O(msg) + bounded device poll
    fn send_req(&self, msg: &[u8]) {
        match self.exchange(msg, Lane::Request) {
            Some(frame) => self.deliver(frame.as_slice()),
            // The device could not answer. The connection is told rather than
            // left with a request that will never complete: its caller is
            // parked and only an abort wakes it.
            None => {
                let sink = self.sink.lock().clone();
                if let Some(s) = sink.and_then(|w| w.upgrade()) { s.disconnect(); }
            }
        }
    }

    /// A FORGET expects no reply and rides the priority queue, so a backlog of
    /// them cannot queue ahead of a request a caller is blocked on. # C: O(msg)
    fn send_forget(&self, msg: &[u8]) { let _ = self.exchange(msg, Lane::HiPrio); }

    /// # C: O(1)
    fn max_message(&self) -> u32 { BUFFER_BYTES as u32 }

    /// # C: O(N_devices)
    fn release(&self) { registry::unclaim(self.device_key); }
}

impl Drop for VirtioFsTransport {
    fn drop(&mut self) {
        let has_pending = !self.inflight.lock().pending.is_empty();
        if has_pending { let _ = registry::shutdown(self.device_key); }
        let pending = core::mem::take(&mut self.inflight.lock().pending);
        for (_, staging) in pending { registry::free_request_staging(staging); }
        registry::unclaim(self.device_key);
    }
}

#[cfg(test)]
mod tests {
    use super::{InFlight, Lane, RequestKey};
    use alloc::collections::BTreeMap;

    #[test]
    fn completion_storage_separates_lanes_and_heads() {
        let mut state = InFlight { pending: BTreeMap::new(), completed: BTreeMap::new() };
        let request = RequestKey { queue: 1, lane: Lane::Request, head: 3 };
        let other_request = RequestKey { queue: 2, lane: Lane::Request, head: 3 };
        let hiprio = RequestKey { queue: 0, lane: Lane::HiPrio, head: 3 };
        state.completed.insert(request, alloc::vec![0x33]);
        state.completed.insert(other_request, alloc::vec![0x55]);
        state.completed.insert(hiprio, alloc::vec![0x44]);
        assert_eq!(state.completed.remove(&request), Some(alloc::vec![0x33]));
        assert_eq!(state.completed.remove(&other_request), Some(alloc::vec![0x55]));
        assert_eq!(state.completed.remove(&hiprio), Some(alloc::vec![0x44]));
    }
}
