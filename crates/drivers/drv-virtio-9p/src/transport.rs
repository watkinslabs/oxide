// The virtio face of a 9P session.
//
// One request occupies one descriptor chain: the encoded T-message as a
// device-READABLE run, then the reply staging buffer as a device-WRITABLE run.
// The device fills the second and reports how many bytes it wrote.

extern crate alloc;
use alloc::sync::{Arc, Weak};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use ninep::client::req::Request;
use ninep::err::{NpError, NpResult};
use ninep::transport::{ReplySink, Transport};
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::consts::{BUFFER_BYTES, COMPLETION_POLL_BUDGET};
use crate::registry::{self, DeviceHandle};

/// A 9P session bound to one virtio-9p device.
pub struct Virtio9pTransport {
    device_key: virtio::VirtioChildDeviceKey,
    dev: DeviceHandle,
    sink: Spinlock<Option<Weak<dyn ReplySink>>, DriverLockClass>,
    /// Serialises only queue publication and used-ring retirement. Request
    /// buffers are private, so the expensive device wait happens outside it.
    queue: Spinlock<(), DriverLockClass>,
    /// Descriptor-head ownership: Linux's virtqueue request object carries
    /// the buffers until the matching used entry retires. A caller may reap a
    /// different head and leave its reply here for that caller.
    inflight: Spinlock<InFlight, DriverLockClass>,
}

struct InFlight {
    pending: BTreeMap<u16, registry::RequestStaging>,
    completed: BTreeMap<u16, Vec<u8>>,
}

enum Polled {
    None,
    Other,
    Complete(NpResult<Vec<u8>>),
}

impl Virtio9pTransport {
    /// Claim the device named `tag` for a session. `None` when no device
    /// carries that tag or a mount already holds it. # C: O(N_devices)
    pub fn claim(tag: &str) -> Option<Arc<Self>> {
        let dev = registry::claim(tag)?;
        let device_key = dev.lock().device_key;
        Some(Arc::new(Self {
            device_key, dev,
            sink: Spinlock::new(None),
            queue: Spinlock::new(()),
            inflight: Spinlock::new(InFlight { pending: BTreeMap::new(), completed: BTreeMap::new() }),
        }))
    }

    /// The device this session speaks to. # C: O(1)
    pub fn device_key(&self) -> virtio::VirtioChildDeviceKey { self.device_key }

    /// Run one request to completion against the device, returning the reply
    /// frame. Publication and completion retirement are serialized, but each
    /// request owns its DMA buffers while the device is working.
    fn exchange(&self, out: &[u8]) -> NpResult<Vec<u8>> {
        if out.len() > BUFFER_BYTES { return Err(NpError::MsgTooLarge); }
        let staging = registry::alloc_request_staging(self.device_key).ok_or(NpError::NoMemory)?;
        let head = {
            let _queue = self.queue.lock();
            let mut s = self.dev.lock();
            if s.shutdown { registry::free_request_staging(staging); return Err(NpError::Disconnected); }
            let hhdm = s.hhdm;

            let tx = hhdm.wrapping_add(staging.tx_pa) as *mut u8;
            // SAFETY: this request owns the private staging frame until its
            // matching used entry is retired; `out` was size-checked above.
            unsafe { for (i, b) in out.iter().enumerate() { core::ptr::write_volatile(tx.add(i), *b); } }
            virtio::dma::clean_to_device(hhdm.wrapping_add(staging.tx_pa), out.len());

            let Some(q) = s.requestq.as_mut() else { registry::free_request_staging(staging); return Err(NpError::Disconnected) };
            let segs = [
                virtio::SplitQueueSeg { dma: staging.tx_dma, len: out.len() as u32, device_writes: false },
                virtio::SplitQueueSeg { dma: staging.rx_dma, len: BUFFER_BYTES as u32, device_writes: true },
            ];
            let head = match q.submit(&segs) {
                Ok(head) => head,
                Err(_) => { registry::free_request_staging(staging); return Err(NpError::Disconnected); }
            };
            self.inflight.lock().pending.insert(head, staging);
            head
        };

        for _ in 0..COMPLETION_POLL_BUDGET {
            match self.poll_one(head) {
                Polled::Complete(result) => return result,
                Polled::Other | Polled::None => core::hint::spin_loop(),
            }
        }
        // The pending request remains owned until a later used entry retires
        // it; freeing DMA memory while the device may still write is unsafe.
        Err(NpError::Disconnected)
    }

    fn poll_one(&self, wanted: u16) -> Polled {
        let _queue = self.queue.lock();
        if let Some(frame) = self.inflight.lock().completed.remove(&wanted) {
            return Polled::Complete(Ok(frame));
        }
        let (hhdm, used) = {
            let mut s = self.dev.lock();
            let hhdm = s.hhdm;
            let Some(q) = s.requestq.as_mut() else { return Polled::Complete(Err(NpError::Disconnected)); };
            match q.pop_used() {
                Ok(Some(used)) => (hhdm, used),
                Ok(None) => return Polled::None,
                Err(_) => return Polled::Complete(Err(NpError::Disconnected)),
            }
        };
        let staging = self.inflight.lock().pending.remove(&used.head);
        let Some(staging) = staging else { return Polled::Complete(Err(NpError::Disconnected)); };
        virtio::dma::invalidate_from_device(hhdm.wrapping_add(staging.rx_pa), BUFFER_BYTES);
        let result = Self::read_reply(hhdm, &staging, used.len as usize);
        registry::free_request_staging(staging);
        match result {
            Ok(frame) if used.head != wanted => {
                self.inflight.lock().completed.insert(used.head, frame);
                Polled::Other
            }
            Ok(frame) => Polled::Complete(Ok(frame)),
            Err(e) => Polled::Complete(Err(e)),
        }
    }

    fn read_reply(hhdm: u64, staging: &registry::RequestStaging, written: usize) -> NpResult<Vec<u8>> {
        // The device-reported length is clamped before it bounds any access,
        // and the frame's own size field is checked against it.
        let avail = written.min(BUFFER_BYTES);
        if avail < ninep::uapi::limits::HDRSZ { return Err(NpError::BadMessage); }
        let rx = hhdm.wrapping_add(staging.rx_pa) as *const u8;
        let mut head = [0u8; 4];
        for (i, slot) in head.iter_mut().enumerate() {
            // SAFETY: the caller holds this request's staging ownership;
            // `i < 4 <= HDRSZ <= avail <= BUFFER_BYTES`.
            *slot = unsafe { core::ptr::read_volatile(rx.add(i)) };
        }
        let declared = u32::from_le_bytes(head) as usize;
        if declared < ninep::uapi::limits::HDRSZ || declared > avail {
            return Err(NpError::BadMessage);
        }
        let mut frame = Vec::new();
        frame.try_reserve_exact(declared).map_err(|_| NpError::NoMemory)?;
        for i in 0..declared {
            // SAFETY: `i < declared <= avail <= BUFFER_BYTES`.
            frame.push(unsafe { core::ptr::read_volatile(rx.add(i)) });
        }
        Ok(frame)
    }
}

impl Transport for Virtio9pTransport {
    /// # C: O(1)
    fn attach_sink(&self, sink: Weak<dyn ReplySink>) { *self.sink.lock() = Some(sink); }

    /// # C: O(frame) + bounded device poll
    fn submit(&self, req: &Arc<Request>) -> NpResult<()> {
        let frame = self.exchange(&req.tc)?;
        let sink = self.sink.lock().clone();
        match sink.and_then(|w| w.upgrade()) {
            Some(s) => { s.deliver(&frame); Ok(()) }
            // No sink means the session was torn down between submit and
            // completion; the reply has nowhere to go.
            None => Err(NpError::Disconnected),
        }
    }

    /// The exchange is complete by the time `submit` returns, so there is never
    /// an in-flight request to withdraw and never a reason to send `Tflush`.
    /// # C: O(1)
    fn try_cancel(&self, _req: &Arc<Request>) -> bool { false }

    /// # C: O(1)
    fn max_msize(&self) -> u32 { BUFFER_BYTES as u32 }

    /// # C: O(1)
    fn is_connected(&self) -> bool { !self.dev.lock().shutdown }

    /// # C: O(N_devices)
    fn shutdown(&self) { registry::unclaim(self.device_key); }
}

impl Drop for Virtio9pTransport {
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
    use super::InFlight;
    use alloc::collections::BTreeMap;

    #[test]
    fn completion_storage_keeps_heads_independent() {
        let mut state = InFlight { pending: BTreeMap::new(), completed: BTreeMap::new() };
        state.completed.insert(7, alloc::vec![0x71]);
        state.completed.insert(9, alloc::vec![0x91]);
        assert_eq!(state.completed.remove(&9), Some(alloc::vec![0x91]));
        assert_eq!(state.completed.remove(&7), Some(alloc::vec![0x71]));
    }
}
