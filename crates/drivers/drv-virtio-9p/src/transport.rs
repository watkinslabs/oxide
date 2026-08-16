// The virtio face of a 9P session.
//
// One request occupies one descriptor chain: the encoded T-message as a
// device-READABLE run, then the reply staging buffer as a device-WRITABLE run.
// The device fills the second and reports how many bytes it wrote.

extern crate alloc;
use alloc::sync::{Arc, Weak};
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
    /// Serialises the shared staging buffers. One request is in flight at a
    /// time: both directions use ONE pair of buffers, so a second concurrent
    /// request would overwrite the first one's bytes mid-transfer.
    io: Spinlock<(), DriverLockClass>,
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
            io: Spinlock::new(()),
        }))
    }

    /// The device this session speaks to. # C: O(1)
    pub fn device_key(&self) -> virtio::VirtioChildDeviceKey { self.device_key }

    /// Run one request to completion against the device, returning the reply
    /// frame. The whole exchange happens under the I/O lock so the staging
    /// buffers belong to exactly one request at a time.
    fn exchange(&self, out: &[u8]) -> NpResult<Vec<u8>> {
        if out.len() > BUFFER_BYTES { return Err(NpError::MsgTooLarge); }
        let _io = self.io.lock();
        let mut s = self.dev.lock();
        if s.shutdown || s.tx_pa == 0 || s.rx_pa == 0 { return Err(NpError::Disconnected); }
        let (hhdm, tx_pa, tx_dma, rx_pa, rx_dma) = (s.hhdm, s.tx_pa, s.tx_dma, s.rx_pa, s.rx_dma);

        let tx = hhdm.wrapping_add(tx_pa) as *mut u8;
        // SAFETY: HHDM view of this device's outgoing staging buffer, which the
        // driver owns exclusively under the I/O lock held above; `out.len()` was
        // checked against the buffer size, so every write stays inside it.
        unsafe {
            for (i, b) in out.iter().enumerate() { core::ptr::write_volatile(tx.add(i), *b); }
        }
        virtio::dma::clean_to_device(hhdm.wrapping_add(tx_pa), out.len());

        let Some(q) = s.requestq.as_mut() else { return Err(NpError::Disconnected) };
        let segs = [
            virtio::SplitQueueSeg { dma: tx_dma, len: out.len() as u32, device_writes: false },
            virtio::SplitQueueSeg { dma: rx_dma, len: BUFFER_BYTES as u32, device_writes: true },
        ];
        if q.submit(&segs).is_err() { return Err(NpError::Disconnected); }

        // A bounded poll: a wedged device must fail the operation with a
        // diagnosis rather than park the caller forever.
        let written = (0..COMPLETION_POLL_BUDGET).find_map(|_| match q.pop_used() {
            Ok(Some(used)) => Some(Ok(used.len as usize)),
            Ok(None) => { core::hint::spin_loop(); None }
            Err(_) => Some(Err(NpError::Disconnected)),
        });
        let written = match written {
            Some(Ok(n)) => n,
            Some(Err(e)) => return Err(e),
            None => return Err(NpError::Disconnected),
        };
        virtio::dma::invalidate_from_device(hhdm.wrapping_add(rx_pa), BUFFER_BYTES);

        // The device-reported length is clamped to the buffer before it bounds
        // any access, and the frame's own size field is then checked against
        // it: a device over-reporting either one must not make the client read
        // bytes the device never wrote.
        let avail = written.min(BUFFER_BYTES);
        if avail < ninep::uapi::limits::HDRSZ { return Err(NpError::BadMessage); }
        let rx = hhdm.wrapping_add(rx_pa) as *const u8;
        let mut head = [0u8; 4];
        for (i, slot) in head.iter_mut().enumerate() {
            // SAFETY: HHDM view of this device's reply buffer, held under the
            // I/O lock; `i < 4 <= HDRSZ <= avail <= BUFFER_BYTES`.
            *slot = unsafe { core::ptr::read_volatile(rx.add(i)) };
        }
        let declared = u32::from_le_bytes(head) as usize;
        if declared < ninep::uapi::limits::HDRSZ || declared > avail {
            return Err(NpError::BadMessage);
        }
        let mut frame = Vec::new();
        frame.try_reserve_exact(declared).map_err(|_| NpError::NoMemory)?;
        for i in 0..declared {
            // SAFETY: same buffer under the same lock; `i < declared <= avail
            // <= BUFFER_BYTES`, so the read stays inside the staging buffer the
            // device just wrote.
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
    fn drop(&mut self) { registry::unclaim(self.device_key); }
}
