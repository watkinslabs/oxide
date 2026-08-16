// The virtio face of a FUSE connection.
//
// virtiofs is FUSE with a different courier. One request occupies one
// descriptor chain: the encoded `fuse_in_header` plus body as a device-READABLE
// run, then the reply staging buffer as a device-WRITABLE run. Nothing here
// knows what a FUSE opcode means — the connection above the seam owns all of
// that, and owns it exactly once for both transports.

extern crate alloc;
use alloc::sync::Weak;
use alloc::vec::Vec;

use fuse_transport::{FuseReplySink, FuseTransportOps};
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::consts::{BUFFER_BYTES, COMPLETION_POLL_BUDGET};
use crate::registry::{self, DeviceHandle};

/// Bytes of a `fuse_out_header`: `len[4] error[4] unique[8]`. A reply shorter
/// than this carries no `unique` and can be matched to nothing.
const FUSE_OUT_HEADER_SIZE: usize = 16;

/// Which queue a message goes on.
#[derive(Clone, Copy, PartialEq, Eq)]
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
    /// Serialises the shared staging buffers: both directions use ONE pair, so
    /// a second concurrent request would overwrite the first one's bytes.
    io: Spinlock<(), DriverLockClass>,
}

impl VirtioFsTransport {
    /// Claim the device named `tag`. `None` when no device carries that tag or
    /// a mount already holds it. # C: O(N_devices)
    pub fn claim(tag: &str) -> Option<alloc::sync::Arc<Self>> {
        let dev = registry::claim(tag)?;
        let device_key = dev.lock().device_key;
        Some(alloc::sync::Arc::new(Self {
            device_key, dev, sink: Spinlock::new(None), io: Spinlock::new(()),
        }))
    }

    /// The device this connection speaks to. # C: O(1)
    pub fn device_key(&self) -> virtio::VirtioChildDeviceKey { self.device_key }

    /// Place `out` on `lane` and, for a lane that expects one, collect the
    /// reply frame. `None` means the exchange failed or none was expected.
    fn exchange(&self, out: &[u8], lane: Lane) -> Option<Vec<u8>> {
        if out.len() > BUFFER_BYTES { return None; }
        let _io = self.io.lock();
        let mut s = self.dev.lock();
        if s.shutdown || s.tx_pa == 0 || s.rx_pa == 0 { return None; }
        let (hhdm, tx_pa, tx_dma, rx_pa, rx_dma) = (s.hhdm, s.tx_pa, s.tx_dma, s.rx_pa, s.rx_dma);

        let tx = hhdm.wrapping_add(tx_pa) as *mut u8;
        // SAFETY: HHDM view of this device's outgoing staging buffer, owned
        // exclusively under the I/O lock held above; `out.len()` was checked
        // against the buffer size, so every write stays inside it.
        unsafe {
            for (i, b) in out.iter().enumerate() { core::ptr::write_volatile(tx.add(i), *b); }
        }
        virtio::dma::clean_to_device(hhdm.wrapping_add(tx_pa), out.len());

        let q = match lane {
            Lane::Request => s.requestq.as_mut(),
            Lane::HiPrio => s.hiprioq.as_mut(),
        };
        let q = q?;
        // A hiprio message expects no reply, so it is submitted with only the
        // readable run: offering a writable one would invite the device to
        // write a reply nobody will collect.
        let readable = virtio::SplitQueueSeg { dma: tx_dma, len: out.len() as u32, device_writes: false };
        let writable = virtio::SplitQueueSeg { dma: rx_dma, len: BUFFER_BYTES as u32, device_writes: true };
        let ok = match lane {
            Lane::Request => q.submit(&[readable, writable]).is_ok(),
            Lane::HiPrio => q.submit(&[readable]).is_ok(),
        };
        if !ok { return None; }

        let written = (0..COMPLETION_POLL_BUDGET).find_map(|_| match q.pop_used() {
            Ok(Some(used)) => Some(Some(used.len as usize)),
            Ok(None) => { core::hint::spin_loop(); None }
            Err(_) => Some(None),
        })??;
        if lane == Lane::HiPrio { return None; }
        virtio::dma::invalidate_from_device(hhdm.wrapping_add(rx_pa), BUFFER_BYTES);

        // The device-reported length is clamped to the buffer before it bounds
        // any access, and the header's own `len` is then checked against it: a
        // device over-reporting either must not make the connection read bytes
        // the device never wrote.
        let avail = written.min(BUFFER_BYTES);
        if avail < FUSE_OUT_HEADER_SIZE { return None; }
        let rx = hhdm.wrapping_add(rx_pa) as *const u8;
        let mut head = [0u8; 4];
        for (i, slot) in head.iter_mut().enumerate() {
            // SAFETY: HHDM view of this device's reply buffer under the I/O
            // lock; `i < 4 <= FUSE_OUT_HEADER_SIZE <= avail <= BUFFER_BYTES`.
            *slot = unsafe { core::ptr::read_volatile(rx.add(i)) };
        }
        let declared = u32::from_le_bytes(head) as usize;
        if declared < FUSE_OUT_HEADER_SIZE || declared > avail { return None; }
        let mut frame = Vec::new();
        frame.try_reserve_exact(declared).ok()?;
        for i in 0..declared {
            // SAFETY: same buffer under the same lock; `i < declared <= avail
            // <= BUFFER_BYTES`, so the read stays inside what the device wrote.
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
    fn drop(&mut self) { registry::unclaim(self.device_key); }
}
