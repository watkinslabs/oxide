use super::*;
use alloc::sync::Arc;
use sync::Spinlock;

/// A backing store in memory, so every rule below is exercised with no
/// filesystem, no mount and no disk.
struct Mem {
    bytes: Spinlock<Vec<u8>, LoopLockClass>,
    writable: bool,
    /// Bytes beyond this read as nothing at all — a sparse or truncated file.
    readable_len: Option<usize>,
    flushes: core::sync::atomic::AtomicU32,
}

impl Mem {
    fn new(len: usize) -> Arc<Self> { Self::with(vec![0u8; len], true) }
    fn with(bytes: Vec<u8>, writable: bool) -> Arc<Self> {
        Arc::new(Mem { bytes: Spinlock::new(bytes), writable, readable_len: None,
                       flushes: core::sync::atomic::AtomicU32::new(0) })
    }
    fn truncated(len: usize, readable: usize) -> Arc<Self> {
        Arc::new(Mem { bytes: Spinlock::new(vec![0xAA; len]), writable: true,
                       readable_len: Some(readable),
                       flushes: core::sync::atomic::AtomicU32::new(0) })
    }
}

impl Backing for Mem {
    fn size_bytes(&self) -> u64 { self.bytes.lock().len() as u64 }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let src = self.bytes.lock();
        let limit = self.readable_len.unwrap_or(src.len());
        let start = off as usize;
        if start >= limit { return Ok(0); }
        let n = core::cmp::min(buf.len(), limit - start);
        buf[..n].copy_from_slice(&src[start..start + n]);
        Ok(n)
    }
    fn write_at(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        if !self.writable { return Err(BlockError::Eio); }
        let mut dst = self.bytes.lock();
        let start = off as usize;
        if start + buf.len() > dst.len() { return Err(BlockError::Enospc); }
        dst[start..start + buf.len()].copy_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&self) -> KResult<()> {
        self.flushes.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    fn writable(&self) -> bool { self.writable }
}

fn window(offset: u64, sizelimit: u64) -> Window { Window { offset, sizelimit, ..Window::default() } }

fn bound(len: usize, w: Window) -> (LoopDevice, Arc<Mem>) {
    let mem = Mem::new(len);
    let dev = LoopDevice::new(0);
    dev.bind(mem.clone(), w, 0, 512).expect("bind");
    (dev, mem)
}

fn read(dev: &LoopDevice, block: u64, count: u32) -> KResult<Vec<u8>> {
    let mut req = BlockRequest { op: BlockOp::Read, start_block: block, len_blocks: count, ..Default::default() };
    dev.submit_sync(&mut req)?;
    Ok(req.buffer)
}

fn write(dev: &LoopDevice, block: u64, data: Vec<u8>) -> KResult<()> {
    let count = (data.len() / 512) as u32;
    let mut req = BlockRequest { op: BlockOp::Write, start_block: block, len_blocks: count, buffer: data, ..Default::default() };
    dev.submit_sync(&mut req)
}

/// An unbound device exists, holds nothing, and refuses I/O — which is what a
/// device added through the control node looks like before it is configured.
#[test]
fn an_unbound_device_reports_nothing_and_refuses_io() {
    let dev = LoopDevice::new(3);
    assert_eq!(dev.number(), 3);
    assert!(!dev.is_bound());
    assert_eq!(dev.capacity_blocks(), 0);
    assert_eq!(read(&dev, 0, 1), Err(BlockError::Enxio));
    assert_eq!(dev.status().err(), Some(BlockError::Enxio));
    assert_eq!(dev.unbind(), Err(BlockError::Enxio), "clearing a clear device says so");
    assert_eq!(dev.refresh_capacity(), Err(BlockError::Enxio));
}

/// Binding publishes the capacity the window implies, and binding twice is
/// refused rather than swapping media under a mounted filesystem.
#[test]
fn binding_publishes_capacity_and_refuses_a_second_bind() {
    let (dev, _mem) = bound(8192, window(0, 0));
    assert!(dev.is_bound());
    assert_eq!(dev.capacity_blocks(), 16);
    assert_eq!(dev.bind(Mem::new(4096), window(0, 0), 0, 512), Err(BlockError::Ebusy));
    assert!(dev.unbind().is_ok());
    assert_eq!(dev.capacity_blocks(), 0);
    assert!(dev.bind(Mem::new(4096), window(0, 0), 0, 512).is_ok(), "rebind after clear");
}

/// The property the whole window exists for: a device over one region of a
/// file cannot reach a byte outside it, in either direction.
#[test]
fn the_window_bounds_every_access() {
    let mem = Mem::new(8192);
    // Mark the byte just past the window so a leak is visible as data.
    mem.bytes.lock()[2048] = 0x5A;
    let dev = LoopDevice::new(0);
    dev.bind(mem.clone(), window(1024, 1024), 0, 512).expect("bind");
    assert_eq!(dev.capacity_blocks(), 2, "1 KiB window is two sectors");

    // The last legal sector reads.
    assert!(read(&dev, 1, 1).is_ok());
    // One sector past the window does not, and never returns the 0x5A byte.
    assert_eq!(read(&dev, 2, 1), Err(BlockError::Eio));
    assert_eq!(read(&dev, 1, 2), Err(BlockError::Eio), "straddling the end is refused whole");
    // Nor can a write escape it.
    assert_eq!(write(&dev, 2, vec![0xFF; 512]), Err(BlockError::Eio));
    assert_eq!(mem.bytes.lock()[2048], 0x5A, "the byte past the window is untouched");
}

/// Device offset zero is the window's start, not the file's.
#[test]
fn device_offset_zero_is_the_window_start() {
    let mem = Mem::new(4096);
    mem.bytes.lock()[1024] = 0xC3;
    let dev = LoopDevice::new(0);
    dev.bind(mem, window(1024, 0), 0, 512).expect("bind");
    assert_eq!(read(&dev, 0, 1).unwrap()[0], 0xC3);
}

/// A write lands in the backing store at the windowed offset and reads back.
#[test]
fn a_write_reaches_the_backing_store_through_the_window() {
    let (dev, mem) = bound(4096, window(512, 0));
    write(&dev, 1, vec![0x42; 512]).expect("write");
    // Device block 1 with a 512-byte offset is file byte 1024.
    assert_eq!(mem.bytes.lock()[1024], 0x42);
    assert_eq!(mem.bytes.lock()[1023], 0, "nothing before it moved");
    assert_eq!(read(&dev, 1, 1).unwrap()[0], 0x42);
}

/// A read the backing store cannot fully satisfy yields zeroes for the rest.
/// A sparse or truncated file is a hole, not an I/O error.
#[test]
fn a_short_backing_read_becomes_zeroes_not_an_error() {
    let mem = Mem::truncated(4096, 700);
    let dev = LoopDevice::new(0);
    dev.bind(mem, window(0, 0), 0, 512).expect("bind");
    let got = read(&dev, 1, 1).expect("short read is not an error");
    assert_eq!(got.len(), 512);
    assert_eq!(&got[..188], &[0xAA; 188][..], "the bytes that exist");
    assert!(got[188..].iter().all(|b| *b == 0), "the hole reads as zeroes");
}

/// A read-only device refuses writes, and so does a device over a description
/// that cannot be written even when the flag is clear.
#[test]
fn a_read_only_device_or_backing_refuses_writes() {
    let dev = LoopDevice::new(0);
    dev.bind(Mem::new(4096), window(0, 0), LO_FLAGS_READ_ONLY, 512).expect("bind");
    assert_eq!(write(&dev, 0, vec![1; 512]), Err(BlockError::Eio));
    assert!(read(&dev, 0, 1).is_ok(), "reads still work");

    let ro_backing = LoopDevice::new(1);
    ro_backing.bind(Mem::with(vec![0; 4096], false), window(0, 0), 0, 512).expect("bind");
    assert_eq!(write(&ro_backing, 0, vec![1; 512]), Err(BlockError::Eio));
}

/// Moving the window resizes the device, which is what `SET_STATUS` is for.
#[test]
fn moving_the_window_resizes_the_device() {
    let (dev, _mem) = bound(8192, window(0, 0));
    assert_eq!(dev.capacity_blocks(), 16);
    dev.set_window(window(4096, 0), 0).expect("set");
    assert_eq!(dev.capacity_blocks(), 8);
    dev.set_window(window(0, 1024), 0).expect("set");
    assert_eq!(dev.capacity_blocks(), 2);
    let (w, flags, bsize) = dev.status().expect("status");
    assert_eq!((w.offset, w.sizelimit, flags, bsize), (0, 1024, 0, 512));
}

/// `SET_CAPACITY` notices the backing store growing under a bound device —
/// the only reason that ioctl exists.
#[test]
fn refreshing_capacity_notices_a_grown_backing_store() {
    let (dev, mem) = bound(4096, window(0, 0));
    assert_eq!(dev.capacity_blocks(), 8);
    mem.bytes.lock().resize(8192, 0);
    assert_eq!(dev.capacity_blocks(), 8, "not noticed until asked");
    assert_eq!(dev.refresh_capacity(), Ok(16));
    assert_eq!(dev.capacity_blocks(), 16);
}

/// Zeroing is an ordinary write of zeroes; discard is refused, and the device
/// says so through `supports_discard` rather than only at submission.
#[test]
fn write_zeroes_writes_zeroes_and_discard_is_refused() {
    let (dev, mem) = bound(4096, window(0, 0));
    mem.bytes.lock()[0..512].fill(0xEE);
    let mut req = BlockRequest { op: BlockOp::WriteZeroes { no_unmap: false }, start_block: 0, len_blocks: 1, ..Default::default() };
    dev.submit_sync(&mut req).expect("write zeroes");
    assert!(mem.bytes.lock()[0..512].iter().all(|b| *b == 0));

    assert!(!dev.supports_discard());
    let mut req = BlockRequest { op: BlockOp::Discard, start_block: 0, len_blocks: 1, ..Default::default() };
    assert_eq!(dev.submit_sync(&mut req), Err(BlockError::Eopnotsupp));
}

/// A flush reaches the backing store, so a filesystem's barrier means
/// something on a loop device.
#[test]
fn a_flush_reaches_the_backing_store() {
    let (dev, mem) = bound(4096, window(0, 0));
    let mut req = BlockRequest { op: BlockOp::Flush, ..Default::default() };
    dev.submit_sync(&mut req).expect("flush");
    dev.flush().expect("flush");
    assert_eq!(mem.flushes.load(core::sync::atomic::Ordering::Relaxed), 2);
}

/// A request whose sector arithmetic overflows is refused rather than
/// wrapping into a valid-looking offset inside the window.
#[test]
fn a_request_whose_arithmetic_overflows_is_refused() {
    let (dev, _mem) = bound(4096, window(0, 0));
    assert_eq!(read(&dev, u64::MAX, 1), Err(BlockError::Eio));
    let mut req = BlockRequest { op: BlockOp::Read, start_block: u64::MAX / 256, len_blocks: u32::MAX, ..Default::default() };
    assert!(dev.submit_sync(&mut req).is_err());
}

/// A write request whose buffer is shorter than the sectors it claims is a
/// malformed request, not a short write.
#[test]
fn a_write_shorter_than_its_sector_count_is_refused() {
    let (dev, _mem) = bound(4096, window(0, 0));
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: 2, buffer: vec![0; 512], ..Default::default() };
    assert_eq!(dev.submit_sync(&mut req), Err(BlockError::Einval));
}
