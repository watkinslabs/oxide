//! The trait a mounted volume reads its bytes through.

use alloc::vec::Vec;

use syscall::errno::Errno;

/// Where a volume's bytes come from.
pub trait SectorSource {
    /// Read `buf.len()` bytes starting at sector `sector`. A short read is an
    /// error: unlike a backing file, a volume's own sectors either exist or
    /// the volume is truncated.
    fn read_sectors(&self, sector: u64, buf: &mut [u8]) -> Result<(), Errno>;

    /// Write `buf` starting at sector `sector`.
    ///
    /// The default refuses. A medium that cannot be written is not an error to
    /// be discovered halfway through a file: a mount asks first, through
    /// [`Self::writable`], and refuses to mount writable at all.
    fn write_sectors(&self, _sector: u64, _buf: &[u8]) -> Result<(), Errno> { Err(Errno::Erofs) }

    /// Whether this medium accepts writes at all. # C: O(1)
    fn writable(&self) -> bool { false }
}

/// A whole volume held in memory, addressed in units of `sector_size`.
///
/// Every layout rule a real medium enforces is enforced here too: a request
/// past the end is `EIO` rather than a short read, and a read-only image
/// refuses writes at the same place a read-only mount would.
pub struct MemImage {
    bytes: sync::Spinlock<Vec<u8>, sync::TaskList>,
    sector_size: u32,
    writable: bool,
}

impl MemImage {
    /// An image of `sectors` zeroed sectors. # C: O(image bytes)
    pub fn new(sector_size: u32, sectors: u64) -> Self {
        let len = (sector_size as usize) * (sectors as usize);
        Self::from_bytes(sector_size, alloc::vec![0u8; len])
    }

    /// An image over bytes already laid out. # C: O(1)
    pub fn from_bytes(sector_size: u32, bytes: Vec<u8>) -> Self {
        Self { bytes: sync::Spinlock::new(bytes), sector_size, writable: true }
    }

    /// Refuse writes through this image. # C: O(1)
    pub fn read_only(mut self) -> Self { self.writable = false; self }

    /// A copy of the whole image, to assert on what a write laid down.
    /// # C: O(image bytes)
    pub fn snapshot(&self) -> Vec<u8> { self.bytes.lock().clone() }

    /// Lay out a fixture directly. # C: O(len)
    pub fn poke(&self, offset: usize, bytes: &[u8]) {
        self.bytes.lock()[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    /// Read a fixture's bytes back. # C: O(len)
    pub fn peek(&self, offset: usize, len: usize) -> Vec<u8> {
        self.bytes.lock()[offset..offset + len].to_vec()
    }

    /// The image's length in bytes. # C: O(1)
    pub fn len(&self) -> usize { self.bytes.lock().len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Byte span a sector request covers, or `None` when it leaves the image.
    /// # C: O(1)
    fn span(&self, sector: u64, len: usize, total: usize) -> Option<(usize, usize)> {
        let start = usize::try_from(sector.checked_mul(u64::from(self.sector_size))?).ok()?;
        let end = start.checked_add(len)?;
        if end > total { return None; }
        Some((start, end))
    }
}

impl SectorSource for MemImage {
    fn read_sectors(&self, sector: u64, buf: &mut [u8]) -> Result<(), Errno> {
        let bytes = self.bytes.lock();
        let (start, end) = self.span(sector, buf.len(), bytes.len()).ok_or(Errno::Eio)?;
        buf.copy_from_slice(&bytes[start..end]);
        Ok(())
    }

    fn write_sectors(&self, sector: u64, buf: &[u8]) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let mut bytes = self.bytes.lock();
        let total = bytes.len();
        let (start, end) = self.span(sector, buf.len(), total).ok_or(Errno::Eio)?;
        bytes[start..end].copy_from_slice(buf);
        Ok(())
    }

    fn writable(&self) -> bool { self.writable }
}
