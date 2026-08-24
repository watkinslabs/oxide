//! The trait a mounted volume reads its bytes through.

use alloc::vec::Vec;

use syscall::errno::Errno;

/// What a caller reports for a failed inline en/decryption.
///
/// A length that is not whole data units is the caller's error and stays
/// `EINVAL`; everything else — an undeclared mode, a key nothing can serve —
/// reaches the caller as a failed transfer, because from the volume's side
/// that is what it is.
/// # C: O(1)
pub(crate) fn crypt_errno(e: block::BlockError) -> Errno {
    match e {
        block::BlockError::Einval => Errno::Einval,
        block::BlockError::Eopnotsupp => Errno::Eopnotsupp,
        _ => Errno::Eio,
    }
}

/// Where a volume's bytes come from.
pub trait SectorSource {
    /// Number of addressable sectors, when the medium can report its size.
    /// Format fallbacks that depend on an exact device geometry must refuse
    /// to guess when this is unavailable. # C: O(1)
    fn sector_count(&self) -> Option<u64> { None }

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

    /// The same write, saying what the filesystem knows about it: that it
    /// carries metadata, that it should be started ahead of ordinary data.
    ///
    /// The flags are a HINT about ORDER and nothing else. A medium is free to
    /// discard them entirely — the default does exactly that, forwarding to
    /// [`Self::write_sectors`] — and the bytes that land are identical either
    /// way, which is what makes ignoring them correct rather than lossy. A
    /// medium with a queue behind it overrides this to pass them down; a
    /// medium with no queue has nothing to order and no reason to.
    ///
    /// An implementor that overrides this must also make `write_sectors`
    /// reach it, or the two entry points will disagree about the same write.
    /// # C: as `write_sectors`
    fn write_sectors_flags(&self, sector: u64, buf: &[u8], flags: block::RequestFlags)
        -> Result<(), Errno> {
        let _ = flags;
        self.write_sectors(sector, buf)
    }

    /// Whether a write this medium acknowledged may still be VOLATILE.
    ///
    /// The question every durability promise is answered against. `false` is
    /// the truthful answer for a medium with no cache behind it, and it makes
    /// the promises below cost nothing rather than turning them into errors.
    /// # C: O(1)
    fn write_cache(&self) -> bool { false }

    /// Write `buf`, keeping a promise about when it — and what came before it —
    /// is on the MEDIUM rather than in the medium's cache.
    ///
    /// What a commit record is written through. The pre-flush half makes
    /// everything written earlier durable before these bytes land, so the
    /// record can never name blocks a power loss never finished writing; the
    /// forced-unit-access half makes the record itself durable by the time this
    /// returns. A caller that wrote the record with [`Self::write_sectors`] and
    /// flushed afterwards would have neither guarantee, because the medium is
    /// free to reorder the two.
    ///
    /// Deliberately no encryption context: every block written under a
    /// durability promise is this filesystem's own metadata, which is never
    /// enciphered by the layer below. A caller needing both would be asking for
    /// a commit record whose bytes the medium transforms, and the transform
    /// would have to be part of the ordering argument.
    /// The default keeps both halves with barriers around an ordinary write,
    /// which is what a medium with no per-request durability bit can do. It
    /// claims no hardware forced-unit-access on purpose: this path cannot carry
    /// the bit down, and claiming one it then dropped would report a promise
    /// nothing kept. A medium whose device HAS one overrides this.
    /// # C: as `write_sectors_flags`, plus up to two barriers
    fn write_sectors_durable(&self, sector: u64, buf: &[u8], flags: block::RequestFlags,
        want: block::Durability) -> Result<(), Errno> {
        let seq = block::durability::sequence(self.write_cache(), false, want, true);
        block::durability::submit::run_with(seq, || self.flush(),
            |_| self.write_sectors_flags(sector, buf, flags))
    }

    /// Read sectors whose contents are ENCRYPTED, handing back plaintext.
    ///
    /// `None` is an ordinary read and must stay exactly that: a medium may not
    /// treat the absence of a context as a hint. `Some` says these sectors
    /// hold ciphertext under that key at that data unit number, and the caller
    /// wants what the file actually contains.
    ///
    /// The default does the crypto in software, which is the right answer for
    /// every medium with nothing beneath it that can do it in line with the
    /// transfer. What it deliberately does NOT do is ignore the context and
    /// return the bytes as they lie — that would hand a caller ciphertext it
    /// would go on to treat as file data.
    /// # C: O(len(buf))
    fn read_sectors_crypt(&self, sector: u64, buf: &mut [u8],
        ctx: Option<&block::crypto::Ctx>) -> Result<(), Errno> {
        self.read_sectors(sector, buf)?;
        match ctx {
            None => Ok(()),
            Some(c) => block::crypto::fallback::decrypt(c, buf).map_err(crypt_errno),
        }
    }

    /// Write sectors that must reach the medium ENCRYPTED, given plaintext.
    ///
    /// The same contract in the other direction, and the same refusal to
    /// ignore the context: a medium that wrote `buf` as it stands would put
    /// the file's own bytes on the disk while every layer above believed they
    /// were encrypted.
    /// # C: O(len(buf))
    fn write_sectors_crypt(&self, sector: u64, buf: &[u8],
        ctx: Option<&block::crypto::Ctx>, flags: block::RequestFlags) -> Result<(), Errno> {
        let Some(c) = ctx else { return self.write_sectors_flags(sector, buf, flags) };
        let mut ct = alloc::vec::Vec::from(buf);
        block::crypto::fallback::encrypt(c, &mut ct).map_err(crypt_errno)?;
        self.write_sectors_flags(sector, &ct, flags)
    }

    /// What the device beneath this medium can encrypt itself, if anything.
    ///
    /// `None` means nothing here does inline encryption in hardware, which is
    /// not a refusal — the software path serves the same configuration and
    /// writes the same bytes. It only means a raw key is the only kind that
    /// can be used, because a hardware-wrapped key needs the hardware.
    /// # C: O(1)
    fn crypto_profile(&self) -> Option<&block::crypto::Profile> { None }

    /// Tell the medium it may forget `count` sectors from `sector` on, erasing
    /// whatever they hold.
    ///
    /// Not a write and not a free: the sectors keep whatever the filesystem
    /// has them recorded as, and only their CONTENTS are destroyed. What is
    /// read back afterwards is the medium's business — a device may report
    /// zeroes, the previous bytes, or anything else — so nothing may depend on
    /// the value.
    ///
    /// The default refuses, because a medium that cannot erase must say so
    /// rather than return success for an erase that did not happen: a caller
    /// asking for one is asking for the old bytes to be GONE.
    fn discard_sectors(&self, _sector: u64, _count: u64) -> Result<(), Errno> {
        Err(Errno::Eopnotsupp)
    }

    /// Whether this medium erases at all. # C: O(1)
    fn supports_discard(&self) -> bool { false }

    /// Whether this medium accepts writes at all. # C: O(1)
    fn writable(&self) -> bool { false }

    /// Make everything already written to this medium durable on it.
    ///
    /// The default does nothing, which is right for a medium with no cache
    /// behind it: an in-memory image is durable the instant it is written.
    /// # C: depends on the medium
    fn flush(&self) -> Result<(), Errno> { Ok(()) }

    /// Make durable everything written to ONE member of this medium.
    ///
    /// A volume spread over several devices must not let its commit record
    /// become durable before the data it refers to on the other members: the
    /// record would then name blocks a power loss never finished writing. WHICH
    /// members are owed one is the filesystem's decision — it knows which it has
    /// written to and which carries the record — so the choice is not made here;
    /// this only aims a barrier at a named member.
    ///
    /// A single medium is its own member zero, and any other index is a
    /// filesystem asking for a member that does not exist.
    /// # C: depends on the medium
    fn flush_device(&self, member: usize) -> Result<(), Errno> {
        if member == 0 { self.flush() } else { Err(Errno::Einval) }
    }

    /// How many members this medium is made of. # C: O(1)
    fn members(&self) -> usize { 1 }
}

/// One command a [`MemImage`] was asked for, in arrival order.
///
/// Recorded because ORDER is the whole content of a durability promise: a
/// barrier issued after the write it was meant to precede leaves the counts
/// identical and the guarantee gone, so a test that only counts flushes cannot
/// fail on the bug it exists to catch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cmd {
    /// A write at a volume block address.
    Write(u64),
    /// A cache flush of this medium.
    Flush,
    /// A cache flush of every medium but the one the commit record lands on.
    FlushOthers,
    /// An erase at a volume block address.
    Erase(u64),
}

/// A whole volume held in memory, addressed in units of `sector_size`.
///
/// Every layout rule a real medium enforces is enforced here too: a request
/// past the end is `EIO` rather than a short read, and a read-only image
/// refuses writes at the same place a read-only mount would.
pub struct MemImage {
    bytes: sync::Spinlock<Vec<u8>, sync::TaskList>,
    /// Every command this image was asked for, in order.
    log: sync::Spinlock<Vec<Cmd>, sync::TaskList>,
    /// Whether this image pretends to hold acknowledged writes in a volatile
    /// cache. Off by default: an in-memory image is durable the instant it is
    /// written, and that is the honest answer. A test that needs the barrier
    /// path exercised turns it on.
    write_cache: bool,
    /// Every erase this image was asked for, as sector and count. A discard
    /// leaves no trace in the bytes that a write of zeroes would not also
    /// leave, so the two are indistinguishable by content — recording the
    /// request is the only way a test can tell which one it asked for.
    erased: sync::Spinlock<Vec<(u64, u64)>, sync::TaskList>,
    /// How many of the next cache flushes this image REFUSES.
    ///
    /// A real device can fail a barrier, and a filesystem's answer to one —
    /// retry, then stop writing rather than record a state the medium does not
    /// hold — is unreachable from a fixture that always succeeds. Counted down
    /// rather than latched, so a test can arrange a transient refusal that the
    /// retry recovers from as well as a member that never comes back.
    refuse_flushes: sync::Spinlock<u32, sync::TaskList>,
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
        Self { bytes: sync::Spinlock::new(bytes), log: sync::Spinlock::new(Vec::new()),
               write_cache: false, erased: sync::Spinlock::new(Vec::new()),
               refuse_flushes: sync::Spinlock::new(0), sector_size, writable: true }
    }

    /// Have this image behave as a device that holds acknowledged writes in a
    /// volatile cache, so the barriers a durability promise needs are actually
    /// issued at it. # C: O(1)
    pub fn with_write_cache(mut self) -> Self { self.write_cache = true; self }

    /// Have the next `n` cache flushes fail, as a device with a failing cache
    /// does. The command is still RECORDED: it was issued, and a test asserting
    /// how many times a caller retried counts exactly those. # C: O(1)
    pub fn refusing_flushes(self, n: u32) -> Self { *self.refuse_flushes.lock() = n; self }

    /// How many refusals this image still owes. # C: O(1)
    pub fn flush_refusals_left(&self) -> u32 { *self.refuse_flushes.lock() }

    /// The commands this image has been asked for, in order. # C: O(commands)
    pub fn commands(&self) -> Vec<Cmd> { self.log.lock().clone() }

    /// Forget the recorded commands, so a test can assert over one phase of a
    /// longer sequence. # C: O(1)
    pub fn forget_commands(&self) { self.log.lock().clear(); }

    /// The erases this image has been asked for, in the order they arrived.
    /// # C: O(erases)
    pub fn erased(&self) -> Vec<(u64, u64)> { self.erased.lock().clone() }

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
    fn sector_count(&self) -> Option<u64> {
        Some(self.bytes.lock().len() as u64 / u64::from(self.sector_size))
    }

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
        drop(bytes);
        self.log.lock().push(Cmd::Write(sector));
        Ok(())
    }

    fn write_cache(&self) -> bool { self.write_cache }

    /// Recorded, then nothing: the bytes are already where they will be read
    /// from. What the record is for is the ORDER — a test asserts that the
    /// barrier arrived before the block it was meant to fence.
    fn flush(&self) -> Result<(), Errno> {
        self.log.lock().push(Cmd::Flush);
        let mut left = self.refuse_flushes.lock();
        if *left > 0 { *left -= 1; return Err(Errno::Eio); }
        Ok(())
    }

    fn discard_sectors(&self, sector: u64, count: u64) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let len = usize::try_from(count.checked_mul(u64::from(self.sector_size))
                                       .ok_or(Errno::Eio)?).map_err(|_| Errno::Eio)?;
        let mut bytes = self.bytes.lock();
        let total = bytes.len();
        let (start, end) = self.span(sector, len, total).ok_or(Errno::Eio)?;
        bytes[start..end].fill(0);
        drop(bytes);
        self.erased.lock().push((sector, count));
        self.log.lock().push(Cmd::Erase(sector));
        Ok(())
    }

    fn supports_discard(&self) -> bool { self.writable }

    fn writable(&self) -> bool { self.writable }
}
