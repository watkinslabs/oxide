// The persistent-RAM backend (the reference's `ramoops`): a reserved region
// carved into zones, a dmesg record written into the next dump zone on a
// crash, and every surviving zone enumerated at attach time.
//
// The region is named by a base address and a length, never owned as a
// buffer, so the backend is identical whether that address is a physical
// reservation carried through a reboot or a `Vec` in a hosted test. Only
// `boot` knows the difference.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Kernfs as PstoreClass, Spinlock};
use vfs::VfsError;

use crate::geometry::{carve, Layout, Zone};
use crate::hdr::{parse_kmsg_hdr, write_kmsg_hdr};
use crate::limits::MAX_RECORDS_PER_SCAN;
use crate::record::{Record, RecordId};
use crate::uapi::RecordType;
use crate::zone;

/// The backend name that appears in every record filename.
pub const BACKEND_NAME: &str = "ramoops";

/// A span of memory that outlives the kernel that wrote it. Not a buffer:
/// the bytes belong to the machine, and this only names where they are.
pub struct RamRegion {
    base: usize,
    len: usize,
}

// SAFETY: `RamRegion` is a base address and a length, not a reference. Every
// dereference happens inside `RamBackend`, which holds its zones behind one
// lock, so no two callers ever hold overlapping slices of the same region.
unsafe impl Send for RamRegion {}
// SAFETY: see the `Send` impl — the region confers no access on its own.
unsafe impl Sync for RamRegion {}

impl RamRegion {
    /// Name a region of `len` bytes at virtual address `base`.
    ///
    /// # SAFETY: `base..base+len` must be a mapped, writable, exclusively
    /// owned span for the lifetime of this value — a reservation excluded
    /// from the page allocator, or a hosted test's own allocation. Nothing
    /// else may write it, because the contents are parsed as a header.
    /// # C: O(1)
    pub unsafe fn new(base: usize, len: usize) -> RamRegion { RamRegion { base, len } }

    /// The region's length in bytes. # C: O(1)
    pub fn len(&self) -> usize { self.len }

    /// Whether the region names nothing. # C: O(1)
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// The bytes of one zone.
    ///
    /// # SAFETY: caller holds the backend lock, so this is the only live
    /// slice over `off..off+len`, and the constructor's contract makes the
    /// span mapped and writable.
    /// # C: O(1)
    unsafe fn zone_mut(&self, z: Zone) -> &mut [u8] {
        // SAFETY: `carve` produced `z` entirely inside `0..self.len`, the
        // constructor's contract makes that span mapped and writable, and the
        // caller holds the lock that makes this borrow unique.
        unsafe { core::slice::from_raw_parts_mut((self.base + z.off) as *mut u8, z.len) }
    }
}

/// A dump zone's signature tag. Distinct per class so a console zone can
/// never be attached as a dump zone after a geometry change.
const SIG_DUMP: u32 = 0x0000_0000;
/// See [`SIG_DUMP`].
const SIG_CONSOLE: u32 = 0x4353_4c47;

struct Zones {
    region: RamRegion,
    layout: Layout,
    /// Which dump zone the next capture claims, wrapping — the reference's
    /// `dump_write_cnt`. The oldest crash is the one overwritten.
    next_dump: usize,
    /// The console zone's contents AS FOUND AT ATTACH — the reference's
    /// `old_log`, taken once and served from ever after.
    ///
    /// It cannot be re-read live: the console zone is appended to by this
    /// boot's own output, and a 4 KiB circular buffer is overwritten by it
    /// within seconds. Reading live would publish the CURRENT boot's log
    /// under a name that promises the previous one's — the record would be
    /// there and be wrong, which is worse than absent.
    console_old: Vec<u8>,
}

/// The persistent-RAM backend.
pub struct RamBackend {
    zones: Spinlock<Zones, PstoreClass>,
}

impl RamBackend {
    /// Attach to `region`, carving it and validating every zone.
    ///
    /// Returns the backend and the records that survived. A zone whose
    /// contents this kernel did not write, or no longer checksum, is zeroed
    /// here rather than published. # C: O(region length)
    pub fn attach(region: RamRegion, record_size: usize, console_size: usize)
        -> (Arc<RamBackend>, Vec<Record>)
    {
        let layout = carve(region.len(), record_size, console_size);
        let mut found = Vec::new();
        let mut next_dump = 0usize;
        for (i, z) in layout.dump.iter().enumerate() {
            if i >= MAX_RECORDS_PER_SCAN { break; }
            // SAFETY: nothing else holds this region yet — the backend it
            // will belong to has not been constructed, let alone published.
            let buf = unsafe { region.zone_mut(*z) };
            let ok = matches!(zone::attach(buf, SIG_DUMP), zone::Attach::Valid { .. });
            if !ok { continue; }
            match Self::decode_dump(buf, i) {
                Some(r) => {
                    // Keep writing after the newest survivor so a second
                    // crash does not land on the record of the first.
                    next_dump = (i + 1) % layout.dump.len().max(1);
                    found.push(r);
                }
                // A zone that validated but carries no record header of ours
                // is discarded, exactly as the reference discards a dump zone
                // with no valid header.
                None => zone::zap(buf, SIG_DUMP),
            }
        }
        let mut console_old = Vec::new();
        if let Some(z) = layout.console {
            // SAFETY: same as the dump loop above — sole owner at attach.
            let buf = unsafe { region.zone_mut(z) };
            if matches!(zone::attach(buf, SIG_CONSOLE), zone::Attach::Valid { .. }) {
                console_old = zone::read_all(buf);
                if !console_old.is_empty() {
                    found.push(Record { id: RecordId { ty: RecordType::Console, index: 0 },
                        sec: 0, nsec: 0, body: console_old.clone() });
                }
            }
        }
        let b = Arc::new(RamBackend {
            zones: Spinlock::new(Zones { region, layout, next_dump, console_old }) });
        (b, found)
    }

    fn decode_dump(buf: &mut [u8], index: usize) -> Option<Record> {
        let body = zone::read_all(buf);
        let h = parse_kmsg_hdr(&body)?;
        Some(Record {
            id: RecordId { ty: RecordType::Dmesg, index },
            sec: h.sec,
            nsec: h.nsec,
            body: body[h.len..].to_vec(),
        })
    }

    /// Bytes one dmesg record body may occupy, after the zone header and the
    /// record's own timestamp line. Zero when there is no dump zone at all.
    /// # C: O(1)
    pub fn dump_room(&self) -> usize {
        let g = self.zones.lock();
        match g.layout.dump.first() {
            None => 0,
            // A generous allowance for the timestamp line; a body that
            // overruns is truncated by the zone anyway.
            Some(z) => zone::capacity(z.len).saturating_sub(64),
        }
    }

    /// Store one dmesg record: the timestamp line, then `body`. The zone is
    /// reset first so the record starts at its beginning and a reader finds
    /// the header where it must be. # C: O(len body)
    pub fn write_dmesg(&self, sec: u64, nsec: u32, body: &[u8]) {
        let mut g = self.zones.lock();
        let Some(z) = g.layout.dump.get(g.next_dump).copied() else { return };
        // SAFETY: the lock is held, so this is the only live slice over the
        // region, and `z` came from the carve of that same region.
        let buf = unsafe { g.region.zone_mut(z) };
        zone::zap(buf, SIG_DUMP);
        let hdr = write_kmsg_hdr(sec, nsec);
        zone::write(buf, SIG_DUMP, hdr.as_bytes());
        zone::write(buf, SIG_DUMP, body);
        let n = g.layout.dump.len();
        if n > 0 { g.next_dump = (g.next_dump + 1) % n; }
    }

    /// Append console bytes to the single console zone. # C: O(len bytes)
    pub fn write_console(&self, bytes: &[u8]) {
        let g = self.zones.lock();
        let Some(z) = g.layout.console else { return };
        // SAFETY: the lock is held; see `write_dmesg`.
        let buf = unsafe { g.region.zone_mut(z) };
        zone::write(buf, SIG_CONSOLE, bytes);
    }

    /// Erase the zone one record came from — what unlinking its file does.
    /// # C: O(1)
    pub fn erase(&self, id: RecordId) -> Result<(), VfsError> {
        let mut g = self.zones.lock();
        let (z, tag) = match id.ty {
            RecordType::Dmesg => {
                let z = *g.layout.dump.get(id.index).ok_or(VfsError::Einval)?;
                (z, SIG_DUMP)
            }
            RecordType::Console => (g.layout.console.ok_or(VfsError::Einval)?, SIG_CONSOLE),
            _ => return Err(VfsError::Einval),
        };
        // SAFETY: the lock is held; see `write_dmesg`.
        let buf = unsafe { g.region.zone_mut(z) };
        zone::zap(buf, tag);
        // The snapshot is the console record; dropping the zone alone would
        // leave the file still readable from a copy nothing can erase.
        if id.ty == RecordType::Console { g.console_old.clear(); }
        Ok(())
    }

    /// Every record the region holds right now — the enumeration a mount
    /// performs. # C: O(region length)
    pub fn records(&self) -> Vec<Record> {
        let g = self.zones.lock();
        let mut out = Vec::new();
        for (i, z) in g.layout.dump.iter().enumerate() {
            if i >= MAX_RECORDS_PER_SCAN { break; }
            // SAFETY: the lock is held; see `write_dmesg`.
            let buf = unsafe { g.region.zone_mut(*z) };
            if let Some(r) = Self::decode_dump(buf, i) { out.push(r); }
        }
        if !g.console_old.is_empty() {
            out.push(Record { id: RecordId { ty: RecordType::Console, index: 0 },
                sec: 0, nsec: 0, body: g.console_old.clone() });
        }
        out
    }

    /// Human-readable geometry, for the boot log. # C: O(1)
    pub fn describe(&self) -> String {
        let g = self.zones.lock();
        let mut s = String::from(BACKEND_NAME);
        s.push_str(": ");
        push_dec(&mut s, g.layout.dump.len() as u64);
        s.push_str(" dump zone(s) of ");
        push_dec(&mut s, g.layout.dump.first().map(|z| z.len).unwrap_or(0) as u64);
        s.push_str(" B, console ");
        push_dec(&mut s, g.layout.console.map(|z| z.len).unwrap_or(0) as u64);
        s.push_str(" B\n");
        s
    }
}

fn push_dec(s: &mut String, mut v: u64) {
    let mut buf = [0u8; 20];
    let mut n = 0usize;
    if v == 0 { buf[0] = b'0'; n = 1; }
    while v > 0 { buf[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
    while n > 0 { n -= 1; s.push(buf[n] as char); }
}

#[cfg(test)]
#[path = "tests/ram.rs"]
mod tests;
