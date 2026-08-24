//! Snapshot targets: one origin owner and copy-on-write views.
//!
//! Linux keeps the origin's snapshot list separate from each target's table
//! entry (`dm-snap.c::register_snapshot`).  The same shape is used here: an
//! origin target and every snapshot target for that origin share an
//! `OriginState`, while each snapshot owns its exception map and store.

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use block::BlockOp;
use sched::live::Mutex;
use sync::{Spinlock, StackedBlock as DmClass};
use syscall::errno::Errno;

use crate::args::parse_u64;
use crate::target::{Ctr, DevMode, DmDev, DmIo, DmResult, DmTarget, MapResult,
                    StatusType, TargetFeatures, TargetType};

pub mod exception;
pub mod store;

use self::exception::ExceptionMap;
use self::exception::Exception;
use self::store::{ExceptionStore, PersistentStore, TransientStore};

mod registry {
    use super::*;

    static ORIGINS: Spinlock<Vec<Arc<OriginState>>, DmClass> = Spinlock::new(Vec::new());

    pub fn for_device(dev: &DmDev) -> Arc<OriginState> {
        let mut all = ORIGINS.lock();
        if let Some(found) = all.iter().find(|o| o.dev.major == dev.major && o.dev.minor == dev.minor) {
            return found.clone();
        }
        let state = Arc::new(OriginState { dev: dev.clone(), snapshots: Mutex::new(Vec::new()) });
        all.push(state.clone());
        state
    }
}

struct OriginState {
    dev: DmDev,
    snapshots: Mutex<Vec<Weak<Snapshot>>>,
}

impl OriginState {
    fn add(&self, snapshot: &Arc<Snapshot>) {
        // SAFETY: target construction is process context; this mutex is the
        // Linux origin snapshot-list owner and may sleep only if contended.
        let mut list = unsafe { self.snapshots.lock() };
        list.retain(|s| s.upgrade().is_some());
        list.push(Arc::downgrade(snapshot));
    }

    fn preserve(&self, sector: u64) -> DmResult<()> {
        // Snapshot copy-out is serialized per origin, matching Linux's
        // origin lock around the snapshot list and exception transition.
        // Each Snapshot takes its own sleeping state mutex while doing the
        // bounded copy, so no spinlock is held across block I/O.
        let list = {
            // SAFETY: process-context I/O path; the list lock is released
            // before any snapshot performs block I/O.
            unsafe { self.snapshots.lock() }.iter().filter_map(Weak::upgrade).collect::<Vec<_>>()
        };
        for snapshot in list {
            let chunk = sector.checked_sub(snapshot.begin).ok_or(Errno::Einval)? / snapshot.chunk_sectors;
            snapshot.preserve_chunk(chunk)?;
        }
        Ok(())
    }
}

struct SnapshotState {
    exceptions: ExceptionMap,
    store: Box<dyn ExceptionStore>,
    invalid: bool,
}

struct Snapshot {
    begin: u64,
    origin: DmDev,
    cow: DmDev,
    chunk_sectors: u64,
    state: Mutex<SnapshotState>,
}

impl Snapshot {
    fn chunk(&self, sector: u64) -> DmResult<(u64, u64)> {
        let relative = sector.checked_sub(self.begin).ok_or(Errno::Einval)?;
        Ok((relative / self.chunk_sectors, relative % self.chunk_sectors))
    }

    fn preserve_chunk(&self, chunk: u64) -> DmResult<()> {
        // SAFETY: this is the target's process-context map path. A sleeping
        // mutex, rather than a spinlock, deliberately covers the exception's
        // read/copy/commit transaction exactly once.
        let mut state = unsafe { self.state.lock() };
        if state.invalid || state.exceptions.lookup(chunk).is_some() { return Ok(()); }
        let dest = state.store.prepare_exception().ok_or_else(|| { state.invalid = true; Errno::Enospc })?;
        let mut data = Vec::new();
        crate::device::io::forward(&*self.origin.bdev, BlockOp::Read,
            self.origin_offset(chunk), self.chunk_sectors, &mut data).map_err(|_| Errno::Eio)?;
        crate::device::io::forward(&*self.cow.bdev, BlockOp::Write,
            dest * self.chunk_sectors, self.chunk_sectors, &mut data).map_err(|_| Errno::Eio)?;
        let exception = Exception::single(chunk, dest);
        if !state.store.commit_exception(exception) {
            state.invalid = true;
            return Err(Errno::Eio);
        }
        state.exceptions.insert(chunk, dest);
        Ok(())
    }

    fn origin_offset(&self, chunk: u64) -> u64 { chunk * self.chunk_sectors }

    fn map_io(&self, io: &mut DmIo<'_>) -> DmResult<MapResult> {
        let (chunk, within) = self.chunk(io.sector)?;
        let destination = {
            // SAFETY: read-only status lookup; this mutex is never held while
            // forwarding an ordinary mapped I/O.
            unsafe { self.state.lock() }.exceptions.lookup(chunk)
        };
        match io.op {
            BlockOp::Write => self.preserve_chunk(chunk)?,
            BlockOp::Read if destination.is_none() => {
                return Ok(MapResult::Remapped {
                    dev: self.origin.bdev.clone(),
                    sector: self.origin_offset(chunk) + within,
                });
            }
            _ => {}
        }
        let destination = {
            // SAFETY: the preceding preserve transaction has completed.
            unsafe { self.state.lock() }.exceptions.lookup(chunk).or(destination)
                .ok_or(Errno::Eio)?
        };
        Ok(MapResult::Remapped { dev: self.cow.bdev.clone(), sector: destination * self.chunk_sectors + within })
    }

    fn merge_io(&self, io: &mut DmIo<'_>) -> DmResult<MapResult> {
        let (chunk, within) = self.chunk(io.sector)?;
        let mut state = unsafe { self.state.lock() };
        if state.exceptions.lookup(chunk).is_some() {
            let mut data = Vec::new();
            crate::device::io::forward(&*self.cow.bdev, BlockOp::Read,
                state.exceptions.lookup(chunk).ok_or(Errno::Eio)? * self.chunk_sectors,
                self.chunk_sectors, &mut data).map_err(|_| Errno::Eio)?;
            crate::device::io::forward(&*self.origin.bdev, BlockOp::Write,
                self.origin_offset(chunk), self.chunk_sectors, &mut data).map_err(|_| Errno::Eio)?;
            let mut next = state.exceptions.clone();
            next.remove(chunk);
            if !state.store.rewrite_exceptions(&next) { state.invalid = true; return Err(Errno::Eio); }
            state.exceptions = next;
        }
        Ok(MapResult::Remapped { dev: self.origin.bdev.clone(), sector: self.origin_offset(chunk) + within })
    }

    fn table_status(&self, kind: StatusType, persistent: bool) -> String {
        let mode = if persistent { "P" } else { "N" };
        match kind {
            StatusType::Table => format!("{} {} {} {}", self.origin.name, self.cow.name, mode, self.chunk_sectors),
            StatusType::Info => {
                // Linux reports the current exception count and capacity as
                // the snapshot's live status, not a table reconstruction.
                let state = unsafe { self.state.lock() };
                format!("{} {} {}", state.exceptions.len(), state.store.total_chunks(), if state.invalid { "Invalid" } else { "Valid" })
            }
        }
    }
}

struct SnapshotTarget {
    snapshot: Arc<Snapshot>,
    persistent: bool,
    merge: bool,
}

impl DmTarget for SnapshotTarget {
    fn map(&self, io: &mut DmIo<'_>) -> DmResult<MapResult> {
        if self.merge { self.snapshot.merge_io(io) } else { self.snapshot.map_io(io) }
    }
    fn status(&self, kind: StatusType) -> String { self.snapshot.table_status(kind, self.persistent) }
    fn iterate_devices(&self) -> Vec<DmDev> { alloc::vec![self.snapshot.origin.clone(), self.snapshot.cow.clone()] }
    fn max_io_len(&self) -> u64 { self.snapshot.chunk_sectors }
}

struct OriginTarget { origin: Arc<OriginState>, begin: u64 }

impl DmTarget for OriginTarget {
    fn map(&self, io: &mut DmIo<'_>) -> DmResult<MapResult> {
        if matches!(io.op, BlockOp::Write) {
            let relative = io.sector.checked_sub(self.begin).ok_or(Errno::Einval)?;
            self.origin.preserve(relative)?;
        }
        Ok(MapResult::Remapped { dev: self.origin.dev.bdev.clone(), sector: io.sector - self.begin })
    }
    fn status(&self, kind: StatusType) -> String {
        if kind == StatusType::Table { self.origin.dev.name.clone() } else { String::new() }
    }
    fn iterate_devices(&self) -> Vec<DmDev> { alloc::vec![self.origin.dev.clone()] }
}

fn snapshot_ctr_impl(c: &mut Ctr<'_>, merge: bool) -> DmResult<Arc<dyn DmTarget>> {
    if c.argv.len() < 4 { return Err(c.fail("requires 4 or more arguments", Errno::Einval)); }
    let origin = c.resolver.get_device(c.argv[0], if merge { DevMode::RW } else { DevMode::RO })
        .map_err(|_| c.fail("Cannot get origin device", Errno::Enxio))?;
    let cow = c.resolver.get_device(c.argv[1], DevMode::RW).map_err(|_| c.fail("Cannot get COW device", Errno::Enxio))?;
    if origin.major == cow.major && origin.minor == cow.minor { return Err(c.fail("COW device cannot be the origin device", Errno::Einval)); }
    let persistent = match c.argv[2] { "P" => true, "N" => false, _ => return Err(c.fail("Invalid exception store type", Errno::Einval)) };
    let chunk = parse_u64(c.argv[3]).ok_or_else(|| c.fail("Invalid chunk size", Errno::Einval))?;
    if chunk == 0 || !chunk.is_power_of_two() { return Err(c.fail("Invalid chunk size", Errno::Einval)); }
    let origin_state = registry::for_device(&origin);
    let (store, metadata): (Box<dyn ExceptionStore>, Vec<Exception>) = if persistent {
        let mut p = PersistentStore::new(cow.bdev.clone(), chunk);
        let metadata = p.load_or_initialize();
        (Box::new(p), metadata)
    } else {
        (Box::new(TransientStore::new(chunk, cow.bdev.capacity_blocks() * (cow.bdev.block_size() as u64) / crate::uapi::SECTOR_BYTES)), Vec::new())
    };
    let mut exceptions = ExceptionMap::new();
    exceptions.load(&metadata);
    let snapshot = Arc::new(Snapshot { begin: c.begin, origin, cow, chunk_sectors: chunk,
        state: Mutex::new(SnapshotState { exceptions, store, invalid: false }) });
    origin_state.add(&snapshot);
    Ok(Arc::new(SnapshotTarget { snapshot, persistent, merge }))
}

fn snapshot_ctr(c: &mut Ctr<'_>) -> DmResult<Arc<dyn DmTarget>> { snapshot_ctr_impl(c, false) }

fn merge_ctr(c: &mut Ctr<'_>) -> DmResult<Arc<dyn DmTarget>> { snapshot_ctr_impl(c, true) }

fn origin_ctr(c: &mut Ctr<'_>) -> DmResult<Arc<dyn DmTarget>> {
    if c.argv.len() != 1 { return Err(c.fail("requires one origin device", Errno::Einval)); }
    let origin = c.resolver.get_device(c.argv[0], DevMode::RW).map_err(|_| c.fail("Cannot get origin device", Errno::Enxio))?;
    Ok(Arc::new(OriginTarget { origin: registry::for_device(&origin), begin: c.begin }))
}

const FEATURES: TargetFeatures = TargetFeatures {
    singleton: false, always_writeable: false, immutable: false, wildcard: false,
    nowait: false,
};

pub const SNAPSHOT_TYPE: TargetType = TargetType {
    name: "snapshot", version: [1, 16, 0], features: FEATURES, ctr: snapshot_ctr,
};
pub const ORIGIN_TYPE: TargetType = TargetType {
    name: "snapshot-origin", version: [1, 9, 0], features: FEATURES, ctr: origin_ctr,
};
pub const MERGE_TYPE: TargetType = TargetType {
    name: "snapshot-merge", version: [1, 5, 0], features: FEATURES, ctr: merge_ctr,
};

#[cfg(test)]
mod tests {
    use super::*;
    use block::{BlockDevice, BlockRequest, MemDisk};
    use sync::TaskList;

    struct Resolver { origin: DmDev, cow: DmDev }
    impl crate::target::DeviceResolver for Resolver {
        fn get_device(&self, path: &str, mode: DevMode) -> DmResult<DmDev> {
            let mut d = if path == "origin" { self.origin.clone() } else if path == "cow" { self.cow.clone() } else { return Err(Errno::Enxio) };
            d.mode = mode;
            Ok(d)
        }
    }

    #[test]
    fn transient_snapshot_preserves_origin_before_a_snapshot_write() {
        let origin: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 64);
        let cow: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 64);
        let origin_dev = DmDev { major: 240, minor: 1, name: "origin".into(), mode: DevMode::RW, bdev: origin.clone() };
        let cow_dev = DmDev { major: 240, minor: 2, name: "cow".into(), mode: DevMode::RW, bdev: cow.clone() };
        let resolver = Resolver { origin: origin_dev, cow: cow_dev };
        let args = ["origin", "cow", "N", "8"];
        let mut ctr = Ctr { begin: 0, len: 32, argv: &args, resolver: &resolver, error: None };
        let target = snapshot_ctr(&mut ctr).expect("snapshot target");

        let original = alloc::vec![0x11; 512];
        let mut write = BlockRequest::new_write(0, 1, original.clone());
        origin.submit_sync(&mut write).expect("seed origin");

        let changed = alloc::vec![0x22; 512];
        let mut io = DmIo { op: BlockOp::Write, sector: 0, n_sectors: 1, data: &mut changed.clone() };
        let MapResult::Remapped { dev, sector } = target.map(&mut io).expect("map snapshot write") else { panic!("write must remap") };
        let mut snapshot_write = BlockRequest::new_write(sector, 1, changed.clone());
        dev.submit_sync(&mut snapshot_write).expect("write COW");

        let mut origin_read = BlockRequest::new_read(0, 1, 512);
        origin.submit_sync(&mut origin_read).expect("read origin");
        assert_eq!(origin_read.buffer, original);
        let mut snapshot_read_data = Vec::new();
        let mut snapshot_read = DmIo { op: BlockOp::Read, sector: 0, n_sectors: 1, data: &mut snapshot_read_data };
        let MapResult::Remapped { dev, sector } = target.map(&mut snapshot_read).expect("map snapshot read") else { panic!("read must remap") };
        let mut read = BlockRequest::new_read(sector, 1, 512);
        dev.submit_sync(&mut read).expect("read snapshot COW");
        assert_eq!(read.buffer, changed);
    }

    #[test]
    fn persistent_snapshot_merge_replays_cow_data_to_origin() {
        let origin: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 64);
        let cow: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 64);
        let origin_dev = DmDev { major: 241, minor: 1, name: "origin-merge".into(), mode: DevMode::RW, bdev: origin.clone() };
        let cow_dev = DmDev { major: 241, minor: 2, name: "cow-merge".into(), mode: DevMode::RW, bdev: cow.clone() };
        let resolver = Resolver { origin: origin_dev, cow: cow_dev };
        let original = alloc::vec![0x31; 512];
        origin.submit_sync(&mut BlockRequest::new_write(0, 1, original)).expect("seed origin");

        let args = ["origin", "cow", "P", "8"];
        let mut ctr = Ctr { begin: 0, len: 32, argv: &args, resolver: &resolver, error: None };
        let snapshot = snapshot_ctr(&mut ctr).expect("persistent snapshot");
        let changed = alloc::vec![0x42; 512];
        let mut io = DmIo { op: BlockOp::Write, sector: 0, n_sectors: 1, data: &mut changed.clone() };
        let MapResult::Remapped { dev, sector } = snapshot.map(&mut io).expect("map snapshot write") else { panic!("write must remap") };
        dev.submit_sync(&mut BlockRequest::new_write(sector, 1, changed)).expect("write COW");

        let mut merge_ctr = Ctr { begin: 0, len: 32, argv: &args, resolver: &resolver, error: None };
        let merge = snapshot_ctr_impl(&mut merge_ctr, true).expect("snapshot merge");
        let mut merge_io = DmIo { op: BlockOp::Read, sector: 0, n_sectors: 1, data: &mut Vec::new() };
        let MapResult::Remapped { dev, sector } = merge.map(&mut merge_io).expect("merge exception") else { panic!("merge must remap") };
        let mut read = BlockRequest::new_read(sector, 1, 512);
        dev.submit_sync(&mut read).expect("read merged origin");
        assert_eq!(read.buffer, alloc::vec![0x42; 512]);
    }
}
