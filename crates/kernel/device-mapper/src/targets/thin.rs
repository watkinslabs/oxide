//! Linux-shaped thin-pool and thin targets.
//!
//! `dm-thin-metadata.c` owns virtual-device IDs and virtual-block mappings;
//! `dm-thin.c` owns pool policy and the copy-on-write transition.  The pool
//! below keeps those owners together behind one sleeping mutex.  The metadata
//! device is retained as a dependency and commit boundary; mappings are kept
//! in memory until the persistent metadata format is added, so this module
//! deliberately does not claim reboot persistence yet.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use block::BlockOp;
use sched::live::Mutex;
use sync::{Spinlock, StackedBlock as DmClass};
use syscall::errno::Errno;

use crate::args::{parse_u32, parse_u64};
use crate::target::{Ctr, DevMode, DmDev, DmIo, DmResult, DmTarget, MapResult,
                    StatusType, TargetFeatures, TargetType};

const MIN_BLOCK_SECTORS: u64 = 64 * 1024 / crate::uapi::SECTOR_BYTES;
const MAX_BLOCK_SECTORS: u64 = 1024 * 1024 * 1024 / crate::uapi::SECTOR_BYTES;
const MAX_THIN_ID: u64 = (1 << 24) - 1;

struct ThinDevice {
    mappings: BTreeMap<u64, u64>,
    shared: BTreeSet<u64>,
}

struct PoolState {
    devices: BTreeMap<u64, ThinDevice>,
    next_data_block: u64,
    out_of_data: bool,
}

pub struct ThinPool {
    pub metadata: DmDev,
    pub data: DmDev,
    pub block_sectors: u64,
    pub low_water_blocks: u64,
    state: Mutex<PoolState>,
}

impl ThinPool {
    fn data_blocks(&self) -> u64 {
        self.data.bdev.capacity_blocks() * self.data.bdev.block_size() as u64
            / crate::uapi::SECTOR_BYTES / self.block_sectors
    }

    fn create_thin(&self, id: u64) -> DmResult<()> {
        if id > MAX_THIN_ID { return Err(Errno::Einval); }
        let mut state = unsafe { self.state.lock() };
        if state.devices.contains_key(&id) { return Err(Errno::Ebusy); }
        state.devices.insert(id, ThinDevice { mappings: BTreeMap::new(), shared: BTreeSet::new() });
        Ok(())
    }

    fn create_snapshot(&self, id: u64, origin: u64) -> DmResult<()> {
        if id > MAX_THIN_ID || origin > MAX_THIN_ID { return Err(Errno::Einval); }
        let mut state = unsafe { self.state.lock() };
        if state.devices.contains_key(&id) { return Err(Errno::Ebusy); }
        let source = state.devices.get(&origin).ok_or(Errno::Enxio)?;
        let mappings = source.mappings.clone();
        let shared: BTreeSet<u64> = mappings.values().copied().collect();
        if let Some(source) = state.devices.get_mut(&origin) { source.shared.extend(shared.iter().copied()); }
        state.devices.insert(id, ThinDevice { mappings, shared });
        Ok(())
    }

    fn delete_thin(&self, id: u64) -> DmResult<()> {
        let mut state = unsafe { self.state.lock() };
        state.devices.remove(&id).map(|_| ()).ok_or(Errno::Enxio)
    }

    fn allocate(&self, state: &mut PoolState) -> DmResult<u64> {
        if state.next_data_block.saturating_add(self.low_water_blocks) >= self.data_blocks() {
            state.out_of_data = true;
            return Err(Errno::Enospc);
        }
        let block = state.next_data_block;
        state.next_data_block += 1;
        Ok(block)
    }

    fn map_thin(&self, id: u64, io: &mut DmIo<'_>) -> DmResult<MapResult> {
        let block = io.sector / self.block_sectors;
        let within = io.sector % self.block_sectors;
        let mut state = unsafe { self.state.lock() };
        let (mapped, shared) = state.devices.get(&id).ok_or(Errno::Enxio)
            .map(|thin| (thin.mappings.get(&block).copied(), mapped_is_shared(thin, block)))?;
        if matches!(io.op, BlockOp::Read) && mapped.is_none() {
            io.data.fill(0);
            return Ok(MapResult::Submitted);
        }
        if matches!(io.op, BlockOp::Discard) {
            state.devices.get_mut(&id).expect("thin still exists").mappings.remove(&block);
            return Ok(MapResult::Submitted);
        }
        let physical = match mapped {
            Some(old) if shared && matches!(io.op, BlockOp::Write | BlockOp::WriteZeroes { .. }) => {
                let fresh = self.allocate(&mut state)?;
                let mut data = Vec::new();
                crate::device::io::forward(&*self.data.bdev, BlockOp::Read,
                    old * self.block_sectors, self.block_sectors, &mut data).map_err(|_| Errno::Eio)?;
                crate::device::io::forward(&*self.data.bdev, BlockOp::Write,
                    fresh * self.block_sectors, self.block_sectors, &mut data).map_err(|_| Errno::Eio)?;
                let thin = state.devices.get_mut(&id).expect("thin still exists");
                thin.shared.remove(&old);
                thin.mappings.insert(block, fresh);
                fresh
            }
            Some(existing) => existing,
            None => {
                let fresh = self.allocate(&mut state)?;
                state.devices.get_mut(&id).expect("thin still exists").mappings.insert(block, fresh);
                crate::device::io::forward(&*self.data.bdev, BlockOp::WriteZeroes { no_unmap: false },
                    fresh * self.block_sectors, self.block_sectors, &mut Vec::new()).map_err(|_| Errno::Eio)?;
                fresh
            }
        };
        Ok(MapResult::Remapped { dev: self.data.bdev.clone(), sector: physical * self.block_sectors + within })
    }

    fn status(&self, id: Option<u64>) -> String {
        let state = unsafe { self.state.lock() };
        match id {
            Some(id) => format!("{} {}", id, state.devices.get(&id).map_or(0, |d| d.mappings.len())),
            None => format!("{} {} {}", self.data_blocks(), state.next_data_block, if state.out_of_data { "out_of_data_space" } else { "rw" }),
        }
    }
}

fn mapped_is_shared(thin: &ThinDevice, block: u64) -> bool {
    thin.mappings.get(&block).is_some_and(|physical| thin.shared.contains(physical))
}

struct PoolRegistryEntry { major: u32, minor: u32, pool: Weak<ThinPool> }
static POOLS: Spinlock<Vec<PoolRegistryEntry>, DmClass> = Spinlock::new(Vec::new());

fn find_pool(dev: &DmDev) -> DmResult<Arc<ThinPool>> {
    let mut pools = POOLS.lock();
    pools.retain(|e| e.pool.upgrade().is_some());
    pools.iter().find(|e| e.major == dev.major && e.minor == dev.minor)
        .and_then(|e| e.pool.upgrade()).ok_or(Errno::Enxio)
}

struct PoolTarget { pool: Arc<ThinPool> }
impl DmTarget for PoolTarget {
    fn map(&self, io: &mut DmIo<'_>) -> DmResult<MapResult> {
        Ok(MapResult::Remapped { dev: self.pool.data.bdev.clone(), sector: io.sector })
    }
    fn status(&self, kind: StatusType) -> String {
        match kind { StatusType::Info => self.pool.status(None), StatusType::Table => format!("{} {} {} {}", self.pool.metadata.name, self.pool.data.name, self.pool.block_sectors, self.pool.low_water_blocks) }
    }
    fn message(&self, argv: &[&str]) -> DmResult<Option<String>> {
        match argv {
            ["create_thin", id] => { self.pool.create_thin(parse_u64(id).ok_or(Errno::Einval)?)?; Ok(None) }
            ["create_snap", id, origin] => { self.pool.create_snapshot(parse_u64(id).ok_or(Errno::Einval)?, parse_u64(origin).ok_or(Errno::Einval)?)?; Ok(None) }
            ["delete", id] => { self.pool.delete_thin(parse_u64(id).ok_or(Errno::Einval)?)?; Ok(None) }
            _ => Err(Errno::Einval),
        }
    }
    fn iterate_devices(&self) -> Vec<DmDev> { alloc::vec![self.pool.metadata.clone(), self.pool.data.clone()] }
    fn bind(&self, dev: &crate::device::MappedDevice) {
        let mut pools = POOLS.lock();
        pools.retain(|e| e.pool.upgrade().is_some() && !(e.major == devt_major(dev) && e.minor == dev.minor));
        pools.push(PoolRegistryEntry { major: devt_major(dev), minor: dev.minor, pool: Arc::downgrade(&self.pool) });
    }
}

fn devt_major(_dev: &crate::device::MappedDevice) -> u32 { crate::device::DM_MAJOR }

struct ThinTarget { pool: Arc<ThinPool>, id: u64, pool_dev: DmDev }
impl DmTarget for ThinTarget {
    fn map(&self, io: &mut DmIo<'_>) -> DmResult<MapResult> { self.pool.map_thin(self.id, io) }
    fn status(&self, kind: StatusType) -> String {
        match kind { StatusType::Info => self.pool.status(Some(self.id)), StatusType::Table => format!("{} {}", self.pool_dev.name, self.id) }
    }
    fn iterate_devices(&self) -> Vec<DmDev> { alloc::vec![self.pool_dev.clone()] }
    fn max_io_len(&self) -> u64 { self.pool.block_sectors }
}

fn pool_ctr(c: &mut Ctr<'_>) -> DmResult<Arc<dyn DmTarget>> {
    if c.argv.len() < 4 { return Err(c.fail("Invalid argument count", Errno::Einval)); }
    if c.argv[0] == c.argv[1] { return Err(c.fail("Metadata and data devices must differ", Errno::Einval)); }
    let metadata = c.resolver.get_device(c.argv[0], DevMode::RW).map_err(|_| c.fail("Error opening metadata device", Errno::Enxio))?;
    let data = c.resolver.get_device(c.argv[1], DevMode::RW).map_err(|_| c.fail("Error opening data device", Errno::Enxio))?;
    let block_sectors = parse_u64(c.argv[2]).ok_or_else(|| c.fail("Invalid block size", Errno::Einval))?;
    if !(MIN_BLOCK_SECTORS..=MAX_BLOCK_SECTORS).contains(&block_sectors) || block_sectors % MIN_BLOCK_SECTORS != 0 {
        return Err(c.fail("Invalid block size", Errno::Einval));
    }
    let low_water_blocks = parse_u64(c.argv[3]).ok_or_else(|| c.fail("Invalid low water mark", Errno::Einval))?;
    if c.argv.len() > 4 {
        let count = parse_u32(c.argv[4]).ok_or_else(|| c.fail("Invalid feature count", Errno::Einval))? as usize;
        if c.argv.len() != 5 + count { return Err(c.fail("Invalid feature count", Errno::Einval)); }
        for feature in &c.argv[5..] {
            if !matches!(*feature, "skip_block_zeroing" | "ignore_discard" | "no_discard_passdown" | "read_only" | "error_if_no_space") {
                return Err(c.fail("Unrecognised feature requested", Errno::Einval));
            }
        }
    }
    Ok(Arc::new(PoolTarget { pool: Arc::new(ThinPool { metadata, data, block_sectors, low_water_blocks, state: Mutex::new(PoolState { devices: BTreeMap::new(), next_data_block: 0, out_of_data: false }) }) }))
}

fn thin_ctr(c: &mut Ctr<'_>) -> DmResult<Arc<dyn DmTarget>> {
    if c.argv.len() != 2 { return Err(c.fail("Invalid argument count", Errno::Einval)); }
    let pool_dev = c.resolver.get_device(c.argv[0], DevMode::RW).map_err(|_| c.fail("Error opening pool device", Errno::Enxio))?;
    let id = parse_u64(c.argv[1]).ok_or_else(|| c.fail("Invalid thin id", Errno::Einval))?;
    if id > MAX_THIN_ID { return Err(c.fail("Invalid thin id", Errno::Einval)); }
    let pool = find_pool(&pool_dev).map_err(|_| c.fail("Thin pool is not live", Errno::Enxio))?;
    if !unsafe { pool.state.lock() }.devices.contains_key(&id) { return Err(c.fail("Thin device does not exist", Errno::Enxio)); }
    Ok(Arc::new(ThinTarget { pool, id, pool_dev }))
}

const POOL_FEATURES: TargetFeatures = TargetFeatures { singleton: true, always_writeable: false, immutable: false, wildcard: false, nowait: false };
const THIN_FEATURES: TargetFeatures = TargetFeatures { singleton: false, always_writeable: false, immutable: false, wildcard: false, nowait: false };

pub const POOL_TYPE: TargetType = TargetType { name: "thin-pool", version: [1, 19, 0], features: POOL_FEATURES, ctr: pool_ctr };
pub const THIN_TYPE: TargetType = TargetType { name: "thin", version: [1, 10, 0], features: THIN_FEATURES, ctr: thin_ctr };

#[cfg(test)]
mod tests {
    use super::*;
    use block::{BlockDevice, BlockRequest, MemDisk};
    use sync::TaskList;

    fn pool() -> Arc<ThinPool> {
        let metadata: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 256);
        let data: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 256);
        Arc::new(ThinPool {
            metadata: DmDev { major: 242, minor: 1, name: "thin-meta".into(), mode: DevMode::RW, bdev: metadata },
            data: DmDev { major: 242, minor: 2, name: "thin-data".into(), mode: DevMode::RW, bdev: data },
            block_sectors: MIN_BLOCK_SECTORS,
            low_water_blocks: 0,
            state: Mutex::new(PoolState { devices: BTreeMap::new(), next_data_block: 0, out_of_data: false }),
        })
    }

    #[test]
    fn thin_allocates_on_write_and_internal_snapshot_cows() {
        let pool = pool();
        pool.create_thin(1).expect("thin create");
        let pool_dev = pool.data.clone();
        let first = ThinTarget { pool: pool.clone(), id: 1, pool_dev: pool_dev.clone() };
        let mut first_data = alloc::vec![0x11; 512];
        let mut write = DmIo { op: BlockOp::Write, sector: 0, n_sectors: 1, data: &mut first_data };
        let MapResult::Remapped { dev, sector } = first.map(&mut write).expect("thin write") else { panic!("write must map") };
        dev.submit_sync(&mut BlockRequest::new_write(sector, 1, first_data.clone())).expect("write data");

        pool.create_snapshot(2, 1).expect("internal snapshot");
        let second = ThinTarget { pool: pool.clone(), id: 2, pool_dev };
        let mut second_data = alloc::vec![0x22; 512];
        let mut second_io = DmIo { op: BlockOp::Write, sector: 0, n_sectors: 1, data: &mut second_data };
        let MapResult::Remapped { dev, sector } = second.map(&mut second_io).expect("snapshot write") else { panic!("snapshot write must map") };
        dev.submit_sync(&mut BlockRequest::new_write(sector, 1, second_data.clone())).expect("write snapshot data");

        let mut first_read_data = Vec::new();
        let mut first_read_io = DmIo { op: BlockOp::Read, sector: 0, n_sectors: 1, data: &mut first_read_data };
        let MapResult::Remapped { dev, sector } = first.map(&mut first_read_io).expect("read origin thin") else { panic!("read must map") };
        let mut first_read = BlockRequest::new_read(sector, 1, 512);
        dev.submit_sync(&mut first_read).expect("read origin thin");
        assert_eq!(first_read.buffer, alloc::vec![0x11; 512]);

        let mut second_read_data = Vec::new();
        let mut second_read_io = DmIo { op: BlockOp::Read, sector: 0, n_sectors: 1, data: &mut second_read_data };
        let MapResult::Remapped { dev, sector } = second.map(&mut second_read_io).expect("read snapshot thin") else { panic!("read must map") };
        let mut second_read = BlockRequest::new_read(sector, 1, 512);
        dev.submit_sync(&mut second_read).expect("read snapshot thin");
        assert_eq!(second_read.buffer, alloc::vec![0x22; 512]);
    }
}
