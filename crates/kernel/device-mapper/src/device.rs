//! The mapped device: two table slots, a live state, and the block device
//! userspace sees.
//!
//! Module manifest:
//! - `state`: the fields under the lock, and the small answers about them.
//! - `io`: the `BlockDevice` face — split, map, remap, defer.
//! - `registry`: which mapped devices exist, by name, uuid and minor.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockOp, BlockRequest, KResult, QueueLimits};
use sync::{Spinlock, StackedBlock as DmClass};
use syscall::errno::Errno;

use crate::suspend::{DmFlags, Step};
use crate::table::Table;
use crate::target::{DmResult, StatusType};

pub mod io;
pub mod registry;

/// Reported CHS geometry. Nearly obsolete, and kept only because a mapped
/// device that a PC firmware boots is asked for it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Geometry {
    /// Cylinder count, at most 65535.
    pub cylinders: u16,
    /// Head count, at most 255.
    pub heads: u8,
    /// Sectors per track, at most 255.
    pub sectors: u8,
    /// First sector of the mapped device the geometry describes.
    pub start: u64,
}

/// One I/O parked while the device is not accepting them.
pub struct Deferred {
    /// The request as submitted.
    pub request: BlockRequest,
    /// Where its result goes.
    pub completion: block::BlockCompletion,
}

/// Everything about a mapped device that changes.
pub struct DevState {
    /// Live state bits.
    pub flags: DmFlags,
    /// The table I/O is placed by.
    pub active: Option<Arc<Table>>,
    /// A table loaded but not yet live.
    pub inactive: Option<Arc<Table>>,
    /// Counter a caller waits on for a table change or a target event.
    pub event_nr: u32,
    /// Open file descriptions holding the device.
    pub open_count: i32,
    /// Reported CHS geometry.
    pub geometry: Geometry,
    /// I/O parked by a suspend.
    pub deferred: Vec<Deferred>,
    /// Current name; a rename replaces it.
    pub name: String,
    /// Uuid, settable exactly once.
    pub uuid: Option<String>,
}

/// One device-mapper device.
pub struct MappedDevice {
    /// Minor number, fixed for the device's whole life.
    pub minor: u32,
    state: Spinlock<DevState, DmClass>,
    /// Waiters for `DM_DEV_WAIT`; publication happens under `state`, wake
    /// happens after that lock is released, matching Linux's event queue.
    event_waiters: alloc::sync::Arc<sched::live::WaitList>,
}

/// Block major device-mapper devices are published under.
pub const DM_MAJOR: u32 = 253;

impl MappedDevice {
    /// Create a suspended, table-less device. It errors every I/O until a
    /// table is loaded and resumed, which is what the reference's freshly
    /// created device does. # C: O(1)
    pub fn new(minor: u32, name: &str, uuid: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            minor,
            state: Spinlock::new(DevState {
                flags: DmFlags::SUSPENDED,
                active: None, inactive: None,
                event_nr: 0, open_count: 0,
                geometry: Geometry::default(),
                deferred: Vec::new(),
                name: name.to_string(),
                uuid: uuid.map(|s| s.to_string()),
            }),
            event_waiters: alloc::sync::Arc::new(sched::live::WaitList::new()),
        })
    }

    /// Read something out of the device's state under its lock. # C: O(f)
    pub fn with_state<R>(&self, f: impl FnOnce(&mut DevState) -> R) -> R {
        f(&mut self.state.lock())
    }

    /// Current name. # C: O(name)
    pub fn name(&self) -> String { self.state.lock().name.clone() }
    /// Current uuid. # C: O(uuid)
    pub fn uuid(&self) -> Option<String> { self.state.lock().uuid.clone() }
    /// Live state bits. # C: O(1)
    pub fn flags(&self) -> DmFlags { self.state.lock().flags }
    /// Whether a caller has suspended the device. # C: O(1)
    pub fn suspended(&self) -> bool { self.flags().contains(DmFlags::SUSPENDED) }
    /// Open file descriptions holding the device. # C: O(1)
    pub fn open_count(&self) -> i32 { self.state.lock().open_count }
    /// Event counter. # C: O(1)
    pub fn event_nr(&self) -> u32 { self.state.lock().event_nr }
    /// The live table, if any. # C: O(1)
    pub fn live_table(&self) -> Option<Arc<Table>> { self.state.lock().active.clone() }
    /// The loaded-but-not-live table, if any. # C: O(1)
    pub fn inactive_table(&self) -> Option<Arc<Table>> { self.state.lock().inactive.clone() }
    /// Length of the live table in sectors; zero with no table. # C: O(1)
    pub fn capacity_sectors(&self) -> u64 { self.state.lock().active.as_ref().map_or(0, |t| t.size()) }

    /// Raise the event counter. Called when a table changes or a target
    /// reports something a caller waits for. # C: O(1)
    pub fn bump_event(&self) -> u32 {
        let event = {
            let mut s = self.state.lock();
            s.event_nr = s.event_nr.wrapping_add(1);
            s.event_nr
        };
        self.event_waiters.wake_all();
        crate::control::notify_global_event();
        event
    }

    /// Wait list used by the control owner for `DM_DEV_WAIT`. # C: O(1)
    pub fn event_waiters(&self) -> &sched::live::WaitList { &self.event_waiters }

    /// Record that a description opened the device. # C: O(1)
    pub fn open(&self) { self.state.lock().open_count += 1; }
    /// Record that a description closed the device. # C: O(1)
    pub fn close(&self) { let mut s = self.state.lock(); if s.open_count > 0 { s.open_count -= 1; } }

    /// Install a table in the inactive slot. # C: O(1)
    pub fn load_table(&self, t: Arc<Table>) { self.state.lock().inactive = Some(t); }
    /// Discard the inactive slot. Reports whether one was there. # C: O(1)
    pub fn clear_table(&self) -> bool { self.state.lock().inactive.take().is_some() }

    /// Rename the device. # C: O(name)
    pub fn set_name(&self, name: &str) { self.state.lock().name = name.to_string(); }

    /// Set the uuid, which may be done exactly once. A uuid that could be
    /// changed would let a caller re-point a name that other tools have
    /// already resolved through it. # C: O(uuid)
    pub fn set_uuid(&self, uuid: &str) -> DmResult<()> {
        let mut s = self.state.lock();
        if s.uuid.is_some() { return Err(Errno::Einval); }
        s.uuid = Some(uuid.to_string());
        Ok(())
    }

    /// Set the reported geometry. # C: O(1)
    pub fn set_geometry(&self, g: Geometry) -> DmResult<()> {
        let capacity = g.cylinders as u64 * g.heads as u64 * g.sectors as u64;
        if g.start > capacity { return Err(Errno::Einval); }
        self.state.lock().geometry = g;
        Ok(())
    }
    /// The reported geometry. # C: O(1)
    pub fn geometry(&self) -> Geometry { self.state.lock().geometry }

    /// Suspend the device. Runs exactly the plan `suspend` produced, and
    /// nothing else — the ordering lives there and is tested there.
    /// # C: O(N_targets)
    pub fn suspend(&self, lockfs: bool, noflush: bool) -> DmResult<()> {
        let (flags, map) = { let s = self.state.lock(); (s.flags, s.active.clone()) };
        let steps = crate::suspend::plan_suspend(flags, lockfs, noflush, map.is_some())?;
        self.run(&steps, map.as_deref(), None)
    }

    /// Resume the device, swapping in a loaded table if one is waiting.
    /// # C: O(N_targets)
    pub fn resume(&self, lockfs: bool, noflush: bool) -> DmResult<()> {
        let (flags, map, new) = {
            let s = self.state.lock();
            (s.flags, s.active.clone(), s.inactive.clone())
        };
        let steps = crate::suspend::plan_resume(
            flags, new.is_some(), lockfs, noflush, map.is_some(), new.as_ref().map_or(0, |t| t.size()))?;
        // A plan that would install a table before the device is quiesced is
        // never executed. This cannot happen with the planner above; the check
        // is here so a later change to it fails loudly instead of silently
        // corrupting an in-flight write.
        if !crate::suspend::swap_is_quiesced(&steps) { return Err(Errno::Einval); }
        self.run(&steps, map.as_deref(), new.as_deref())
    }

    fn run(&self, steps: &[Step], live: Option<&Table>, incoming: Option<&Table>) -> DmResult<()> {
        for step in steps {
            match step {
                Step::SetNoflushSuspending => { self.state.lock().flags |= DmFlags::NOFLUSH_SUSPENDING; }
                Step::Presuspend => { if let Some(t) = live { t.presuspend(); } }
                Step::FreezeFs => { self.state.lock().flags |= DmFlags::FROZEN; }
                Step::BlockIo => { self.state.lock().flags |= DmFlags::BLOCK_IO_FOR_SUSPEND; }
                // Every submitter completes inline on this block layer, so
                // nothing is in flight once submissions are blocked. The step
                // stays in the plan because the ordering it enforces is the
                // contract, and a queued driver reaching completion later
                // waits here.
                Step::WaitForCompletion => {}
                Step::SetSuspended => { self.state.lock().flags |= DmFlags::SUSPENDED; }
                Step::PostSuspend => {
                    self.state.lock().flags |= DmFlags::POST_SUSPENDING;
                    if let Some(t) = live { t.postsuspend(); }
                    self.state.lock().flags -= DmFlags::POST_SUSPENDING;
                }
                Step::Preresume => { let t = incoming.or(live); if let Some(t) = t { t.preresume()?; } }
                Step::SwapTable => {
                    let mut s = self.state.lock();
                    if let Some(t) = s.inactive.take() { s.active = Some(t); }
                    let active = s.active.clone();
                    drop(s);
                    if let Some(t) = active { t.bind(self); }
                    self.bump_event();
                }
                Step::ResumeTargets => { let t = self.state.lock().active.clone(); if let Some(t) = t { t.resume(); } }
                Step::FlushDeferred => self.flush_deferred(),
                Step::ThawFs => { self.state.lock().flags -= DmFlags::FROZEN; }
                Step::ClearSuspended => { self.state.lock().flags -= DmFlags::SUSPENDED; }
                Step::PresuspendUndo => { if let Some(t) = live { t.presuspend_undo(); } }
            }
        }
        Ok(())
    }

    /// Re-admit I/O and dispose of whatever parked while it was blocked.
    fn flush_deferred(&self) {
        let (parked, fate) = {
            let mut s = self.state.lock();
            s.flags -= DmFlags::BLOCK_IO_FOR_SUSPEND;
            let fate = crate::defer::drain(s.flags);
            s.flags -= DmFlags::NOFLUSH_SUSPENDING;
            (core::mem::take(&mut s.deferred), fate)
        };
        for d in parked {
            match fate {
                crate::defer::Drain::Resubmit => self.submit(d.request, d.completion),
                crate::defer::Drain::Fail => (d.completion)(d.request, Err(block::BlockError::Eio)),
            }
        }
    }

    /// Park an I/O until the device resumes. # C: O(1)
    pub(crate) fn park(&self, request: BlockRequest, completion: block::BlockCompletion) {
        self.state.lock().deferred.push(Deferred { request, completion });
    }

    /// Number of parked I/Os. # C: O(1)
    pub fn deferred_len(&self) -> usize { self.state.lock().deferred.len() }

    /// Status text of every target of the chosen table. # C: O(output)
    pub fn status_lines(&self, kind: StatusType, inactive: bool) -> Vec<String> {
        let s = self.state.lock();
        let t = if inactive { s.inactive.as_ref() } else { s.active.as_ref() };
        t.map_or_else(Vec::new, |t| t.status_lines(kind))
    }
}

impl BlockDevice for MappedDevice {
    /// Sectors are the device-mapper unit, so a mapped device addresses in
    /// them regardless of what its members use. # C: O(1)
    fn block_size(&self) -> u32 { crate::uapi::SECTOR_BYTES as u32 }

    fn capacity_blocks(&self) -> u64 { self.capacity_sectors() }

    fn queue_limits(&self) -> KResult<QueueLimits> {
        let mut limits = QueueLimits::for_logical_block_size(crate::uapi::SECTOR_BYTES as u32)?;
        if let Some(t) = self.live_table() { t.set_restrictions(&mut limits); }
        Ok(limits)
    }

    fn supports_discard(&self) -> bool {
        self.live_table().is_some_and(|t| t.targets().iter().all(|e| {
            e.target.iterate_devices().iter().all(|d| d.bdev.supports_discard())
        }) && t.num_targets() > 0)
    }

    fn submit(&self, request: BlockRequest, completion: block::BlockCompletion) {
        io::submit(self, request, completion)
    }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> { io::submit_sync(self, req) }

    fn flush(&self) -> KResult<()> {
        let Some(t) = self.live_table() else { return Ok(()) };
        for d in t.devices() { d.bdev.flush()?; }
        Ok(())
    }
}

/// Whether an operation carries a payload whose length scales with the
/// transfer. Discard, flush and write-zeroes do not, so a split of one of them
/// must not slice a buffer that is not there. # C: O(1)
pub const fn has_payload(op: BlockOp) -> bool {
    matches!(op, BlockOp::Read | BlockOp::Write)
}
