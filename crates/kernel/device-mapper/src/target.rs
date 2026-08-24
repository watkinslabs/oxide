//! What a device-mapper target is: the contract every mapping type
//! implements, and the values its constructor and mapping function trade with
//! the core.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, QueueLimits};
use syscall::errno::Errno;

/// Every fallible device-mapper operation reports a Linux errno.
pub type DmResult<T> = core::result::Result<T, Errno>;

/// Access a target asked for when it resolved a device. A target that only
/// reads its backing store must not hold it writable, because the mode is what
/// stops a read-only table from being stacked under a writable one.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DevMode {
    /// The holder may read the device.
    pub read: bool,
    /// The holder may write the device.
    pub write: bool,
}

impl DevMode {
    /// Read-only access. # C: O(1)
    pub const RO: Self = Self { read: true, write: false };
    /// Read-write access. # C: O(1)
    pub const RW: Self = Self { read: true, write: true };
}

/// One resolved backing device a target maps onto.
#[derive(Clone)]
pub struct DmDev {
    /// Packed device number, as the dependency report prints it.
    pub major: u32,
    /// Minor half of the device number.
    pub minor: u32,
    /// The name the table named it by, echoed back in the table report.
    pub name: String,
    /// Access the holder took.
    pub mode: DevMode,
    /// The device itself.
    pub bdev: Arc<dyn BlockDevice>,
}

impl DmDev {
    /// Packed `dev_t` in the encoding the dependency report uses. # C: O(1)
    pub fn devt(&self) -> u64 { crate::devt::pack(self.major, self.minor) }
}

/// How a constructor turns a device name into a device. The core supplies the
/// block registry; a hosted test supplies whatever backing it wants, which is
/// what makes every target constructor testable without a disk.
pub trait DeviceResolver: Send + Sync {
    /// Resolve `path` — either `major:minor` or a `/dev` path — at `mode`.
    /// # C: O(N_disks)
    fn get_device(&self, path: &str, mode: DevMode) -> DmResult<DmDev>;
}

/// The geometry a constructor is being asked to cover, and the services it
/// needs while parsing. `error` carries the reason a refusal happened, which
/// the ioctl surface reports back the way the reference's `ti->error` does.
pub struct Ctr<'a> {
    /// First sector of the mapped device this target covers.
    pub begin: u64,
    /// Length of the covered range, in sectors.
    pub len: u64,
    /// Whitespace-split parameter words, after the type name and geometry.
    pub argv: &'a [&'a str],
    /// How to turn a device name into a device.
    pub resolver: &'a dyn DeviceResolver,
    /// Why the constructor refused, set immediately before it returns an error.
    pub error: Option<&'static str>,
}

impl Ctr<'_> {
    /// Record a refusal reason and hand back the errno to return with it.
    /// # C: O(1)
    pub fn fail(&mut self, why: &'static str, e: Errno) -> Errno { self.error = Some(why); e }
}

/// One I/O the core is asking a target to place. Sector is relative to the
/// start of the MAPPED device, not to the target — a target that needs its own
/// offset subtracts `ti.begin` itself, exactly as the reference's targets do,
/// because several of them (stripe, snapshot) need the absolute sector too.
pub struct DmIo<'a> {
    /// What the submitter wants done.
    pub op: block::BlockOp,
    /// First sector, relative to the mapped device.
    pub sector: u64,
    /// Length in sectors. Zero for a flush.
    pub n_sectors: u64,
    /// Payload. A read's buffer is filled by the device; a write's carries the
    /// data. Empty for flush, discard and write-zeroes.
    pub data: &'a mut Vec<u8>,
}

/// What a target's mapping function decided.
pub enum MapResult {
    /// Submit this I/O to `dev` starting at `sector`, in the device's own
    /// sector numbering.
    Remapped {
        /// Device the rewritten I/O goes to.
        dev: Arc<dyn BlockDevice>,
        /// Sector on that device.
        sector: u64,
    },
    /// The target performed the I/O itself and there is nothing left to do.
    Submitted,
    /// Push the I/O back and retry it once the device makes progress.
    Requeue,
    /// Push the I/O back and retry it after a delay.
    DelayRequeue,
    /// Fail the I/O.
    Kill,
}

/// Which of the two report forms a status request wants.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StatusType {
    /// Runtime state: how full a snapshot is, which stripes have errored.
    Info,
    /// The constructor arguments, so the table can be reloaded from the report.
    Table,
}

/// Target-type feature bits. Only the ones the core acts on are modelled; a
/// bit nothing consults would be a second source of truth about behaviour.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct TargetFeatures {
    /// This type may only appear as the sole target of a table.
    pub singleton: bool,
    /// A table holding this type may be loaded onto a read-only device.
    pub always_writeable: bool,
    /// Once a table holds this type, a reload may not change the type.
    pub immutable: bool,
    /// This type accepts a table whose length does not cover the device.
    pub wildcard: bool,
    /// This type may run while the device is being suspended without flushing.
    pub nowait: bool,
}

/// The behaviour of one constructed target.
pub trait DmTarget: Send + Sync {
    /// Place one I/O. # C: depends on target
    fn map(&self, io: &mut DmIo<'_>) -> DmResult<MapResult>;

    /// Render the target's status or its table line. # C: O(output)
    fn status(&self, kind: StatusType) -> String;

    /// Answer a `DM_TARGET_MSG`. `Ok(Some(text))` sets the data-out flag.
    /// The default refusal is what a target with no messages reports.
    /// # C: O(1)
    fn message(&self, _argv: &[&str]) -> DmResult<Option<String>> { Err(Errno::Einval) }

    /// Devices this target depends on, for the dependency report and for the
    /// stacked queue limits. # C: O(N_devices)
    fn iterate_devices(&self) -> Vec<DmDev>;

    /// Narrow the mapped device's queue limits to what this target can honour.
    /// # C: O(1)
    fn io_hints(&self, _limits: &mut QueueLimits) {}

    /// Largest I/O this target will accept in one piece, in sectors, or zero
    /// for no constraint of its own. The core still splits at the target
    /// boundary; this splits further, which is how a striped or chunked target
    /// keeps every piece inside one stripe or chunk. # C: O(1)
    fn max_io_len(&self) -> u64 { 0 }

    /// Called before the device is suspended, while I/O is still admitted.
    /// # C: O(1)
    fn presuspend(&self) {}

    /// Called when a suspend that had already run `presuspend` is abandoned.
    /// # C: O(1)
    fn presuspend_undo(&self) {}

    /// Called once the device is quiesced. # C: O(1)
    fn postsuspend(&self) {}

    /// Called before a resume; a refusal aborts the resume and keeps the old
    /// table live. # C: depends on target
    fn preresume(&self) -> DmResult<()> { Ok(()) }

    /// Called after the table became live and before I/O is re-admitted.
    /// # C: O(1)
    fn resume(&self) {}

    /// Bind a live target to the mapped-device owner after table publication.
    /// `thin` uses this Linux-shaped lifecycle point so a later table can
    /// resolve the already-live `thin-pool` by its mapper device number.
    /// # C: O(1)
    fn bind(&self, _dev: &crate::device::MappedDevice) {}
}

/// A registered mapping type: its name, its version, and how to build one.
#[derive(Copy, Clone)]
pub struct TargetType {
    /// Name a table line selects this type by.
    pub name: &'static str,
    /// Version reported by `DM_LIST_VERSIONS` and `DM_GET_TARGET_VERSION`.
    pub version: [u32; 3],
    /// Bits the core acts on.
    pub features: TargetFeatures,
    /// Build one target for the geometry and arguments in `ctr`.
    pub ctr: fn(&mut Ctr<'_>) -> DmResult<Arc<dyn DmTarget>>,
}
