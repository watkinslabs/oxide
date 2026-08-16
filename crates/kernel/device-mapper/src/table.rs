//! A mapped device's table: the ordered targets that tile it, and the index
//! that finds the one covering a sector.
//!
//! Module manifest:
//! - `btree`: the sector index and its lookup.
//! - `tests/*`: the construction rules and the index, over fake targets.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::QueueLimits;
use syscall::errno::Errno;

use crate::args::split_args;
use crate::target::{Ctr, DeviceResolver, DmDev, DmTarget, DmResult, StatusType, TargetFeatures, TargetType};

pub mod btree;

/// Largest sector a table may address. The reference caps a device at the
/// largest signed byte offset, which is that many sectors.
pub const MAX_TABLE_SECTORS: u64 = (i64::MAX as u64) >> crate::uapi::SECTOR_SHIFT;

/// One constructed entry of a table.
pub struct TargetEntry {
    /// First sector of the mapped device this entry covers.
    pub begin: u64,
    /// Length of the covered range, in sectors.
    pub len: u64,
    /// Registered name of the mapping type.
    pub type_name: &'static str,
    /// Version of the mapping type that built this entry.
    pub version: [u32; 3],
    /// Feature bits of the mapping type.
    pub features: TargetFeatures,
    /// The constructed target.
    pub target: Arc<dyn DmTarget>,
}

impl TargetEntry {
    /// Last sector this entry covers. # C: O(1)
    pub fn high(&self) -> u64 { self.begin + self.len - 1 }
}

/// A table under construction. It becomes a [`Table`] only once it is
/// complete, so a half-built table can never be installed.
pub struct TableBuilder {
    targets: Vec<TargetEntry>,
    /// Whether the device the table will drive may be written.
    writable: bool,
    singleton: bool,
    immutable_type: Option<&'static str>,
    /// Refusal reason from the last failed `add_target`.
    pub error: Option<&'static str>,
}

/// A complete table, ready to be installed in a device's table slot.
pub struct Table {
    targets: Vec<TargetEntry>,
    index: btree::Index,
    size: u64,
    writable: bool,
}

impl TableBuilder {
    /// Start a table for a device that may or may not be written. # C: O(1)
    pub fn new(writable: bool) -> Self {
        Self { targets: Vec::new(), writable, singleton: false, immutable_type: None, error: None }
    }

    /// Targets added so far. # C: O(1)
    pub fn len(&self) -> usize { self.targets.len() }

    /// Whether no target has been added yet. # C: O(1)
    pub fn is_empty(&self) -> bool { self.targets.is_empty() }

    /// Append one target line. Order matters: the checks below run in the
    /// reference's order, so a table that is wrong in more than one way is
    /// refused for the same reason it would be there.
    /// # C: O(N_args) plus the target's own constructor
    pub fn add_target(&mut self, tt: &TargetType, begin: u64, len: u64, params: &str,
                      resolver: &dyn DeviceResolver) -> DmResult<()> {
        self.error = None;
        // A singleton already present means nothing may follow it, whatever
        // the new line names.
        if self.singleton { return Err(self.fail("target type must appear alone in table")); }
        if len == 0 { return Err(self.fail("zero-length target")); }
        match begin.checked_add(len) {
            Some(end) if end <= MAX_TABLE_SECTORS => {}
            _ => return Err(self.fail("too large device")),
        }
        if tt.features.singleton {
            if !self.targets.is_empty() { return Err(self.fail("singleton target type must appear alone in table")); }
            self.singleton = true;
        }
        if tt.features.always_writeable && !self.writable {
            return Err(self.fail("target type may not be included in a read-only table"));
        }
        match self.immutable_type {
            Some(name) if name != tt.name =>
                return Err(self.fail("immutable target type cannot be mixed with other target types")),
            Some(_) => {}
            None if tt.features.immutable => {
                if !self.targets.is_empty() {
                    return Err(self.fail("immutable target type cannot be mixed with other target types"));
                }
                self.immutable_type = Some(tt.name);
            }
            None => {}
        }
        // Tiling: the first target starts at zero and each later one starts
        // exactly where the previous ended. A gap would leave sectors with no
        // owner and an overlap would give one sector two, and either turns a
        // lookup into a silently wrong destination rather than an error.
        if !self.adjoins(begin) { return Err(self.fail("Gap in table")); }

        let words = split_args(params);
        let argv: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
        let mut ctr = Ctr { begin, len, argv: &argv, resolver, error: None };
        let target = match (tt.ctr)(&mut ctr) {
            Ok(t) => t,
            Err(e) => { self.error = ctr.error.or(Some("Unknown error")); return Err(e); }
        };
        self.targets.push(TargetEntry {
            begin, len, type_name: tt.name, version: tt.version, features: tt.features, target,
        });
        Ok(())
    }

    fn adjoins(&self, begin: u64) -> bool {
        match self.targets.last() {
            None => begin == 0,
            Some(prev) => begin == prev.begin + prev.len,
        }
    }

    fn fail(&mut self, why: &'static str) -> Errno { self.error = Some(why); Errno::Einval }

    /// Finish the table and build its index. An empty table is legal — the
    /// reference lets a device carry one and errors every I/O to it, because a
    /// device must exist before its table can be loaded. # C: O(N_targets)
    pub fn complete(self) -> Table {
        let highs: Vec<u64> = self.targets.iter().map(|t| t.high()).collect();
        let size = self.targets.last().map_or(0, |t| t.begin + t.len);
        Table { index: btree::Index::build(&highs), targets: self.targets, size, writable: self.writable }
    }
}

impl Table {
    /// Total length of the mapped device this table describes, in sectors.
    /// # C: O(1)
    pub fn size(&self) -> u64 { self.size }

    /// Whether the table permits writes. # C: O(1)
    pub fn writable(&self) -> bool { self.writable }

    /// Number of targets. # C: O(1)
    pub fn num_targets(&self) -> usize { self.targets.len() }

    /// The targets in table order. # C: O(1)
    pub fn targets(&self) -> &[TargetEntry] { &self.targets }

    /// Target at a table position. # C: O(1)
    pub fn target(&self, i: usize) -> Option<&TargetEntry> { self.targets.get(i) }

    /// Target covering `sector`, or `None` past the end. # C: O(log N)
    pub fn find_target(&self, sector: u64) -> Option<&TargetEntry> {
        self.targets.get(self.find_index(sector)?)
    }

    /// Table position of the target covering `sector`. # C: O(log N)
    pub fn find_index(&self, sector: u64) -> Option<usize> { self.index.find(sector, self.size) }

    /// Depth of the built index, which the index tests assert against.
    /// # C: O(1)
    pub fn index_depth(&self) -> usize { self.index.depth() }

    /// Every device every target depends on, in table order, deduplicated by
    /// device number the way the dependency report is. # C: O(N_devices^2)
    pub fn devices(&self) -> Vec<DmDev> {
        let mut out: Vec<DmDev> = Vec::new();
        for t in &self.targets {
            for d in t.target.iterate_devices() {
                if !out.iter().any(|e| e.major == d.major && e.minor == d.minor) { out.push(d); }
            }
        }
        out
    }

    /// Stack every target's constraints onto the device's queue limits.
    /// # C: O(N_targets)
    pub fn set_restrictions(&self, limits: &mut QueueLimits) {
        for t in &self.targets { t.target.io_hints(limits); }
    }

    /// Render the whole table as the status report prints it: one line per
    /// target, each `<begin> <len> <type> <target text>`. # C: O(output)
    pub fn status_lines(&self, kind: StatusType) -> Vec<String> {
        self.targets.iter().map(|t| {
            let body = t.target.status(kind);
            let mut s = t.begin.to_string();
            s.push(' '); s.push_str(&t.len.to_string());
            s.push(' '); s.push_str(t.type_name);
            if !body.is_empty() { s.push(' '); s.push_str(&body); }
            s
        }).collect()
    }

    /// Run every target's pre-suspend hook, in table order. # C: O(N_targets)
    pub fn presuspend(&self) { for t in &self.targets { t.target.presuspend(); } }
    /// Undo a pre-suspend that will not be followed by a suspend. # C: O(N_targets)
    pub fn presuspend_undo(&self) { for t in &self.targets { t.target.presuspend_undo(); } }
    /// Run every target's post-suspend hook. # C: O(N_targets)
    pub fn postsuspend(&self) { for t in &self.targets { t.target.postsuspend(); } }
    /// Ask every target whether the resume may proceed. The first refusal
    /// stops the walk, because a target that has already agreed must not be
    /// resumed when a later one has not. # C: O(N_targets)
    pub fn preresume(&self) -> DmResult<()> {
        for t in &self.targets { t.target.preresume()?; }
        Ok(())
    }
    /// Run every target's resume hook. # C: O(N_targets)
    pub fn resume(&self) { for t in &self.targets { t.target.resume(); } }
}
