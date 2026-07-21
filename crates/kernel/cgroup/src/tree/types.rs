use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use vfs::VfsError;

use super::controllers::ALL;

pub type KResult<T> = core::result::Result<T, VfsError>;

/// One cgroup's cpu.max bandwidth state, snapshotted for the scanner.
/// Times in ns.
pub struct CpuGroup {
    pub cgid: u64,
    pub quota_ns: u64,
    pub period_ns: u64,
    pub base_ns: u64,
    pub period_start_ns: u64,
    pub throttled: bool,
    pub pids: Vec<u64>,
}

/// Resident-memory owner class.  A charge has exactly one class for its
/// lifetime; aggregate totals are derived from these fields, never kept as a
/// second mutable ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryKind {
    Anon,
    File,
    Shmem,
    KernelStack,
    SlabReclaimable,
    SlabUnreclaimable,
    PageTables,
    PerCpu,
    Sock,
    Vmalloc,
}

/// Cumulative memory-controller event emitted by the owner that observed it.
/// Reclaim and OOM selection deliberately own their respective event calls;
/// a failed charge only records `Max` here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryEvent { Low, High, Max, Oom, OomKill }

/// Result of one resident-memory reservation before any external reclaim
/// work runs.  The tree reports facts only: policy lives behind the
/// registered pressure hook after the hierarchy lock is released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryCharge {
    Charged { crossed_high: bool },
    Max { limit_cgid: u64 },
}

/// A pressure transition exported by the leaf cgroup owner.  `High` is
/// emitted only for an actual below-to-above high crossing; `Max` denotes an
/// uncharged hard-limit failure that may be reclaimed and retried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryPressure { High, Max { limit_cgid: u64 } }

/// Outcome of a pressure owner transaction.  Retry is valid only for an
/// uncommitted `memory.max` reservation after real memory was released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryPressureResult { Continue, Retry }

/// Direct resident-byte ledger for one cgroup.  `memory.current` and
/// `memory.stat` derive from this one canonical owner-class source.
#[derive(Clone, Copy, Default)]
pub struct MemoryStats {
    pub anon: u64,
    pub file: u64,
    pub shmem: u64,
    pub kernel_stack: u64,
    pub slab_reclaimable: u64,
    pub slab_unreclaimable: u64,
    pub pagetables: u64,
    pub percpu: u64,
    pub sock: u64,
    pub vmalloc: u64,
}

impl MemoryStats {
    pub fn total(&self) -> u64 {
        self.anon.saturating_add(self.file).saturating_add(self.shmem)
            .saturating_add(self.kernel_stack).saturating_add(self.slab_reclaimable)
            .saturating_add(self.slab_unreclaimable).saturating_add(self.pagetables)
            .saturating_add(self.percpu).saturating_add(self.sock).saturating_add(self.vmalloc)
    }

    /// Linux `memory.stat:file`: ordinary page cache plus swap-backed shmem.
    pub fn file_total(&self) -> u64 { self.file.saturating_add(self.shmem) }

    /// Linux `memory.stat:kernel`: all directly-accounted kernel classes.
    pub fn kernel_total(&self) -> u64 {
        self.kernel_stack.saturating_add(self.slab_reclaimable)
            .saturating_add(self.slab_unreclaimable).saturating_add(self.pagetables)
            .saturating_add(self.percpu).saturating_add(self.sock).saturating_add(self.vmalloc)
    }

    pub fn get(&self, kind: MemoryKind) -> u64 {
        match kind {
            MemoryKind::Anon => self.anon,
            MemoryKind::File => self.file,
            MemoryKind::Shmem => self.shmem,
            MemoryKind::KernelStack => self.kernel_stack,
            MemoryKind::SlabReclaimable => self.slab_reclaimable,
            MemoryKind::SlabUnreclaimable => self.slab_unreclaimable,
            MemoryKind::PageTables => self.pagetables,
            MemoryKind::PerCpu => self.percpu,
            MemoryKind::Sock => self.sock,
            MemoryKind::Vmalloc => self.vmalloc,
        }
    }

    pub fn add(&mut self, kind: MemoryKind, bytes: u64) {
        let slot = match kind {
            MemoryKind::Anon => &mut self.anon,
            MemoryKind::File => &mut self.file,
            MemoryKind::Shmem => &mut self.shmem,
            MemoryKind::KernelStack => &mut self.kernel_stack,
            MemoryKind::SlabReclaimable => &mut self.slab_reclaimable,
            MemoryKind::SlabUnreclaimable => &mut self.slab_unreclaimable,
            MemoryKind::PageTables => &mut self.pagetables,
            MemoryKind::PerCpu => &mut self.percpu,
            MemoryKind::Sock => &mut self.sock,
            MemoryKind::Vmalloc => &mut self.vmalloc,
        };
        *slot = slot.saturating_add(bytes);
    }

    pub fn sub(&mut self, kind: MemoryKind, bytes: u64) {
        let slot = match kind {
            MemoryKind::Anon => &mut self.anon,
            MemoryKind::File => &mut self.file,
            MemoryKind::Shmem => &mut self.shmem,
            MemoryKind::KernelStack => &mut self.kernel_stack,
            MemoryKind::SlabReclaimable => &mut self.slab_reclaimable,
            MemoryKind::SlabUnreclaimable => &mut self.slab_unreclaimable,
            MemoryKind::PageTables => &mut self.pagetables,
            MemoryKind::PerCpu => &mut self.percpu,
            MemoryKind::Sock => &mut self.sock,
            MemoryKind::Vmalloc => &mut self.vmalloc,
        };
        *slot = slot.saturating_sub(bytes);
    }
}

/// Direct event ledger for one cgroup; hierarchy is derived at read time.
#[derive(Clone, Copy, Default)]
pub struct MemoryEvents { pub low: u64, pub high: u64, pub max: u64, pub oom: u64, pub oom_kill: u64 }

impl MemoryEvents {
    pub fn add(&mut self, event: MemoryEvent) {
        match event {
            MemoryEvent::Low => self.low = self.low.saturating_add(1),
            MemoryEvent::High => self.high = self.high.saturating_add(1),
            MemoryEvent::Max => self.max = self.max.saturating_add(1),
            MemoryEvent::Oom => self.oom = self.oom.saturating_add(1),
            MemoryEvent::OomKill => self.oom_kill = self.oom_kill.saturating_add(1),
        }
    }
}

/// One cgroup directory.
pub struct Node {
    pub name: String,
    pub parent: Option<u64>,
    pub children: BTreeMap<String, u64>,
    /// DAC owner `(i_uid, i_gid)` of the cgroup DIRECTORY inode. Stamped to the
    /// creating task's fsuid/fsgid at `mkdir` (Linux `cgroup_create` uses
    /// `current_fsuid`/`current_fsgid`) and re-writable via `chown(2)` on the
    /// dir — systemd's cgroup delegation chowns the delegated subtree's
    /// directory to the target uid so the unprivileged user manager owns it
    /// (`26§4`). Default root (0).
    pub uid: u32,
    pub gid: u32,
    /// Default owner of this node's control-file inodes that were not
    /// individually chowned. It starts as the creation owner. When every
    /// currently visible interface is chowned to the directory owner, the
    /// default follows that recursive delegation too, so controller files made
    /// visible later retain the delegated owner. Kept separate from `uid` so a
    /// boundary which delegates only selected files keeps its resource controls
    /// (`memory.max`, …) root-owned.
    pub file_uid: u32,
    pub file_gid: u32,
    /// Per-control-file `chown(2)` overrides `(uid, gid)` keyed by file name.
    /// systemd delegates ONLY `cgroup.procs`/`cgroup.threads`/
    /// `cgroup.subtree_control` by chowning them to the user; the rest stay at
    /// the frozen creation owner.
    pub file_owner: BTreeMap<String, (u32, u32)>,
    /// Member process pids directly in this cgroup (cgroup.procs).
    pub procs: BTreeSet<u64>,
    /// Non-leader thread count directly in this cgroup. pids.current counts
    /// every task (Linux pids controller), so threads charge here too.
    pub threads: u64,
    /// Controllers this node delegates to children (cgroup.subtree_control).
    pub subtree_control: u8,
    /// Controllers available here = parent's subtree_control (root: ALL).
    pub avail: u8,
    pub frozen: bool,
    // pids controller
    pub pids_max: Option<u64>,
    // memory controller (bytes)
    pub mem_max: Option<u64>,
    pub mem_high: Option<u64>,
    pub mem_low: u64,
    pub mem_min: u64,
    pub swap_max: Option<u64>,
    pub mem_oom_group: bool,
    pub zswap_max: Option<u64>,
    pub memory: MemoryStats,
    pub memory_events: MemoryEvents,
    /// Bytes of anonymous memory whose canonical swap slot is charged to
    /// this memcg. The slot, rather than a task, owns this charge so fork,
    /// migration, and swap-in cannot double-account or lose it.
    pub swap_current: u64,
    // cpu controller
    pub cpu_weight: u32,
    pub cpu_quota: Option<u64>,
    pub cpu_period: u64,
    // cpu.max bandwidth runtime state (`13§3`/`26`): runtime baseline at
    // period start, period start timestamp, and whether members are
    // currently throttled (frozen for being over quota this period).
    pub cpu_runtime_base_ns: u64,
    pub cpu_period_start_ns: u64,
    pub cpu_throttled: bool,
    // io controller — opaque per-device lines, stored verbatim
    pub io_max: String,
    pub io_weight: u32,
    // io.stat accounting (`26`): cumulative bytes/ops charged to this
    // node at block submit (read/write). io.stat reports the subtree sum.
    pub io_rbytes: u64,
    pub io_wbytes: u64,
    pub io_rios: u64,
    pub io_wios: u64,
    // cpuset controller
    pub cpuset_cpus: String,
    pub cpuset_mems: String,
}

impl Node {
    pub(super) fn new(name: String, parent: Option<u64>, avail: u8) -> Self {
        Self {
            name, parent, children: BTreeMap::new(), procs: BTreeSet::new(),
            uid: 0, gid: 0, file_uid: 0, file_gid: 0, file_owner: BTreeMap::new(),
            threads: 0,
            subtree_control: 0, avail, frozen: false,
            pids_max: None,
            mem_max: None, mem_high: None, mem_low: 0, mem_min: 0,
            swap_max: None, mem_oom_group: false, zswap_max: None,
            memory: MemoryStats::default(), memory_events: MemoryEvents::default(),
            swap_current: 0,
            cpu_weight: 100, cpu_quota: None, cpu_period: 100_000,
            cpu_runtime_base_ns: 0, cpu_period_start_ns: 0, cpu_throttled: false,
            io_max: String::new(), io_weight: 100,
            io_rbytes: 0, io_wbytes: 0, io_rios: 0, io_wios: 0,
            cpuset_cpus: String::new(), cpuset_mems: String::new(),
        }
    }
}

pub struct Tree {
    pub(super) nodes: BTreeMap<u64, Node>,
    pub(super) next_id: u64,
    /// pid → cgid membership index (for fork inheritance + /proc).
    pub(super) proc_cg: BTreeMap<u64, u64>,
    /// thread tid → owning cgroup, for uncharge on thread exit.
    pub(super) thread_cg: BTreeMap<u64, u64>,
    pub(super) mounted: bool,
}

pub const ROOT: u64 = 1;

impl Tree {
    /// Empty (unmounted) tree.
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { nodes: BTreeMap::new(), next_id: ROOT, proc_cg: BTreeMap::new(),
               thread_cg: BTreeMap::new(), mounted: false }
    }

    /// True once the root cgroup exists.
    /// # C: O(1)
    pub fn is_mounted(&self) -> bool { self.mounted }

    /// Create the root cgroup on first mount. Idempotent.
    /// # C: O(1)
    pub fn mount_root(&mut self) -> bool {
        if self.mounted { return false; }
        self.nodes.insert(ROOT, Node::new(String::new(), None, ALL));
        self.next_id = ROOT + 1;
        self.mounted = true;
        true
    }

    /// Borrow a node by id.
    /// # C: O(log n)
    pub fn node(&self, id: u64) -> Option<&Node> { self.nodes.get(&id) }
}
