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
    pub mem_current: u64,
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
            swap_max: None, mem_oom_group: false, zswap_max: None, mem_current: 0,
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
    /// pid → bytes currently charged to memory controller. Tracked here
    /// (not in the VMM) so `remove_proc` can uncharge a process's whole
    /// footprint on exit — symmetric by construction, no reliance on
    /// every VMM free path being instrumented.
    pub(super) proc_charge: BTreeMap<u64, u64>,
    pub(super) mounted: bool,
}

pub const ROOT: u64 = 1;

impl Tree {
    /// Empty (unmounted) tree.
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { nodes: BTreeMap::new(), next_id: ROOT, proc_cg: BTreeMap::new(),
               thread_cg: BTreeMap::new(), proc_charge: BTreeMap::new(), mounted: false }
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
