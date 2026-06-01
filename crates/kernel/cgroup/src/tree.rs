// cgroup v2 hierarchy state per `26§4`. Single unified tree; every
// node is a directory under `/sys/fs/cgroup`. This module owns the
// pure state + logic (no VFS/inode coupling — that is `inode.rs`).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vfs::VfsError;

pub type KResult<T> = core::result::Result<T, VfsError>;

// Controller bitset. Order matches the canonical
// `cgroup.controllers` listing.
pub const CPU: u8 = 1 << 0;
pub const MEMORY: u8 = 1 << 1;
pub const IO: u8 = 1 << 2;
pub const PIDS: u8 = 1 << 3;
pub const CPUSET: u8 = 1 << 4;
pub const ALL: u8 = CPU | MEMORY | IO | PIDS | CPUSET;

/// Controller name ↔ bit. Linux ordering: cpu cpuset io memory pids.
const CTRL_TABLE: &[(&str, u8)] = &[
    ("cpu", CPU),
    ("cpuset", CPUSET),
    ("io", IO),
    ("memory", MEMORY),
    ("pids", PIDS),
];

fn ctrl_bit(name: &str) -> Option<u8> {
    CTRL_TABLE.iter().find(|(n, _)| *n == name).map(|(_, b)| *b)
}

/// Controller a `<ctrl>.<knob>` interface file belongs to (None for
/// the always-present `cgroup.*` core files).
fn file_controller(file: &str) -> Option<u8> {
    let pfx = file.split('.').next()?;
    match pfx {
        "cgroup" => None,
        "pids" => Some(PIDS),
        "memory" => Some(MEMORY),
        "cpu" => Some(CPU),
        "io" => Some(IO),
        "cpuset" => Some(CPUSET),
        _ => None,
    }
}

/// Space-separated controller list for a bitset, canonical order.
fn ctrl_list(set: u8) -> String {
    let mut out = String::new();
    for (n, b) in CTRL_TABLE {
        if set & b != 0 {
            if !out.is_empty() { out.push(' '); }
            out.push_str(n);
        }
    }
    out
}

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

/// "max" sentinel ↔ Option<u64>. cgroup v2 uses the literal token
/// `max` for "no limit" across pids.max / memory.max / cpu.max.
fn parse_max(tok: &str) -> Option<Option<u64>> {
    let t = tok.trim();
    if t == "max" { return Some(None); }
    t.parse::<u64>().ok().map(Some)
}

fn fmt_max(v: Option<u64>) -> String {
    match v { Some(n) => n.to_string(), None => "max".to_string() }
}

/// One cgroup directory.
pub struct Node {
    pub name: String,
    pub parent: Option<u64>,
    pub children: BTreeMap<String, u64>,
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
    // cpuset controller
    pub cpuset_cpus: String,
    pub cpuset_mems: String,
}

impl Node {
    fn new(name: String, parent: Option<u64>, avail: u8) -> Self {
        Self {
            name, parent, children: BTreeMap::new(), procs: BTreeSet::new(),
            threads: 0,
            subtree_control: 0, avail, frozen: false,
            pids_max: None,
            mem_max: None, mem_high: None, mem_low: 0, mem_min: 0,
            swap_max: None, mem_current: 0,
            cpu_weight: 100, cpu_quota: None, cpu_period: 100_000,
            cpu_runtime_base_ns: 0, cpu_period_start_ns: 0, cpu_throttled: false,
            io_max: String::new(), io_weight: 100,
            cpuset_cpus: String::new(), cpuset_mems: String::new(),
        }
    }
}

pub struct Tree {
    nodes: BTreeMap<u64, Node>,
    next_id: u64,
    /// pid → cgid membership index (for fork inheritance + /proc).
    proc_cg: BTreeMap<u64, u64>,
    /// thread tid → owning cgroup, for uncharge on thread exit.
    thread_cg: BTreeMap<u64, u64>,
    /// pid → bytes currently charged to memory controller. Tracked here
    /// (not in the VMM) so `remove_proc` can uncharge a process's whole
    /// footprint on exit — symmetric by construction, no reliance on
    /// every VMM free path being instrumented.
    proc_charge: BTreeMap<u64, u64>,
    mounted: bool,
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

    /// Resolve a relative cgroup path ("" or "a/b/c") to a node id.
    /// # C: O(components · log n)
    pub fn resolve(&self, rel: &str) -> Option<u64> {
        let mut cur = ROOT;
        for comp in rel.split('/').filter(|s| !s.is_empty()) {
            cur = *self.nodes.get(&cur)?.children.get(comp)?;
        }
        Some(cur)
    }

    /// Absolute hierarchy path of a node (`/` for root, `/a/b` else).
    /// # C: O(depth · log n)
    pub fn path_of(&self, id: u64) -> String {
        let mut parts: Vec<&str> = Vec::new();
        let mut cur = id;
        while let Some(n) = self.nodes.get(&cur) {
            match n.parent {
                Some(p) => { parts.push(n.name.as_str()); cur = p; }
                None => break,
            }
        }
        if parts.is_empty() { return "/".to_string(); }
        parts.reverse();
        let mut out = String::new();
        for p in parts { out.push('/'); out.push_str(p); }
        out
    }

    /// Create child `name` under `parent`. Returns the new id +
    /// controllers available to it (= parent.subtree_control).
    /// # C: O(log n)
    pub fn create(&mut self, parent: u64, name: &str) -> KResult<(u64, u8)> {
        if name.is_empty() || name.contains('/') { return Err(VfsError::Einval); }
        let avail = {
            let p = self.nodes.get(&parent).ok_or(VfsError::Enoent)?;
            if p.children.contains_key(name) { return Err(VfsError::Eexist); }
            p.subtree_control
        };
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.insert(id, Node::new(name.to_string(), Some(parent), avail));
        self.nodes.get_mut(&parent).unwrap().children.insert(name.to_string(), id);
        Ok((id, avail))
    }

    /// Remove an empty leaf cgroup. ENOTEMPTY if it has children or
    /// member procs; EBUSY for the root.
    /// # C: O(log n)
    pub fn remove(&mut self, id: u64) -> KResult<()> {
        if id == ROOT { return Err(VfsError::Ebusy); }
        let (parent, name) = {
            let n = self.nodes.get(&id).ok_or(VfsError::Enoent)?;
            if !n.children.is_empty() || !n.procs.is_empty() {
                return Err(VfsError::Enotempty);
            }
            (n.parent.unwrap(), n.name.clone())
        };
        self.nodes.get_mut(&parent).unwrap().children.remove(&name);
        self.nodes.remove(&id);
        Ok(())
    }

    /// Add a process to a cgroup (fork inheritance / explicit attach).
    /// Removes it from any prior cgroup first.
    /// # C: O(log n)
    pub fn add_proc(&mut self, cgid: u64, pid: u64) {
        if let Some(old) = self.proc_cg.insert(pid, cgid) {
            if old == cgid { return; }
            if let Some(n) = self.nodes.get_mut(&old) { n.procs.remove(&pid); }
            // Migrate the process's memory charge to the destination node
            // so memory.current stays consistent across moves.
            let charged = self.proc_charge.get(&pid).copied().unwrap_or(0);
            if charged != 0 {
                if let Some(n) = self.nodes.get_mut(&old) { n.mem_current = n.mem_current.saturating_sub(charged); }
                if let Some(n) = self.nodes.get_mut(&cgid) { n.mem_current += charged; }
            }
        }
        if let Some(n) = self.nodes.get_mut(&cgid) { n.procs.insert(pid); }
    }

    /// Drop a process on exit: remove membership AND uncharge its whole
    /// memory footprint (symmetric with `try_charge_mem`).
    /// # C: O(log n)
    pub fn remove_proc(&mut self, pid: u64) {
        if let Some(old) = self.proc_cg.remove(&pid) {
            if let Some(n) = self.nodes.get_mut(&old) { n.procs.remove(&pid); }
            if let Some(c) = self.proc_charge.remove(&pid) {
                if let Some(n) = self.nodes.get_mut(&old) { n.mem_current = n.mem_current.saturating_sub(c); }
            }
        }
    }

    /// Charge a new thread `tid` to `parent_pid`'s cgroup (pids.current
    /// counts every task). Idempotent per tid.
    /// # C: O(log n)
    pub fn add_thread(&mut self, parent_pid: u64, tid: u64) {
        if self.thread_cg.contains_key(&tid) { return; }
        let cg = self.cgroup_of(parent_pid);
        self.thread_cg.insert(tid, cg);
        if let Some(n) = self.nodes.get_mut(&cg) { n.threads += 1; }
    }

    /// Uncharge a thread on exit.
    /// # C: O(log n)
    pub fn remove_thread(&mut self, tid: u64) {
        if let Some(cg) = self.thread_cg.remove(&tid) {
            if let Some(n) = self.nodes.get_mut(&cg) { n.threads = n.threads.saturating_sub(1); }
        }
    }

    /// The cgroup id a pid belongs to (root if untracked).
    /// # C: O(log n)
    pub fn cgroup_of(&self, pid: u64) -> u64 {
        self.proc_cg.get(&pid).copied().unwrap_or(ROOT)
    }

    /// pids.current for a node = every TASK (procs + threads) in its whole
    /// subtree (Linux pids controller counts threads, not just leaders).
    fn subtree_proc_count(&self, id: u64) -> u64 {
        let n = match self.nodes.get(&id) { Some(n) => n, None => return 0 };
        let mut c = n.procs.len() as u64 + n.threads;
        for &child in n.children.values() { c += self.subtree_proc_count(child); }
        c
    }

    /// True iff a fork producing one more task in `cgid`'s subtree
    /// would exceed any ancestor pids.max (Linux pids controller).
    /// # C: O(depth · subtree)
    pub fn fork_would_exceed_pids(&self, cgid: u64) -> bool {
        let mut cur = Some(cgid);
        while let Some(id) = cur {
            let n = match self.nodes.get(&id) { Some(n) => n, None => break };
            if n.avail & PIDS != 0 {
                if let Some(max) = n.pids_max {
                    if self.subtree_proc_count(id) + 1 > max { return true; }
                }
            }
            cur = n.parent;
        }
        false
    }

    /// True iff the node's subtree has any member process.
    /// # C: O(subtree)
    pub fn populated(&self, id: u64) -> bool { self.subtree_proc_count(id) > 0 }

    /// memory.current for a node = bytes charged at this node plus every
    /// descendant (hierarchical, matching cgroup v2 memcg).
    /// # C: O(subtree)
    pub fn subtree_mem(&self, id: u64) -> u64 {
        let n = match self.nodes.get(&id) { Some(n) => n, None => return 0 };
        let mut b = n.mem_current;
        for &child in n.children.values() { b += self.subtree_mem(child); }
        b
    }

    /// Try to charge `bytes` of memory to `pid`'s cgroup. Walks ancestors
    /// with the memory controller enabled + a `memory.max` set; if any
    /// would be exceeded the charge is rejected wholesale (caller returns
    /// ENOMEM). On success the bytes land on the leaf node and the
    /// per-pid charge record (for exit uncharge). Zero bytes always OK.
    /// # C: O(depth · subtree)
    pub fn try_charge_mem(&mut self, pid: u64, bytes: u64) -> bool {
        if bytes == 0 { return true; }
        let cg = self.cgroup_of(pid);
        let mut cur = Some(cg);
        while let Some(id) = cur {
            let n = match self.nodes.get(&id) { Some(n) => n, None => break };
            if n.avail & MEMORY != 0 {
                if let Some(max) = n.mem_max {
                    if self.subtree_mem(id) + bytes > max { return false; }
                }
            }
            cur = n.parent;
        }
        if let Some(n) = self.nodes.get_mut(&cg) { n.mem_current += bytes; }
        *self.proc_charge.entry(pid).or_insert(0) += bytes;
        true
    }

    /// Uncharge `bytes` from `pid`'s cgroup (memory freed). Clamped at the
    /// recorded charge so double-uncharge can't underflow.
    /// # C: O(log n)
    pub fn uncharge_mem(&mut self, pid: u64, bytes: u64) {
        if bytes == 0 { return; }
        let rec = match self.proc_charge.get_mut(&pid) { Some(r) => r, None => return };
        let amt = bytes.min(*rec);
        *rec -= amt;
        if *rec == 0 { self.proc_charge.remove(&pid); }
        let cg = self.cgroup_of(pid);
        if let Some(n) = self.nodes.get_mut(&cg) { n.mem_current = n.mem_current.saturating_sub(amt); }
    }

    /// Bytes currently charged to `pid` (test/observability helper).
    /// # C: O(log n)
    pub fn charged(&self, pid: u64) -> u64 { self.proc_charge.get(&pid).copied().unwrap_or(0) }

    /// Snapshot of every cgroup that has a `cpu.max` quota set, for the
    /// bandwidth scanner: `(cgid, quota_ns, period_ns, base, period_start,
    /// throttled, member_pids)`. cpu.max quota/period are in microseconds
    /// (Linux); converted to ns here so the scanner compares against
    /// `sum_exec_runtime_ns`.
    /// # C: O(N nodes + N members)
    pub fn cpu_quota_groups(&self) -> Vec<CpuGroup> {
        let mut out = Vec::new();
        for (&id, n) in self.nodes.iter() {
            if let Some(q_us) = n.cpu_quota {
                let mut pids = Vec::new();
                self.collect_pids(id, &mut pids);
                out.push(CpuGroup {
                    cgid: id,
                    quota_ns: q_us.saturating_mul(1000),
                    period_ns: n.cpu_period.saturating_mul(1000),
                    base_ns: n.cpu_runtime_base_ns,
                    period_start_ns: n.cpu_period_start_ns,
                    throttled: n.cpu_throttled,
                    pids,
                });
            }
        }
        out
    }

    /// Commit a bandwidth-scan decision: set throttled flag and, on a
    /// period refill, re-baseline runtime + period start.
    /// # C: O(log n)
    pub fn set_cpu_state(&mut self, cgid: u64, throttled: bool, base_ns: u64, period_start_ns: u64) {
        if let Some(n) = self.nodes.get_mut(&cgid) {
            n.cpu_throttled = throttled;
            n.cpu_runtime_base_ns = base_ns;
            n.cpu_period_start_ns = period_start_ns;
        }
    }

    /// All member pids in a node's subtree — for cgroup.kill / freeze.
    /// # C: O(subtree)
    pub fn subtree_pids(&self, id: u64) -> Vec<u64> {
        let mut out = Vec::new();
        self.collect_pids(id, &mut out);
        out
    }
    fn collect_pids(&self, id: u64, out: &mut Vec<u64>) {
        if let Some(n) = self.nodes.get(&id) {
            out.extend(n.procs.iter().copied());
            for &c in n.children.values() { self.collect_pids(c, out); }
        }
    }

    /// Set the freezer flag on a node.
    /// # C: O(log n)
    pub fn set_frozen(&mut self, id: u64, v: bool) {
        if let Some(n) = self.nodes.get_mut(&id) { n.frozen = v; }
    }

    /// Apply a `+ctrl -ctrl` write to subtree_control. Returns the
    /// new available-set for children so the caller can re-sync their
    /// interface files. EINVAL on an unknown controller or one not
    /// available here; ENOSPC if enabling a controller a child lacks.
    /// # C: O(tokens + children)
    pub fn write_subtree_control(&mut self, id: u64, buf: &str) -> KResult<u8> {
        let avail = self.nodes.get(&id).ok_or(VfsError::Enoent)?.avail;
        let mut set = self.nodes.get(&id).unwrap().subtree_control;
        for tok in buf.split_whitespace() {
            let (add, name) = match tok.as_bytes().first() {
                Some(b'+') => (true, &tok[1..]),
                Some(b'-') => (false, &tok[1..]),
                _ => return Err(VfsError::Einval),
            };
            let bit = ctrl_bit(name).ok_or(VfsError::Einval)?;
            if add {
                if avail & bit == 0 { return Err(VfsError::Enospc); }
                set |= bit;
            } else {
                set &= !bit;
            }
        }
        self.nodes.get_mut(&id).unwrap().subtree_control = set;
        // Propagate new availability to existing children.
        let kids: Vec<u64> = self.nodes.get(&id).unwrap().children.values().copied().collect();
        for k in &kids {
            if let Some(c) = self.nodes.get_mut(k) { c.avail = set; }
        }
        Ok(set)
    }

    /// Read a control file's current contents (`26§4` table).
    /// # C: O(subtree) for populated/pids counters; O(members) for procs
    pub fn read_file(&self, id: u64, file: &str) -> KResult<Vec<u8>> {
        let n = self.nodes.get(&id).ok_or(VfsError::Enoent)?;
        if let Some(bit) = file_controller(file) {
            if n.avail & bit == 0 { return Err(VfsError::Enoent); }
        }
        let s: String = match file {
            "cgroup.procs" => {
                let mut o = String::new();
                for p in &n.procs { o.push_str(&p.to_string()); o.push('\n'); }
                o
            }
            "cgroup.threads" => {
                let mut o = String::new();
                for p in &n.procs { o.push_str(&p.to_string()); o.push('\n'); }
                o
            }
            "cgroup.controllers" => { let mut o = ctrl_list(n.avail); o.push('\n'); o }
            "cgroup.subtree_control" => { let mut o = ctrl_list(n.subtree_control); o.push('\n'); o }
            "cgroup.events" => format!("populated {}\nfrozen {}\n",
                self.populated(id) as u8, n.frozen as u8),
            "cgroup.type" => "domain\n".to_string(),
            "cgroup.freeze" => format!("{}\n", n.frozen as u8),
            "cgroup.stat" => {
                let desc = n.children.len();
                format!("nr_descendants {}\nnr_dying_descendants 0\n", desc)
            }
            "cgroup.max.depth" => "max\n".to_string(),
            "cgroup.max.descendants" => "max\n".to_string(),
            "pids.current" => format!("{}\n", self.subtree_proc_count(id)),
            "pids.max" => { let mut o = fmt_max(n.pids_max); o.push('\n'); o }
            "pids.peak" => format!("{}\n", self.subtree_proc_count(id)),
            "pids.events" => "max 0\n".to_string(),
            "memory.current" => format!("{}\n", self.subtree_mem(id)),
            "memory.max" => { let mut o = fmt_max(n.mem_max); o.push('\n'); o }
            "memory.high" => { let mut o = fmt_max(n.mem_high); o.push('\n'); o }
            "memory.low" => format!("{}\n", n.mem_low),
            "memory.min" => format!("{}\n", n.mem_min),
            "memory.swap.max" => { let mut o = fmt_max(n.swap_max); o.push('\n'); o }
            "memory.swap.current" => "0\n".to_string(),
            "memory.events" => "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n".to_string(),
            "memory.stat" => format!("anon {}\nfile 0\nkernel_stack 0\nslab 0\n", self.subtree_mem(id)),
            "cpu.weight" => format!("{}\n", n.cpu_weight),
            "cpu.max" => match n.cpu_quota {
                Some(q) => format!("{} {}\n", q, n.cpu_period),
                None => format!("max {}\n", n.cpu_period),
            },
            "cpu.stat" => "usage_usec 0\nuser_usec 0\nsystem_usec 0\n".to_string(),
            "io.stat" => String::new(),
            "io.max" => n.io_max.clone(),
            "io.weight" => format!("default {}\n", n.io_weight),
            "cpuset.cpus" => { let mut o = n.cpuset_cpus.clone(); o.push('\n'); o }
            "cpuset.mems" => { let mut o = n.cpuset_mems.clone(); o.push('\n'); o }
            "cpuset.cpus.effective" => { let mut o = n.cpuset_cpus.clone(); o.push('\n'); o }
            "cpuset.mems.effective" => { let mut o = n.cpuset_mems.clone(); o.push('\n'); o }
            _ => return Err(VfsError::Enoent),
        };
        Ok(s.into_bytes())
    }

    /// Write a control file. cgroup.procs / subtree_control / kill /
    /// freeze are handled by the caller (they need cross-subsystem
    /// effects); this covers the per-controller limit files.
    /// # C: O(tokens)
    pub fn write_file(&mut self, id: u64, file: &str, buf: &str) -> KResult<()> {
        if let Some(bit) = file_controller(file) {
            let avail = self.nodes.get(&id).ok_or(VfsError::Enoent)?.avail;
            if avail & bit == 0 { return Err(VfsError::Enoent); }
        }
        let n = self.nodes.get_mut(&id).ok_or(VfsError::Enoent)?;
        let t = buf.trim();
        match file {
            "pids.max" => n.pids_max = parse_max(t).ok_or(VfsError::Einval)?,
            "memory.max" => n.mem_max = parse_max(t).ok_or(VfsError::Einval)?,
            "memory.high" => n.mem_high = parse_max(t).ok_or(VfsError::Einval)?,
            "memory.low" => n.mem_low = t.parse().map_err(|_| VfsError::Einval)?,
            "memory.min" => n.mem_min = t.parse().map_err(|_| VfsError::Einval)?,
            "memory.swap.max" => n.swap_max = parse_max(t).ok_or(VfsError::Einval)?,
            "cpu.weight" => {
                let w: u32 = t.parse().map_err(|_| VfsError::Einval)?;
                if !(1..=10_000).contains(&w) { return Err(VfsError::Einval); }
                n.cpu_weight = w;
            }
            "cpu.max" => {
                let mut it = t.split_whitespace();
                let quota = it.next().ok_or(VfsError::Einval)?;
                n.cpu_quota = parse_max(quota).ok_or(VfsError::Einval)?;
                if let Some(p) = it.next() {
                    n.cpu_period = p.parse().map_err(|_| VfsError::Einval)?;
                }
            }
            "io.max" => { n.io_max = t.to_string(); if !n.io_max.is_empty() { n.io_max.push('\n'); } }
            "io.weight" => {
                let w = t.rsplit(' ').next().unwrap_or(t);
                n.io_weight = w.parse().map_err(|_| VfsError::Einval)?;
            }
            "cpuset.cpus" => n.cpuset_cpus = t.to_string(),
            "cpuset.mems" => n.cpuset_mems = t.to_string(),
            _ => return Err(VfsError::Eacces),
        }
        Ok(())
    }
}

/// Files that exist in every cgroup directory (core interface).
pub const CORE_FILES: &[&str] = &[
    "cgroup.procs", "cgroup.threads", "cgroup.controllers",
    "cgroup.subtree_control", "cgroup.events", "cgroup.type",
    "cgroup.stat", "cgroup.max.depth", "cgroup.max.descendants",
];

/// Extra core files present only in non-root cgroups.
pub const NONROOT_FILES: &[&str] = &["cgroup.kill", "cgroup.freeze"];

/// Per-controller interface files, gated on the controller being
/// available (enabled in the parent's subtree_control).
/// # C: O(controllers)
pub fn controller_files(avail: u8) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = Vec::new();
    if avail & PIDS != 0 {
        v.extend(["pids.current", "pids.max", "pids.peak", "pids.events"]);
    }
    if avail & MEMORY != 0 {
        v.extend(["memory.current", "memory.max", "memory.high", "memory.low",
            "memory.min", "memory.swap.max", "memory.swap.current",
            "memory.events", "memory.stat"]);
    }
    if avail & CPU != 0 {
        v.extend(["cpu.weight", "cpu.max", "cpu.stat"]);
    }
    if avail & IO != 0 {
        v.extend(["io.stat", "io.max", "io.weight"]);
    }
    if avail & CPUSET != 0 {
        v.extend(["cpuset.cpus", "cpuset.mems",
            "cpuset.cpus.effective", "cpuset.mems.effective"]);
    }
    v
}
