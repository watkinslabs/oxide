use alloc::vec::Vec;

use super::controllers::{MEMORY, PIDS};
use super::types::{CpuGroup, MemoryCharge, MemoryEvent, MemoryEvents, MemoryKind, MemoryStats, ROOT, Tree};

impl Tree {
    /// Add a process to a cgroup (fork inheritance / explicit attach).
    /// Removes it from any prior cgroup first. Page-owned memory charges do
    /// not follow task membership: PageMeta holds their allocating memcg.
    /// # C: O(log n)
    pub fn add_proc(&mut self, cgid: u64, pid: u64) {
        if let Some(old) = self.proc_cg.insert(pid, cgid) {
            if old == cgid { return; }
            if let Some(n) = self.nodes.get_mut(&old) { n.procs.remove(&pid); }
        }
        if let Some(n) = self.nodes.get_mut(&cgid) { n.procs.insert(pid); }
    }

    /// Drop a process on exit. Resident and swapped pages retain their
    /// allocating memcg until their respective page/slot release paths.
    /// # C: O(log n)
    pub fn remove_proc(&mut self, pid: u64) {
        if let Some(old) = self.proc_cg.remove(&pid) {
            if let Some(n) = self.nodes.get_mut(&old) { n.procs.remove(&pid); }
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
    pub(super) fn subtree_proc_count(&self, id: u64) -> u64 {
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
        let mut b = n.memory.total();
        for &child in n.children.values() { b = b.saturating_add(self.subtree_mem(child)); }
        b
    }

    /// `memory.swap.current` for a node = swap slots charged directly to it
    /// plus every descendant.  Charges stay with the allocating memcg, not
    /// with a task that may subsequently migrate.
    /// # C: O(subtree)
    pub fn subtree_swap(&self, id: u64) -> u64 {
        let n = match self.nodes.get(&id) { Some(n) => n, None => return 0 };
        let mut b = n.swap_current;
        for &child in n.children.values() { b = b.saturating_add(self.subtree_swap(child)); }
        b
    }

    /// Reserve `bytes` against `memory.swap.max` for an existing page owned
    /// by `cgid`. The page-out transaction calls this before publishing its
    /// swap PTE; slot destruction performs the matching uncharge.
    /// # C: O(depth · subtree)
    pub fn try_charge_swap(&mut self, cgid: u64, bytes: u64) -> bool {
        if bytes == 0 { return true; }
        if !self.nodes.contains_key(&cgid) { return false; }
        let mut cur = Some(cgid);
        while let Some(id) = cur {
            let n = match self.nodes.get(&id) { Some(n) => n, None => break };
            if n.avail & MEMORY != 0 {
                if let Some(max) = n.swap_max {
                    if self.subtree_swap(id) + bytes > max { return false; }
                }
            }
            cur = n.parent;
        }
        if let Some(n) = self.nodes.get_mut(&cgid) { n.swap_current += bytes; }
        true
    }

    /// Drop a swap-slot charge after its final PTE reference disappears.
    /// # C: O(log n)
    pub fn uncharge_swap(&mut self, cgid: u64, bytes: u64) {
        if bytes == 0 { return; }
        if let Some(n) = self.nodes.get_mut(&cgid) {
            n.swap_current = n.swap_current.saturating_sub(bytes);
        }
    }

    /// Direct memory-stat snapshot for this node and its descendants.
    /// # C: O(subtree)
    pub fn subtree_memory_stats(&self, id: u64) -> MemoryStats {
        let n = match self.nodes.get(&id) { Some(n) => n, None => return MemoryStats::default() };
        let mut out = n.memory;
        for &child in n.children.values() {
            let next = self.subtree_memory_stats(child);
            for kind in [
                MemoryKind::Anon, MemoryKind::File, MemoryKind::Shmem, MemoryKind::KernelStack,
                MemoryKind::SlabReclaimable, MemoryKind::SlabUnreclaimable, MemoryKind::PageTables,
                MemoryKind::PerCpu, MemoryKind::Sock, MemoryKind::Vmalloc,
            ] { out.add(kind, next.get(kind)); }
        }
        out
    }

    /// Direct memory-event snapshot for this node and its descendants.
    /// # C: O(subtree)
    pub fn subtree_memory_events(&self, id: u64) -> MemoryEvents {
        let n = match self.nodes.get(&id) { Some(n) => n, None => return MemoryEvents::default() };
        let mut out = n.memory_events;
        for &child in n.children.values() {
            let next = self.subtree_memory_events(child);
            out.low = out.low.saturating_add(next.low);
            out.high = out.high.saturating_add(next.high);
            out.max = out.max.saturating_add(next.max);
            out.oom = out.oom.saturating_add(next.oom);
            out.oom_kill = out.oom_kill.saturating_add(next.oom_kill);
        }
        out
    }

    /// Try to charge one concrete resident-memory owner class to `cgid`. Walks ancestors
    /// with the memory controller enabled + a `memory.max` set; if any
    /// would be exceeded the charge is rejected wholesale (caller returns
    /// ENOMEM). The charge remains at its allocating memcg across task
    /// migration and exit. Zero bytes always succeeds.
    /// # C: O(depth · subtree)
    pub fn try_charge_memory(&mut self, cgid: u64, kind: MemoryKind, bytes: u64) -> bool {
        match self.try_charge_memory_transition(cgid, kind, bytes) {
            MemoryCharge::Charged { .. } => true,
            MemoryCharge::Max { .. } => false,
        }
    }

    /// Commit a charge only if every hard limit admits it and return the
    /// pressure fact needed by the external policy owner.  A failed `max`
    /// reservation is never partially charged.  `crossed_high` is a true
    /// below-to-above transition, not a synthetic event for every allocation
    /// that happens to remain above a limit.
    /// # C: O(depth · subtree)
    pub fn try_charge_memory_transition(&mut self, cgid: u64, kind: MemoryKind, bytes: u64) -> MemoryCharge {
        if bytes == 0 { return MemoryCharge::Charged { crossed_high: false }; }
        if !self.nodes.contains_key(&cgid) { return MemoryCharge::Max { limit_cgid: cgid }; }
        let mut crossed_high = false;
        let mut cur = Some(cgid);
        while let Some(id) = cur {
            let n = match self.nodes.get(&id) { Some(n) => n, None => break };
            if n.avail & MEMORY != 0 {
                let current = self.subtree_mem(id);
                if let Some(max) = n.mem_max {
                    if current.saturating_add(bytes) > max {
                        if let Some(owner) = self.nodes.get_mut(&cgid) { owner.memory_events.add(MemoryEvent::Max); }
                        return MemoryCharge::Max { limit_cgid: id };
                    }
                }
                if let Some(high) = n.mem_high {
                    crossed_high |= current <= high && current.saturating_add(bytes) > high;
                }
            }
            cur = n.parent;
        }
        if let Some(n) = self.nodes.get_mut(&cgid) { n.memory.add(kind, bytes); }
        MemoryCharge::Charged { crossed_high }
    }

    /// Uncharge freed resident memory from its PageMeta-owned `cgid` and
    /// original owner class. # C: O(log n)
    pub fn uncharge_memory(&mut self, cgid: u64, kind: MemoryKind, bytes: u64) {
        if bytes == 0 { return; }
        if let Some(n) = self.nodes.get_mut(&cgid) { n.memory.sub(kind, bytes); }
    }

    /// Compatibility entry point for existing anonymous PageMeta callers.
    /// # C: O(depth · subtree)
    pub fn try_charge_memcg(&mut self, cgid: u64, bytes: u64) -> bool {
        self.try_charge_memory(cgid, MemoryKind::Anon, bytes)
    }

    /// Compatibility entry point for existing anonymous PageMeta callers.
    /// Saturation makes duplicate cleanup harmless while preserving the
    /// canonical cgroup ledger.
    /// # C: O(log n)
    pub fn uncharge_memcg(&mut self, cgid: u64, bytes: u64) {
        self.uncharge_memory(cgid, MemoryKind::Anon, bytes);
    }

    /// Record a lifecycle event at the cgroup that observed it.  The source
    /// transition (reclaim, OOM selection, or high throttle) decides when it
    /// is true; readers receive hierarchical totals. # C: O(log n)
    pub fn record_memory_event(&mut self, cgid: u64, event: MemoryEvent) {
        if let Some(n) = self.nodes.get_mut(&cgid) { n.memory_events.add(event); }
    }

    /// Charge a completed block I/O to `pid`'s cgroup (io.stat). `bytes`
    /// transferred; `is_write` selects the r/w counters. Cumulative (io
    /// is not "freed").
    /// # C: O(log n)
    pub fn charge_io(&mut self, pid: u64, bytes: u64, is_write: bool) {
        let cg = self.cgroup_of(pid);
        if let Some(n) = self.nodes.get_mut(&cg) {
            if is_write { n.io_wbytes += bytes; n.io_wios += 1; }
            else        { n.io_rbytes += bytes; n.io_rios += 1; }
        }
    }

    /// Subtree io totals `(rbytes, wbytes, rios, wios)` = this node + all
    /// descendants (io.stat rolls up hierarchically, like memory.current).
    /// # C: O(subtree)
    pub fn subtree_io(&self, id: u64) -> (u64, u64, u64, u64) {
        let n = match self.nodes.get(&id) { Some(n) => n, None => return (0,0,0,0) };
        let (mut rb, mut wb, mut ri, mut wi) = (n.io_rbytes, n.io_wbytes, n.io_rios, n.io_wios);
        for &c in n.children.values() {
            let (a,b,c2,d) = self.subtree_io(c);
            rb += a; wb += b; ri += c2; wi += d;
        }
        (rb, wb, ri, wi)
    }

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
}
