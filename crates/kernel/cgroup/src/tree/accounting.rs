use alloc::vec::Vec;

use super::controllers::{MEMORY, PIDS};
use super::types::{CpuGroup, ROOT, Tree};

impl Tree {
    /// Add a process to a cgroup (fork inheritance / explicit attach).
    /// Removes it from any prior cgroup first.
    /// # C: O(log n)
    pub fn add_proc(&mut self, cgid: u64, pid: u64) {
        if let Some(old) = self.proc_cg.insert(pid, cgid) {
            if old == cgid { return; }
            if let Some(n) = self.nodes.get_mut(&old) { n.procs.remove(&pid); }
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
