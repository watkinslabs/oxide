use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vfs::VfsError;

use super::controllers::{ctrl_list, file_controller, fmt_max, parse_max};
use super::types::{KResult, Tree};

impl Tree {
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
            "memory.swap.current" => format!("{}\n", self.subtree_swap(id)),
            "memory.oom.group" => format!("{}\n", n.mem_oom_group as u8),
            "memory.zswap.max" => { let mut o = fmt_max(n.zswap_max); o.push('\n'); o }
            "memory.pressure_level" => "0\n".to_string(),
            "memory.events" => {
                let e = self.subtree_memory_events(id);
                format!("low {}\nhigh {}\nmax {}\noom {}\noom_kill {}\n", e.low, e.high, e.max, e.oom, e.oom_kill)
            }
            "memory.stat" => {
                let m = self.subtree_memory_stats(id);
                format!("anon {}\nfile {}\nkernel {}\nkernel_stack {}\npagetables {}\npercpu {}\nsock {}\nvmalloc {}\nshmem {}\nslab_reclaimable {}\nslab_unreclaimable {}\nslab {}\n", m.anon, m.file_total(), m.kernel_total(), m.kernel_stack, m.pagetables, m.percpu, m.sock, m.vmalloc, m.shmem, m.slab_reclaimable, m.slab_unreclaimable, m.slab_reclaimable.saturating_add(m.slab_unreclaimable))
            }
            "cpu.weight" => format!("{}\n", n.cpu_weight),
            "cpu.max" => match n.cpu_quota {
                Some(q) => format!("{} {}\n", q, n.cpu_period),
                None => format!("max {}\n", n.cpu_period),
            },
            "cpu.stat" => "usage_usec 0\nuser_usec 0\nsystem_usec 0\n".to_string(),
            "io.stat" => {
                let (rb, wb, ri, wi) = self.subtree_io(id);
                if rb == 0 && wb == 0 && ri == 0 && wi == 0 { String::new() }
                else { format!("8:0 rbytes={} wbytes={} rios={} wios={}\n", rb, wb, ri, wi) }
            }
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
            "memory.oom.group" => {
                n.mem_oom_group = match t {
                    "0" => false,
                    "1" => true,
                    _ => return Err(VfsError::Einval),
                };
            }
            "memory.zswap.max" => n.zswap_max = parse_max(t).ok_or(VfsError::Einval)?,
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
