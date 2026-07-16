// /sys/devices/system/cpu — the CPU device subsystem (Linux
// `drivers/base/cpu.c` + `arch_topology`). A dynamic kobject directory:
// `cpuN` device dirs are enumerated per CPU at readdir time, so the set
// always reflects the live `online_count()` — NOT a snapshot taken at
// boot before the APs are up. Each `cpuN` is a real device dir with an
// `online` file and a `topology/` group. The control files
// (`online`/`present`/`possible`/`offline`/`kernel_max`/`isolated`) are
// the live cpumask. nproc / htop / lscpu (`_SC_NPROCESSORS_CONF` reads
// the `cpuN` dirs) / libnuma / systemd walk this subtree.
//
// KEYSTONE struct-`Inode` model: each directory is a `vfs::Inode` whose
// `i_op->lookup` + `i_fop->iterate` read the per-inode index off `i_private`;
// leaf attributes are `dyn_file::make_owned_file` / `make_gen_file` inodes.
#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use core::fmt::Write as _;
use vfs::{mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

/// Live online-CPU count, clamped to a real range.
fn ncpu() -> usize {
    (cpu::smp::online_count() as usize).clamp(1, cpu::MAX_CPUS)
}

/// Linux cpumask list form: `0` for one CPU, `0-N` for N+1.
fn range_list(n: usize) -> String {
    let mut s = String::new();
    if n <= 1 {
        s.push('0');
    } else {
        let _ = write!(s, "0-{}", n - 1);
    }
    s.push('\n');
    s
}

/// Linux cpumask hex form (single 32-bit group; oxide caps at 64 CPUs so a
/// `u64` covers every supported mask).
fn mask_hex(bits: u64) -> String {
    let mut s = String::new();
    let _ = write!(s, "{bits:x}\n");
    s
}

/// Read-only `/sys` attribute whose body is computed once at lookup. # C: O(1)
fn attr(ino: Ino, body: String) -> InodeRef { crate::dyn_file::make_owned_file(ino, body.into_bytes()) }

// ---- /sys/devices/system/cpu (root) -------------------------------------

/// Control attribute names that live directly under the cpu root.
const ROOT_FILES: &[&str] = &[
    "online", "present", "possible", "offline", "isolated", "nohz_full",
    "kernel_max", "uevent", "modalias",
];

/// `online`/`present`/`possible` body — the live cpumask list, re-read every
/// time so it tracks `online_count()` (Linux `cpu_*_mask` show).
fn cpu_range_body() -> alloc::vec::Vec<u8> { range_list(ncpu()).into_bytes() }

/// Resolve a child of `/sys/devices/system/cpu`.
fn root_lookup(name: &str) -> KResult<InodeRef> {
    match name {
        "online" | "present" | "possible" => Ok(crate::dyn_file::make_gen_file(crate::ids::CPU_ATTR_ONLINE as Ino, cpu_range_body)),
        "offline" | "isolated" | "nohz_full" => Ok(attr(crate::ids::CPU_ATTR_OFFLINE, String::from("\n"))),
        // Linux kernel_max = CONFIG_NR_CPUS-1 (the largest possible id).
        "kernel_max" => Ok(attr(crate::ids::CPU_ATTR_KERNEL_MAX, {
            let mut s = String::new();
            let _ = write!(s, "{}\n", cpu::MAX_CPUS - 1);
            s
        })),
        "uevent" | "modalias" => Ok(attr(crate::ids::CPU_ATTR_UEVENT, String::new())),
        _ => match parse_cpu_n(name) {
            Some(c) if c < ncpu() => Ok(make_syscpu_n(c)),
            _ => Err(VfsError::Enoent),
        },
    }
}

struct SysCpuRootOps;
impl InodeOps for SysCpuRootOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> { root_lookup(name) }
}
impl FileOps for SysCpuRootOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let mut idx = ctx.pos as usize;
        let n = ncpu();
        let total = ROOT_FILES.len() + n;
        while idx < total {
            let next = idx as u64 + 1;
            let (name, ft);
            let mut buf = String::new();
            if idx < ROOT_FILES.len() {
                name = ROOT_FILES[idx];
                ft = FileType::Regular;
            } else {
                let _ = write!(buf, "cpu{}", idx - ROOT_FILES.len());
                name = buf.as_str();
                ft = FileType::Directory;
            }
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, ft, next) {
                return Ok(());
            }
            idx += 1;
        }
        Ok(())
    }
}

/// `/sys/devices/system/cpu` root dir inode. # C: O(1)
pub fn make_syscpu_root() -> InodeRef {
    InodeBuilder::new(crate::ids::CPU_ROOT, mk_mode(FileType::Directory, 0o555), Arc::new(SysCpuRootOps), Arc::new(SysCpuRootOps))
        .build()
}

/// Parse a `cpu<N>` directory name to its index.
fn parse_cpu_n(name: &str) -> Option<usize> {
    name.strip_prefix("cpu").and_then(|d| d.parse::<usize>().ok())
}

// ---- /sys/devices/system/cpu/cpuN ---------------------------------------

const CPUN_FILES: &[&str] = &["online", "uevent"];

/// `i_private` for a `cpuN` device directory. # C: O(1)
pub struct SysCpuNInode { c: usize }

fn cpu_n_lookup(c: usize, name: &str) -> KResult<InodeRef> {
    match name {
        "online" => Ok(attr(crate::ids::CPU_ONLINE + c as Ino, String::from("1\n"))),
        "uevent" => Ok(attr(crate::ids::CPU_UEVENT + c as Ino, String::from("DRIVER=processor\n"))),
        "topology" => Ok(make_syscpu_topology(c)),
        _ => Err(VfsError::Enoent),
    }
}

struct SysCpuNOps;
impl InodeOps for SysCpuNOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<SysCpuNInode>().ok_or(VfsError::Einval)?;
        cpu_n_lookup(d.c, name)
    }
}
impl FileOps for SysCpuNOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let mut idx = ctx.pos as usize;
        let total = CPUN_FILES.len() + 1; // + topology dir
        while idx < total {
            let next = idx as u64 + 1;
            let (name, ft) = if idx < CPUN_FILES.len() {
                (CPUN_FILES[idx], FileType::Regular)
            } else {
                ("topology", FileType::Directory)
            };
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, ft, next) {
                return Ok(());
            }
            idx += 1;
        }
        Ok(())
    }
}

/// `/sys/devices/system/cpu/cpuN` device dir inode. # C: O(1)
pub fn make_syscpu_n(c: usize) -> InodeRef {
    InodeBuilder::new(crate::ids::CPU_DIR + c as Ino, mk_mode(FileType::Directory, 0o555), Arc::new(SysCpuNOps), Arc::new(SysCpuNOps))
        .private(Arc::new(SysCpuNInode { c }))
        .build()
}

// ---- /sys/devices/system/cpu/cpuN/topology ------------------------------

/// Topology attributes (Linux `arch_topology` / `topology_sysfs`). oxide
/// has no SMT and one package, so each CPU is its own core+thread; the
/// package set is every online CPU.
const TOPO_FILES: &[&str] = &[
    "core_id", "physical_package_id", "cluster_id", "die_id",
    "thread_siblings", "thread_siblings_list",
    "core_cpus", "core_cpus_list",
    "core_siblings", "core_siblings_list",
    "package_cpus", "package_cpus_list",
];

/// `i_private` for a `cpuN/topology` directory. # C: O(1)
pub struct SysCpuTopologyInode { c: usize }

fn topo_attr_body(c: usize, name: &str) -> Option<String> {
    let n = ncpu();
    let all: u64 = if n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
    let me: u64 = 1u64 << (c.min(63));
    let mut s = String::new();
    match name {
        // No SMT: each CPU is its own core. Single package/die/cluster.
        "core_id" => { let _ = write!(s, "{c}\n"); }
        "physical_package_id" | "cluster_id" | "die_id" => s.push_str("0\n"),
        // thread siblings == core cpus == just this CPU (no SMT).
        "thread_siblings" | "core_cpus" => return Some(mask_hex(me)),
        "thread_siblings_list" | "core_cpus_list" => { let _ = write!(s, "{c}\n"); }
        // core/package siblings == every online CPU (one package).
        "core_siblings" | "package_cpus" => return Some(mask_hex(all)),
        "core_siblings_list" | "package_cpus_list" => return Some(range_list(n)),
        _ => return None,
    }
    Some(s)
}

struct SysCpuTopologyOps;
impl InodeOps for SysCpuTopologyOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<SysCpuTopologyInode>().ok_or(VfsError::Einval)?;
        match topo_attr_body(d.c, name) {
            Some(body) => Ok(attr(crate::ids::CPU_TOPOLOGY_ATTR + d.c as Ino, body)),
            None => Err(VfsError::Enoent),
        }
    }
}
impl FileOps for SysCpuTopologyOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let mut idx = ctx.pos as usize;
        while idx < TOPO_FILES.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(TOPO_FILES[idx]).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(TOPO_FILES[idx], ino, FileType::Regular, next) {
                return Ok(());
            }
            idx += 1;
        }
        Ok(())
    }
}

/// `/sys/devices/system/cpu/cpuN/topology` dir inode. # C: O(1)
pub fn make_syscpu_topology(c: usize) -> InodeRef {
    InodeBuilder::new(crate::ids::CPU_TOPOLOGY_DIR + c as Ino, mk_mode(FileType::Directory, 0o555), Arc::new(SysCpuTopologyOps), Arc::new(SysCpuTopologyOps))
        .private(Arc::new(SysCpuTopologyInode { c }))
        .build()
}
