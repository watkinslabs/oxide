// /sys/devices/system/cpu — the CPU device subsystem (Linux
// `drivers/base/cpu.c` + `arch_topology`). A dynamic kobject directory:
// `cpuN` device dirs are enumerated per CPU at readdir time, so the set
// always reflects the live `online_count()` — NOT a snapshot taken at
// boot before the APs are up. Each `cpuN` is a real device dir with an
// `online` file and a `topology/` group. The control files
// (`online`/`present`/`possible`/`offline`/`kernel_max`/`isolated`) are
// the live cpumask. nproc / htop / lscpu (`_SC_NPROCESSORS_CONF` reads
// the `cpuN` dirs) / libnuma / systemd walk this subtree.
#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use core::fmt::Write as _;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// Live online-CPU count, clamped to a real range.
fn ncpu() -> usize {
    (cpu::smp::online_count() as usize).clamp(1, cpu::MAX_CPUS)
}

/// Serve `body[off..]` into `buf` (the shared offset-read tail).
fn read_body(body: &[u8], off: u64, buf: &mut [u8]) -> KResult<usize> {
    let off = off as usize;
    if off >= body.len() {
        return Ok(0);
    }
    let n = (body.len() - off).min(buf.len());
    buf[..n].copy_from_slice(&body[off..off + n]);
    Ok(n)
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

// ---- a generic read-only leaf carrying an owned body --------------------

/// Read-only `/sys` attribute whose body is computed once per construction
/// (cheap; the dir's `lookup` builds it on demand).
struct AttrInode {
    ino: Ino,
    body: alloc::vec::Vec<u8>,
}
impl AttrInode {
    fn new(ino: Ino, body: String) -> InodeRef {
        Arc::new(AttrInode { ino, body: body.into_bytes() }) as InodeRef
    }
}
impl Inode for AttrInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> { read_body(&self.body, off, buf) }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// `online`/`present`/`possible` — the live cpumask list, re-read every
/// time so it tracks `online_count()` (Linux `cpu_*_mask` show).
struct CpuRangeInode;
impl Inode for CpuRangeInode {
    fn ino(&self) -> Ino { 0x3000_1C01 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        read_body(range_list(ncpu()).as_bytes(), off, buf)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

// ---- /sys/devices/system/cpu (root) -------------------------------------

/// Control attribute names that live directly under the cpu root.
const ROOT_FILES: &[&str] = &[
    "online", "present", "possible", "offline", "isolated", "nohz_full",
    "kernel_max", "uevent", "modalias",
];

pub struct SysCpuRootInode;
impl Inode for SysCpuRootInode {
    fn ino(&self) -> Ino { 0x3000_1C00 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        match name {
            "online" | "present" | "possible" => Ok(Arc::new(CpuRangeInode) as InodeRef),
            "offline" | "isolated" | "nohz_full" => Ok(AttrInode::new(0x3000_1C02, String::from("\n"))),
            // Linux kernel_max = CONFIG_NR_CPUS-1 (the largest possible id).
            "kernel_max" => Ok(AttrInode::new(0x3000_1C03, {
                let mut s = String::new();
                let _ = write!(s, "{}\n", cpu::MAX_CPUS - 1);
                s
            })),
            "uevent" | "modalias" => Ok(AttrInode::new(0x3000_1C04, String::new())),
            _ => match parse_cpu_n(name) {
                Some(c) if c < ncpu() => Ok(Arc::new(SysCpuNInode { c }) as InodeRef),
                _ => Err(VfsError::Enoent),
            },
        }
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let mut idx = off as usize;
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
            let ino = self.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, name, ft) {
                return Ok(next);
            }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// Parse a `cpu<N>` directory name to its index.
fn parse_cpu_n(name: &str) -> Option<usize> {
    name.strip_prefix("cpu").and_then(|d| d.parse::<usize>().ok())
}

// ---- /sys/devices/system/cpu/cpuN ---------------------------------------

const CPUN_FILES: &[&str] = &["online", "uevent"];

pub struct SysCpuNInode {
    c: usize,
}
impl Inode for SysCpuNInode {
    fn ino(&self) -> Ino { 0x3000_1D00 + self.c as Ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        match name {
            "online" => Ok(AttrInode::new(0x3000_1D80 + self.c as Ino, String::from("1\n"))),
            "uevent" => Ok(AttrInode::new(0x3000_1DC0 + self.c as Ino, String::from("DRIVER=processor\n"))),
            "topology" => Ok(Arc::new(SysCpuTopologyInode { c: self.c }) as InodeRef),
            _ => Err(VfsError::Enoent),
        }
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let mut idx = off as usize;
        let total = CPUN_FILES.len() + 1; // + topology dir
        while idx < total {
            let next = idx as u64 + 1;
            let (name, ft) = if idx < CPUN_FILES.len() {
                (CPUN_FILES[idx], FileType::Regular)
            } else {
                ("topology", FileType::Directory)
            };
            let ino = self.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, name, ft) {
                return Ok(next);
            }
            idx += 1;
        }
        Ok(idx as u64)
    }
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

pub struct SysCpuTopologyInode {
    c: usize,
}
impl SysCpuTopologyInode {
    fn attr_body(&self, name: &str) -> Option<String> {
        let c = self.c;
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
}
impl Inode for SysCpuTopologyInode {
    fn ino(&self) -> Ino { 0x3000_1E00 + self.c as Ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        match self.attr_body(name) {
            Some(body) => Ok(AttrInode::new(0x3000_1F00 + self.c as Ino, body)),
            None => Err(VfsError::Enoent),
        }
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let mut idx = off as usize;
        while idx < TOPO_FILES.len() {
            let next = idx as u64 + 1;
            let ino = self.lookup(TOPO_FILES[idx]).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, TOPO_FILES[idx], FileType::Regular) {
                return Ok(next);
            }
            idx += 1;
        }
        Ok(idx as u64)
    }
}
