// VFS bridge for cgroup v2 per `26§4` + `16§2`. Each cgroup directory
// and each control file is a devfs-registered inode at its full path
// under `/sys/fs/cgroup`; path resolution + readdir reuse the devfs
// registry (`19§3`). mkdir/rmdir dispatch through the `Inode` trait
// into the hierarchy logic in `lib.rs`.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

const DIR_INO_BASE: u64 = 0x6000_0000;
const FILE_INO_BASE: u64 = 0x6100_0000;

/// A cgroup directory. Holds its node id + absolute fs path so it can
/// build child paths for lookup/readdir against the devfs registry.
pub struct CgDir {
    pub cgid: u64,
    pub path: String,
}

impl CgDir {
    fn child_path(&self, name: &str) -> String {
        let mut p = String::with_capacity(self.path.len() + 1 + name.len());
        p.push_str(&self.path);
        if !self.path.ends_with('/') { p.push('/'); }
        p.push_str(name);
        p
    }
}

impl Inode for CgDir {
    fn ino(&self) -> Ino { (DIR_INO_BASE + self.cgid) as Ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn perm(&self) -> Option<u16> { Some(0o555) }

    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        devfs::lookup(&self.child_path(name)).ok_or(VfsError::Enoent)
    }

    fn readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        let snap = devfs::snapshot_visible_to_current();
        let mut idx = off as usize;
        while idx < snap.len() {
            let (path, inode) = &snap[idx];
            if let Some(name) = child_under(&self.path, path) {
                let next = idx as u64 + 1;
                if !f(next, name, inode.file_type()) { return Ok(next); }
            }
            idx += 1;
        }
        Ok(snap.len() as u64)
    }

    fn mkdir(&self, name: &str, _mode: u32) -> KResult<InodeRef> {
        crate::mkdir_child(self.cgid, &self.path, name)
    }

    fn rmdir(&self, name: &str) -> KResult<()> {
        crate::rmdir_child(self.cgid, name)
    }
}

/// A cgroup control file (`cgroup.procs`, `memory.max`, …). Reads and
/// writes route to the hierarchy keyed by `(cgid, file)`.
pub struct CgFile {
    pub cgid: u64,
    pub file: String,
    ino: Ino,
}

impl CgFile {
    /// Construct a control-file inode bound to `(cgid, file)`.
    /// # C: O(1)
    pub fn new(cgid: u64, file: &str, seq: u64) -> Self {
        Self { cgid, file: file.to_string(), ino: (FILE_INO_BASE + seq) as Ino }
    }
}

impl Inode for CgFile {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    /// Current content length. The read path bounds reads by `size()`,
    /// so dynamic control files must report their live byte count or
    /// `cat` reads zero bytes.
    fn size(&self) -> u64 {
        crate::read_file(self.cgid, &self.file).map(|d| d.len()).unwrap_or(0) as u64
    }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn perm(&self) -> Option<u16> {
        // Read-only interface files vs writable knobs.
        match self.file.as_str() {
            "cgroup.controllers" | "cgroup.events" | "cgroup.stat"
            | "cgroup.type" | "pids.current" | "pids.peak" | "pids.events"
            | "memory.current" | "memory.swap.current" | "memory.events"
            | "memory.stat" | "cpu.stat" | "io.stat"
            | "cpuset.cpus.effective" | "cpuset.mems.effective" => Some(0o444),
            _ => Some(0o644),
        }
    }

    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = crate::read_file(self.cgid, &self.file)?;
        if off as usize >= data.len() { return Ok(0); }
        let n = core::cmp::min(buf.len(), data.len() - off as usize);
        buf[..n].copy_from_slice(&data[off as usize..off as usize + n]);
        Ok(n)
    }

    fn write(&self, _off: u64, buf: &[u8]) -> KResult<usize> {
        let s = core::str::from_utf8(buf).map_err(|_| VfsError::Einval)?;
        // A cgroup control file takes ONE value per write. Userspace
        // (bash/busybox `echo`, GNU `printf`) emits the trailing
        // newline as a SEPARATE write() at a non-zero offset, so the
        // kernel sees `7` then `\n` as two calls. Linux kernfs buffers
        // the whole write and parses once; we parse per-write, so a
        // bare-whitespace chunk would re-parse as an empty value and
        // wrongly EINVAL. A whitespace-only chunk carries no value →
        // no-op success, leaving the preceding value write in effect.
        if s.trim().is_empty() {
            return Ok(buf.len());
        }
        crate::write_file(self.cgid, &self.file, s)?;
        Ok(buf.len())
    }
}

/// Direct-child component of `path` under `prefix`, or `None` if
/// `path` is not an immediate child (`<prefix>/<name>`, no deeper).
fn child_under<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    let rest = path.strip_prefix(prefix)?;
    let rest = rest.strip_prefix('/')?;
    if rest.is_empty() || rest.contains('/') { return None; }
    Some(rest)
}

/// Build the full inode set for a cgroup directory at `path` with
/// node id `cgid` and available-controller set `avail`. Returns
/// `(child_path, inode)` rows for the dir + every control file.
/// # C: O(controllers)
pub fn build_inodes(cgid: u64, path: &str, avail: u8, is_root: bool) -> Vec<(String, InodeRef)> {
    let mut rows: Vec<(String, InodeRef)> = Vec::new();
    rows.push((path.to_string(), Arc::new(CgDir { cgid, path: path.to_string() }) as InodeRef));
    let mut seq = cgid << 8;
    let push_file = |file: &str, rows: &mut Vec<(String, InodeRef)>, seq: &mut u64| {
        let mut fp = String::from(path);
        if !path.ends_with('/') { fp.push('/'); }
        fp.push_str(file);
        rows.push((fp, Arc::new(CgFile::new(cgid, file, *seq)) as InodeRef));
        *seq += 1;
    };
    for f in crate::tree::CORE_FILES { push_file(f, &mut rows, &mut seq); }
    if !is_root {
        for f in crate::tree::NONROOT_FILES { push_file(f, &mut rows, &mut seq); }
    }
    for f in crate::tree::controller_files(avail) { push_file(f, &mut rows, &mut seq); }
    rows
}
