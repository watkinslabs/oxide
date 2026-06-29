// VFS bridge for cgroup v2 per `26§4` + `16§2`. cgroupfs SYNTHESIZES
// its inodes on lookup from the hierarchy in `tree.rs` — it owns no
// registry and has ZERO dependency on devfs. A `CgDir` is a cgroup
// directory inode identified by its node id (`cgid`); `lookup`/`readdir`
// resolve its control files + child cgroups straight from the tree, and
// mkdir/rmdir mutate the tree. Control files are `CgFile` inodes whose
// read/write route to the tree keyed by `(cgid, file)`.

use alloc::string::{String, ToString};
use alloc::sync::Arc;

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

const DIR_INO_BASE: u64 = 0x6000_0000;
const FILE_INO_BASE: u64 = 0x6100_0000;

/// A cgroup directory, identified by its node id. lookup/readdir resolve
/// against the live hierarchy (`tree.rs`) via the accessors in `lib.rs`.
pub struct CgDir {
    pub cgid: u64,
}

/// cgroup2 superblock magic (`linux/magic.h` CGROUP2_SUPER_MAGIC) — the
/// distinct `fsid` for the unified hierarchy so mount-point detection sees
/// the `/sys/fs/cgroup` boundary.
const CGROUP2_FSID: u64 = 0x6367_7270;

impl CgDir {
    /// Construct a directory inode for `cgid`.
    /// # C: O(1)
    pub fn new(cgid: u64) -> Self { Self { cgid } }
}

impl Inode for CgDir {
    fn ino(&self) -> Ino { (DIR_INO_BASE + self.cgid) as Ino }
    fn fsid(&self) -> u64 { CGROUP2_FSID }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn perm(&self) -> Option<u16> { Some(0o555) }

    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        // A control file of this cgroup → CgFile inode.
        if crate::node_has_file(self.cgid, name) {
            return Ok(Arc::new(CgFile::new(self.cgid, name)) as InodeRef);
        }
        // A child cgroup → CgDir inode.
        if let Some(child) = crate::node_child_id(self.cgid, name) {
            return Ok(Arc::new(CgDir::new(child)) as InodeRef);
        }
        Err(VfsError::Enoent)
    }

    fn readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        // Stable order: control files first, then child cgroups. The
        // offset is an index into that concatenated sequence. The child's real
        // ino (resolved via `lookup` — no lock held here) feeds getdents `d_ino`.
        let files = crate::node_file_names(self.cgid);
        let kids = crate::node_child_names(self.cgid);
        let total = files.len() + kids.len();
        let mut idx = off as usize;
        while idx < total {
            let next = idx as u64 + 1;
            if idx < files.len() {
                let ino = self.lookup(files[idx]).map(|i| i.ino()).unwrap_or(0);
                if !f(ino, next, files[idx], FileType::Regular) { return Ok(next); }
            } else {
                let name = &kids[idx - files.len()];
                let ino = self.lookup(name).map(|i| i.ino()).unwrap_or(0);
                if !f(ino, next, name, FileType::Directory) { return Ok(next); }
            }
            idx += 1;
        }
        Ok(total as u64)
    }

    fn mkdir(&self, name: &str, _mode: u32) -> KResult<InodeRef> {
        #[cfg(feature = "debug-cgroup")]
        {
            klog::write_raw(b"[cg] mkdir parent=");
            klog::write_dec_u64(self.cgid);
            klog::write_raw(b" name=");
            klog::write_raw(name.as_bytes());
            klog::write_raw(b"\n");
        }
        let id = crate::mkdir_child(self.cgid, name)?;
        Ok(Arc::new(CgDir::new(id)) as InodeRef)
    }

    fn rmdir(&self, name: &str) -> KResult<()> {
        crate::rmdir_child(self.cgid, name)
    }
}

/// A cgroup control file (`cgroup.procs`, `memory.max`, …). Reads and
/// writes route to the hierarchy keyed by `(cgid, file)`. Synthesized on
/// lookup — never registered.
pub struct CgFile {
    pub cgid: u64,
    pub file: String,
}

impl CgFile {
    /// Construct a control-file inode bound to `(cgid, file)`.
    /// # C: O(1)
    pub fn new(cgid: u64, file: &str) -> Self {
        Self { cgid, file: file.to_string() }
    }
    /// Stable inode number — derived from `(cgid, file)` so the same
    /// control file keeps one identity across lookups. cgid in the high
    /// bits, a hash of the file name in the low bits.
    /// # C: O(name)
    fn file_ino(cgid: u64, file: &str) -> Ino {
        let mut h: u64 = 0;
        for b in file.bytes() { h = h.wrapping_mul(31).wrapping_add(b as u64); }
        (FILE_INO_BASE + ((cgid << 8) ^ (h & 0xff))) as Ino
    }
}

impl Inode for CgFile {
    fn ino(&self) -> Ino { Self::file_ino(self.cgid, &self.file) }
    fn fsid(&self) -> u64 { CGROUP2_FSID }
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
            | "memory.stat" | "memory.pressure_level" | "cpu.stat" | "io.stat"
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
        // (bash `echo`, GNU `printf`) emits the trailing
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
