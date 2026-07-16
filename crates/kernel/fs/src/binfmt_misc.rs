//! Linux binfmt_misc filesystem.
//!
//! Mounted at `/proc/sys/fs/binfmt_misc`, this exposes the control files
//! userspace expects (`status`, `register`) and stores registered rules in a
//! kernel-owned table. Exec-time interpreter dispatch is a separate hook, but
//! the filesystem and registration ABI are real and stateful.

extern crate alloc;

mod ids {
    pub(crate) const MAGIC: u64 = 0x4249_4e4d;
    pub(crate) const INO_BASE: u64 = 0x4249_0000;
}

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as LockClass};
use vfs::{FileType, Ino, Inode, InodeOps, InodeRef, KResult, VfsError};
use vfs::{DirContext, FileOps, InodeBuilder, mk_mode};

pub const BINFMT_MISC_MAGIC: u64 = ids::MAGIC;

static NEXT_INO: AtomicU64 = AtomicU64::new(ids::INO_BASE);

#[derive(Clone)]
struct Rule {
    line: Vec<u8>,
    enabled: bool,
}

struct State {
    enabled: AtomicBool,
    rules: Spinlock<BTreeMap<String, Rule>, LockClass>,
}

impl State {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(true),
            rules: Spinlock::new(BTreeMap::new()),
        })
    }

    fn clear(&self) {
        self.rules.lock().clear();
    }

    fn register(&self, src: &[u8]) -> KResult<()> {
        let line = trim_newline(src);
        if line.is_empty() || line[0] != b':' {
            return Err(VfsError::Einval);
        }
        let delim = line[0];
        let mut fields: Vec<&[u8]> = Vec::new();
        let mut start = 1usize;
        for (idx, b) in line.iter().copied().enumerate().skip(1) {
            if b == delim {
                fields.push(&line[start..idx]);
                start = idx + 1;
            }
        }
        fields.push(&line[start..]);
        if fields.len() < 7 || fields[0].is_empty() {
            return Err(VfsError::Einval);
        }
        match fields[1] {
            b"M" | b"E" => {}
            _ => return Err(VfsError::Einval),
        }
        let name = core::str::from_utf8(fields[0]).map_err(|_| VfsError::Einval)?;
        let mut rules = self.rules.lock();
        rules.insert(name.to_string(), Rule { line: line.to_vec(), enabled: true });
        Ok(())
    }
}

fn trim_newline(src: &[u8]) -> &[u8] {
    let mut end = src.len();
    while end > 0 && (src[end - 1] == b'\n' || src[end - 1] == b'\r' || src[end - 1] == 0) {
        end -= 1;
    }
    &src[..end]
}

pub struct BinfmtMiscFs {
    root: InodeRef,
}

impl BinfmtMiscFs {
    pub fn new() -> Arc<Self> {
        let state = State::new();
        let root = make_binfmt_root(state, NEXT_INO.fetch_add(1, Ordering::Relaxed));
        Arc::new(Self { root })
    }
}

impl vfs::fs::FileSystem for BinfmtMiscFs {
    fn name(&self) -> &str { "binfmt_misc" }
    fn magic(&self) -> u64 { BINFMT_MISC_MAGIC }
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
}

/// Per-inode binfmt_misc directory state (Linux `i_private`).
struct BinfmtRootData { state: Arc<State> }

/// Which control file a `BinfmtFileData` represents.
enum BinKind { Status, Register, Rule(String) }

/// Per-inode binfmt_misc control-file state (Linux `i_private`).
struct BinfmtFileData { state: Arc<State>, kind: BinKind }

/// `make_binfmt_root(state, ino)` — the directory inode. # C: O(1)
fn make_binfmt_root(state: Arc<State>, ino: Ino) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755),
        Arc::new(BinfmtRootInodeOps), Arc::new(BinfmtRootFileOps))
        .private(Arc::new(BinfmtRootData { state }))
        .build()
}

/// `make_binfmt_file(state, kind, ino, size)` — a control-file inode. # C: O(1)
fn make_binfmt_file(state: Arc<State>, kind: BinKind, ino: Ino, size: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
        vfs::default_inode_ops(), Arc::new(BinfmtFileOps))
        .size(size)
        .private(Arc::new(BinfmtFileData { state, kind }))
        .build()
}

/// `i_op` for the binfmt_misc directory. # C: O(1)
struct BinfmtRootInodeOps;
impl InodeOps for BinfmtRootInodeOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<BinfmtRootData>().ok_or(VfsError::Einval)?;
        match name {
            "status" => Ok(make_binfmt_file(Arc::clone(&d.state), BinKind::Status,
                NEXT_INO.fetch_add(1, Ordering::Relaxed), 8)),
            "register" => Ok(make_binfmt_file(Arc::clone(&d.state), BinKind::Register,
                NEXT_INO.fetch_add(1, Ordering::Relaxed), 0)),
            _ => {
                let rules = d.state.rules.lock();
                if let Some(r) = rules.get(name) {
                    let size = r.line.len() as u64 + 16;
                    Ok(make_binfmt_file(Arc::clone(&d.state), BinKind::Rule(name.to_string()),
                        NEXT_INO.fetch_add(1, Ordering::Relaxed), size))
                } else {
                    Err(VfsError::Enoent)
                }
            }
        }
    }
}

/// `i_fop` for the binfmt_misc directory (readdir). # C: O(N_rules)
struct BinfmtRootFileOps;
impl FileOps for BinfmtRootFileOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<BinfmtRootData>().ok_or(VfsError::Einval)?;
        let off = ctx.pos;
        let mut idx = 0u64;
        for name in ["status", "register"] {
            if idx >= off {
                let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
                if !ctx.emit(name, ino, FileType::Regular, idx + 1) {
                    return Ok(());
                }
            }
            idx += 1;
        }
        let names: Vec<String> = d.state.rules.lock().keys().cloned().collect();
        for name in names {
            if idx >= off {
                let ino = inode.lookup(&name).map(|i| i.ino()).unwrap_or(0);
                if !ctx.emit(&name, ino, FileType::Regular, idx + 1) {
                    return Ok(());
                }
            }
            idx += 1;
        }
        Ok(())
    }
}

/// `i_fop` for the binfmt_misc control files (status/register/<rule>). # C: O(1)
struct BinfmtFileOps;
impl FileOps for BinfmtFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<BinfmtFileData>().ok_or(VfsError::Einval)?;
        let body: Vec<u8> = match &d.kind {
            BinKind::Status => {
                if d.state.enabled.load(Ordering::Acquire) { b"enabled\n".to_vec() }
                else { b"disabled\n".to_vec() }
            }
            BinKind::Register => return Err(VfsError::Einval),
            BinKind::Rule(name) => {
                let rules = d.state.rules.lock();
                let rule = rules.get(name).ok_or(VfsError::Enoent)?;
                let mut body = Vec::new();
                body.extend_from_slice(if rule.enabled { b"enabled\n" } else { b"disabled\n" });
                body.extend_from_slice(&rule.line);
                body.push(b'\n');
                body
            }
        };
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, inode: &Inode, _off: u64, src: &[u8]) -> KResult<usize> {
        let d = inode.private::<BinfmtFileData>().ok_or(VfsError::Einval)?;
        match &d.kind {
            BinKind::Status => match trim_newline(src) {
                b"1" => d.state.enabled.store(true, Ordering::Release),
                b"0" => d.state.enabled.store(false, Ordering::Release),
                b"-1" => d.state.clear(),
                _ => return Err(VfsError::Einval),
            },
            BinKind::Register => { d.state.register(src)?; }
            BinKind::Rule(name) => {
                let mut rules = d.state.rules.lock();
                let rule = rules.get_mut(name).ok_or(VfsError::Enoent)?;
                match trim_newline(src) {
                    b"1" => rule.enabled = true,
                    b"0" => rule.enabled = false,
                    b"-1" => { rules.remove(name); }
                    _ => return Err(VfsError::Einval),
                }
            }
        }
        Ok(src.len())
    }
}
