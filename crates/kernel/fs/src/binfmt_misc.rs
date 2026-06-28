//! Linux binfmt_misc filesystem.
//!
//! Mounted at `/proc/sys/fs/binfmt_misc`, this exposes the control files
//! userspace expects (`status`, `register`) and stores registered rules in a
//! kernel-owned table. Exec-time interpreter dispatch is a separate hook, but
//! the filesystem and registration ABI are real and stateful.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as LockClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

pub const BINFMT_MISC_MAGIC: u64 = 0x4249_4e4d;

static NEXT_INO: AtomicU64 = AtomicU64::new(0x4249_0000);

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
    root: Arc<BinfmtRoot>,
}

impl BinfmtMiscFs {
    pub fn new() -> Arc<Self> {
        let state = State::new();
        Arc::new(Self {
            root: Arc::new(BinfmtRoot { state, ino: NEXT_INO.fetch_add(1, Ordering::Relaxed) }),
        })
    }
}

impl vfs::fs::FileSystem for BinfmtMiscFs {
    fn name(&self) -> &str { "binfmt_misc" }
    fn magic(&self) -> u64 { BINFMT_MISC_MAGIC }
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone() as InodeRef) }
}

struct BinfmtRoot {
    state: Arc<State>,
    ino: Ino,
}

impl Inode for BinfmtRoot {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }

    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        match name {
            "status" => Ok(Arc::new(StatusInode {
                state: Arc::clone(&self.state),
                ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
            }) as InodeRef),
            "register" => Ok(Arc::new(RegisterInode {
                state: Arc::clone(&self.state),
                ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
            }) as InodeRef),
            _ => {
                let rules = self.state.rules.lock();
                if rules.contains_key(name) {
                    Ok(Arc::new(RuleInode {
                        state: Arc::clone(&self.state),
                        name: name.to_string(),
                        ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
                    }) as InodeRef)
                } else {
                    Err(VfsError::Enoent)
                }
            }
        }
    }

    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let mut idx = 0u64;
        for name in ["status", "register"] {
            if idx >= off {
                let ino = self.lookup(name).map(|i| i.ino()).unwrap_or(0);
                if !f(ino, idx + 1, name, FileType::Regular) {
                    return Ok(idx + 1);
                }
            }
            idx += 1;
        }
        let names: Vec<String> = self.state.rules.lock().keys().cloned().collect();
        for name in names {
            if idx >= off {
                let ino = self.lookup(&name).map(|i| i.ino()).unwrap_or(0);
                if !f(ino, idx + 1, &name, FileType::Regular) {
                    return Ok(idx + 1);
                }
            }
            idx += 1;
        }
        Ok(idx)
    }
}

struct StatusInode {
    state: Arc<State>,
    ino: Ino,
}

impl Inode for StatusInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 8 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = if self.state.enabled.load(Ordering::Acquire) {
            b"enabled\n".as_slice()
        } else {
            b"disabled\n".as_slice()
        };
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _off: u64, src: &[u8]) -> KResult<usize> {
        match trim_newline(src) {
            b"1" => self.state.enabled.store(true, Ordering::Release),
            b"0" => self.state.enabled.store(false, Ordering::Release),
            b"-1" => self.state.clear(),
            _ => return Err(VfsError::Einval),
        }
        Ok(src.len())
    }
}

struct RegisterInode {
    state: Arc<State>,
    ino: Ino,
}

impl Inode for RegisterInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn write(&self, _off: u64, src: &[u8]) -> KResult<usize> {
        self.state.register(src)?;
        Ok(src.len())
    }
}

struct RuleInode {
    state: Arc<State>,
    name: String,
    ino: Ino,
}

impl Inode for RuleInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 {
        self.state.rules.lock().get(&self.name).map(|r| r.line.len() as u64 + 16).unwrap_or(0)
    }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = {
            let rules = self.state.rules.lock();
            let rule = rules.get(&self.name).ok_or(VfsError::Enoent)?;
            let mut body = Vec::new();
            body.extend_from_slice(if rule.enabled { b"enabled\n" } else { b"disabled\n" });
            body.extend_from_slice(&rule.line);
            body.push(b'\n');
            body
        };
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
    fn write(&self, _off: u64, src: &[u8]) -> KResult<usize> {
        let mut rules = self.state.rules.lock();
        let rule = rules.get_mut(&self.name).ok_or(VfsError::Enoent)?;
        match trim_newline(src) {
            b"1" => rule.enabled = true,
            b"0" => rule.enabled = false,
            b"-1" => {
                rules.remove(&self.name);
            }
            _ => return Err(VfsError::Einval),
        }
        Ok(src.len())
    }
}
