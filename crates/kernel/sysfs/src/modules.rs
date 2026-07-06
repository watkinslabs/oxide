// Dynamic `/sys/module` view over the loaded module registry.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use modules::ModuleParam;
use modules::registry::ModuleSnapshot;
use vfs::{mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use crate::{make_body_inode, DIR_PERM};

const INO_MODULE_ROOT: Ino = 0x5100_7000;
const INO_MODULE_DIR:  Ino = 0x5100_7001;
const INO_PARAM_DIR:   Ino = 0x5100_7002;
const INO_MODULE_ATTR: Ino = 0x5100_7003;

struct ModuleRootOps;
impl InodeOps for ModuleRootOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let snap = find_module(name).ok_or(VfsError::Enoent)?;
        Ok(make_module_dir(snap))
    }
}
impl FileOps for ModuleRootOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let snap = modules::registry::snapshot();
        let mut idx = ctx.pos as usize;
        while idx < snap.len() {
            let next = idx as u64 + 1;
            let name = &snap[idx].name;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Directory, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}

struct ModuleDirData { snap: ModuleSnapshot }
struct ModuleDirOps;
impl InodeOps for ModuleDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<ModuleDirData>().ok_or(VfsError::Einval)?;
        match name {
            "parameters" => Ok(make_param_dir(d.snap.clone())),
            "initstate"  => Ok(attr(initstate_body(&d.snap))),
            "refcnt"     => Ok(attr(line_usize(d.snap.refcnt))),
            "license"    => Ok(attr(line_opt(d.snap.license.as_deref()))),
            "vermagic"   => Ok(attr(line_opt(d.snap.vermagic.as_deref()))),
            _ => Err(VfsError::Enoent),
        }
    }
}
impl FileOps for ModuleDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        for (idx, (name, ft)) in MODULE_ENTRIES.iter().enumerate().skip(ctx.pos as usize) {
            let next = idx as u64 + 1;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, *ft, next) { return Ok(()); }
        }
        Ok(())
    }
}

const MODULE_ENTRIES: [(&str, FileType); 5] = [
    ("initstate",  FileType::Regular),
    ("refcnt",     FileType::Regular),
    ("license",    FileType::Regular),
    ("vermagic",   FileType::Regular),
    ("parameters", FileType::Directory),
];

struct ParamDirData { snap: ModuleSnapshot }
struct ParamDirOps;
impl InodeOps for ParamDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<ParamDirData>().ok_or(VfsError::Einval)?;
        let p = d.snap.params.iter().find(|p| p.name == name).ok_or(VfsError::Enoent)?;
        Ok(make_body_inode(param_body(p), attr_ino(name)))
    }
}
impl FileOps for ParamDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<ParamDirData>().ok_or(VfsError::Einval)?;
        let mut idx = ctx.pos as usize;
        while idx < d.snap.params.len() {
            let next = idx as u64 + 1;
            let name = &d.snap.params[idx].name;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Regular, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}

/// Register `/sys/module`. # C: O(1)
pub fn init() {
    crate::register("/sys/module", make_module_root());
}

fn make_module_root() -> InodeRef {
    InodeBuilder::new(INO_MODULE_ROOT, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(ModuleRootOps), Arc::new(ModuleRootOps)).build()
}

fn make_module_dir(snap: ModuleSnapshot) -> InodeRef {
    InodeBuilder::new(INO_MODULE_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(ModuleDirOps), Arc::new(ModuleDirOps))
        .private(Arc::new(ModuleDirData { snap }))
        .build()
}

fn make_param_dir(snap: ModuleSnapshot) -> InodeRef {
    InodeBuilder::new(INO_PARAM_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(ParamDirOps), Arc::new(ParamDirOps))
        .private(Arc::new(ParamDirData { snap }))
        .build()
}

fn find_module(name: &str) -> Option<ModuleSnapshot> {
    modules::registry::snapshot().into_iter().find(|m| m.name == name)
}

fn attr(body: Vec<u8>) -> InodeRef {
    make_body_inode(body, INO_MODULE_ATTR)
}

fn attr_ino(name: &str) -> Ino {
    let mut h = INO_MODULE_ATTR;
    for b in name.as_bytes() { h = h.wrapping_mul(33).wrapping_add(*b as u64); }
    h
}

fn initstate_body(s: &ModuleSnapshot) -> Vec<u8> {
    line_str(s.state.as_str())
}

fn line_opt(v: Option<&str>) -> Vec<u8> {
    line_str(v.unwrap_or(""))
}

fn line_str(v: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(v.as_bytes());
    out.push(b'\n');
    out
}

fn line_usize(v: usize) -> Vec<u8> {
    let mut out = String::new();
    push_dec(&mut out, v);
    out.push('\n');
    out.into_bytes()
}

fn param_body(p: &ModuleParam) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("type=");
    out.push_str(p.ty.as_deref().unwrap_or(""));
    out.push('\n');
    out.push_str("description=");
    out.push_str(&p.desc);
    out.push('\n');
    out.into_bytes()
}

fn push_dec(out: &mut String, mut n: usize) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 { break; }
    }
    for b in &buf[i..] { out.push(*b as char); }
}
