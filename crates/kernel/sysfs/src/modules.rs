// Dynamic `/sys/module` view over the loaded module registry.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use modules::ModuleParam;
use modules::registry::ModuleSnapshot;
use vfs::{mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use crate::{make_body_inode, DIR_PERM};

const INO_MODULE_ROOT: Ino = crate::ids::MODULE_ROOT;
const INO_MODULE_DIR: Ino = crate::ids::MODULE_DIR;
const INO_PARAM_DIR: Ino = crate::ids::MODULE_PARAM_DIR;
const INO_MODULE_ATTR: Ino = crate::ids::MODULE_ATTR;

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
            "taint"      => Ok(attr(line_u64_hex(d.snap.taints))),
            "license"    => Ok(attr(line_str(d.snap.license.as_deref().ok_or(VfsError::Enoent)?))),
            "vermagic"   => Ok(attr(line_str(d.snap.vermagic.as_deref().ok_or(VfsError::Enoent)?))),
            _ => Err(VfsError::Enoent),
        }
    }
}
impl FileOps for ModuleDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<ModuleDirData>().ok_or(VfsError::Einval)?;
        let entries = module_entries(&d.snap);
        for (idx, (name, ft)) in entries.iter().enumerate().skip(ctx.pos as usize) {
            let next = idx as u64 + 1;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, *ft, next) { return Ok(()); }
        }
        Ok(())
    }
}

fn module_entries(s: &ModuleSnapshot) -> Vec<(&'static str, FileType)> {
    let mut out = Vec::new();
    for e in [
        ("initstate",  FileType::Regular),
        ("refcnt",     FileType::Regular),
        ("taint",      FileType::Regular),
    ] {
        out.push(e);
    }
    if s.license.is_some() { out.push(("license", FileType::Regular)); }
    if s.vermagic.is_some() { out.push(("vermagic", FileType::Regular)); }
    out.push(("parameters", FileType::Directory));
    out
}

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

fn line_u64_hex(v: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut out = String::new();
    let _ = write!(out, "0x{:x}\n", v);
    out.into_bytes()
}

fn param_body(p: &ModuleParam) -> Vec<u8> {
    let mut out = String::new();
    if let Some(ty) = p.ty.as_deref() {
        out.push_str("type=");
        out.push_str(ty);
        out.push('\n');
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use modules::registry::ModuleState;

    fn snap() -> ModuleSnapshot {
        ModuleSnapshot {
            name: String::from("empty"),
            license: None,
            vermagic: None,
            params: Vec::new(),
            size: 0,
            refcnt: 0,
            taints: 0,
            state: ModuleState::Live,
            sections: 0,
            symbols: 0,
        }
    }

    #[test]
    fn optional_module_attrs_are_absent_when_metadata_missing() {
        let dir = make_module_dir(snap());
        assert_eq!(dir.lookup("license").map(|_| ()), Err(VfsError::Enoent));
        assert_eq!(dir.lookup("vermagic").map(|_| ()), Err(VfsError::Enoent));
        assert_eq!(module_entries(&snap()).iter().any(|(name, _)| *name == "license"), false);
        assert_eq!(module_entries(&snap()).iter().any(|(name, _)| *name == "vermagic"), false);
    }

    #[test]
    fn param_body_omits_missing_type() {
        let p = ModuleParam { name: String::from("debug"), desc: String::from("enable logs"), ty: None };
        assert_eq!(param_body(&p), b"description=enable logs\n".to_vec());
    }

    #[test]
    fn param_body_keeps_present_type() {
        let p = ModuleParam {
            name: String::from("debug"),
            desc: String::from("enable logs"),
            ty: Some(String::from("int")),
        };
        assert_eq!(param_body(&p), b"type=int\ndescription=enable logs\n".to_vec());
    }
}
