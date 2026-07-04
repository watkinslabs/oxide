extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use crate::dentry::Dentry;
use crate::superblock::{
    FileSystemType, SuperBlock, SB_DIRSYNC, SB_MANDLOCK, SB_NOATIME, SB_NODEV, SB_NODIRATIME,
    SB_NOEXEC, SB_NOSUID, SB_RDONLY, SB_SYNCHRONOUS,
};

use super::ops::{FsContextOps, FsContextSecurity, LegacyFsContextOps};
use super::types::{FsContextPhase, FsContextPurpose, FsParameter, FsValue, KResult};

pub const SB_FLAGS_USER_MASK: u64 = SB_RDONLY
    | SB_NOSUID
    | SB_NODEV
    | SB_NOEXEC
    | SB_SYNCHRONOUS
    | SB_MANDLOCK
    | SB_DIRSYNC
    | SB_NOATIME
    | SB_NODIRATIME;

pub struct FsContext {
    pub(super) ops:           Arc<dyn FsContextOps>,
    pub(super) fs_type:       Arc<dyn FileSystemType>,
    pub(super) purpose:       FsContextPurpose,
    pub(super) phase:         FsContextPhase,
    pub(super) sb_flags:      u64,
    pub(super) sb_flags_mask: u64,
    pub(super) source:        Option<String>,
    pub(super) params:        Vec<FsParameter>,
    pub(super) root:          Option<Arc<Dentry>>,
    pub(super) sb:            Option<Arc<SuperBlock>>,
    pub(super) fs_private:    Arc<dyn Any + Send + Sync>,
    pub(super) log:           Vec<String>,
    pub(super) security:      Option<Arc<dyn FsContextSecurity>>,
}

pub const FC_LOG_MAX: usize = 8;

pub fn apply_sb_flags(sb: &SuperBlock, sb_flags: u64, mask: u64) {
    let set = sb_flags & mask;
    let clear = !sb_flags & mask;
    sb.set_s_flags(set, clear);
    sb.set_readonly(set & SB_RDONLY != 0);
}

impl FsContext {
    pub fn for_mount(fs_type: Arc<dyn FileSystemType>, sb_flags: u64) -> Self {
        let mut fc = Self::alloc(fs_type, FsContextPurpose::Mount, FsContextPhase::CreateParams, sb_flags, SB_FLAGS_USER_MASK);
        if let Some(ops) = fc.fs_type.init_fs_context() { fc.ops = ops; }
        fc
    }
    pub fn for_submount(fs_type: Arc<dyn FileSystemType>, sb_flags: u64) -> Self {
        let mut fc = Self::alloc(fs_type, FsContextPurpose::Submount, FsContextPhase::CreateParams, sb_flags, SB_FLAGS_USER_MASK);
        if let Some(ops) = fc.fs_type.init_fs_context() { fc.ops = ops; }
        fc
    }
    pub fn for_reconfigure(sb: Arc<SuperBlock>, root: Arc<Dentry>, sb_flags: u64, sb_flags_mask: u64) -> Self {
        let fs_type = sb.s_type.clone();
        let mut fc = Self::alloc(fs_type, FsContextPurpose::Reconfigure, FsContextPhase::AwaitingReconf, sb_flags, sb_flags_mask & SB_FLAGS_USER_MASK);
        fc.root = Some(root);
        fc.sb = Some(sb);
        fc
    }

    fn alloc(fs_type: Arc<dyn FileSystemType>, purpose: FsContextPurpose, phase: FsContextPhase, sb_flags: u64, sb_flags_mask: u64) -> Self {
        Self {
            ops: Arc::new(LegacyFsContextOps),
            fs_type, purpose, phase, sb_flags, sb_flags_mask,
            source: None, params: Vec::new(), root: None, sb: None, fs_private: Arc::new(()), log: Vec::new(), security: None,
        }
    }

    pub fn set_ops(&mut self, ops: Arc<dyn FsContextOps>) { self.ops = ops; }
    pub fn set_security(&mut self, sec: Arc<dyn FsContextSecurity>) { self.security = Some(sec); }
    pub fn security(&self) -> Option<&Arc<dyn FsContextSecurity>> { self.security.as_ref() }
    pub fn fs_type(&self) -> &Arc<dyn FileSystemType> { &self.fs_type }
    pub fn purpose(&self) -> FsContextPurpose { self.purpose }
    pub fn phase(&self) -> FsContextPhase { self.phase }
    pub fn sb_flags(&self) -> u64 { self.sb_flags }
    pub fn sb_flags_mask(&self) -> u64 { self.sb_flags_mask }
    pub fn source(&self) -> Option<&str> { self.source.as_deref() }
    pub fn root(&self) -> Option<&Arc<Dentry>> { self.root.as_ref() }
    pub fn sb(&self) -> Option<&Arc<SuperBlock>> { self.sb.as_ref() }
    pub fn params(&self) -> &[FsParameter] { &self.params }
    pub fn fs_private(&self) -> &Arc<dyn Any + Send + Sync> { &self.fs_private }
    pub fn set_source(&mut self, src: &str) { self.source = Some(src.to_string()); }
    pub fn set_fs_private(&mut self, p: Arc<dyn Any + Send + Sync>) { self.fs_private = p; }
    pub fn fail(&mut self) { self.phase = FsContextPhase::Failed; }

    pub fn legacy_options(&self) -> String {
        let mut s = String::new();
        for p in &self.params {
            if !s.is_empty() { s.push(','); }
            s.push_str(&p.key);
            if let FsValue::String(v) = &p.value { s.push('='); s.push_str(v); }
        }
        s
    }

    fn logfc(&mut self, level: char, msg: &str) {
        let mut e = String::with_capacity(msg.len() + 2);
        e.push(level);
        e.push(' ');
        e.push_str(msg);
        if self.log.len() >= FC_LOG_MAX { self.log.remove(0); }
        self.log.push(e);
    }

    pub fn errorf(&mut self, msg: &str) { self.logfc('e', msg); }
    pub fn warnf(&mut self, msg: &str) { self.logfc('w', msg); }
    pub fn infof(&mut self, msg: &str) { self.logfc('i', msg); }
    pub fn invalf<T>(&mut self, msg: &str) -> KResult<T> { self.errorf(msg); Err(crate::types::VfsError::Einval) }
    pub fn log_messages(&self) -> &[String] { &self.log }
    pub fn take_log(&mut self) -> Vec<String> { core::mem::take(&mut self.log) }
}

pub fn put_fs_context(mut fc: FsContext) {
    if let Some(sec) = fc.security.clone() { sec.free(&mut fc); }
    let ops = fc.ops.clone();
    ops.free(&mut fc);
}
