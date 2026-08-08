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

use super::ops::{FsContextOps, FsContextSecurity, ClassicMountFsContextOps};
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
    /// The `mount(2)` data blob kept WHOLE, for a filesystem that publishes no
    /// parameter table (`legacy_fs_context`'s `legacy_data`). `None` on every
    /// `fsopen(2)`/`fspick(2)` context, which has no blob.
    pub(super) monolithic:    Option<String>,
    /// The `mount(2)` target pathname. `fsopen(2)` has none — the target is
    /// chosen later, at `move_mount(2)` — so this is `None` there, and a
    /// filesystem whose superblock identity depends on it must tolerate that.
    pub(super) mount_target:  Option<String>,
    pub(super) root:          Option<Arc<Dentry>>,
    pub(super) sb:            Option<Arc<SuperBlock>>,
    pub(super) fs_private:    Arc<dyn Any + Send + Sync>,
    pub(super) log:           Vec<String>,
    pub(super) security:      Option<Arc<dyn FsContextSecurity>>,
    /// `FSCONFIG_CMD_CREATE_EXCL`: reject reuse of a matching shared super.
    pub(super) create_exclusive: bool,
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
            ops: Arc::new(ClassicMountFsContextOps),
            fs_type, purpose, phase, sb_flags, sb_flags_mask,
            source: None, params: Vec::new(), monolithic: None, mount_target: None,
            root: None, sb: None, fs_private: Arc::new(()), log: Vec::new(), security: None, create_exclusive: false,
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
    /// Keep the `mount(2)` data blob whole for an unconverted backend. # C: O(len)
    pub fn set_monolithic(&mut self, data: &str) { self.monolithic = Some(data.to_string()); }
    /// The verbatim blob, if this context kept one. # C: O(1)
    pub fn monolithic(&self) -> Option<&str> { self.monolithic.as_deref() }
    /// Record the `mount(2)` target pathname. # C: O(len)
    pub fn set_mount_target(&mut self, target: &str) { self.mount_target = Some(target.to_string()); }
    /// The `mount(2)` target, or `None` on a context that never named one. # C: O(1)
    pub fn mount_target(&self) -> Option<&str> { self.mount_target.as_deref() }
    pub fn set_fs_private(&mut self, p: Arc<dyn Any + Send + Sync>) { self.fs_private = p; }
    /// Select `CMD_CREATE_EXCL` superblock admission for the pending create.
    /// # C: O(1)
    pub fn set_create_exclusive(&mut self, exclusive: bool) { self.create_exclusive = exclusive; }
    /// Whether the pending create must not reuse an existing superblock. # C: O(1)
    pub fn create_exclusive(&self) -> bool { self.create_exclusive }
    pub fn fail(&mut self) { self.phase = FsContextPhase::Failed; }

    /// The option string the backend's `fill_super` receives.
    ///
    /// A context that kept its blob whole replays it EXACTLY — no round-trip
    /// through the parameter list, so nothing is reordered, deduplicated or
    /// re-quoted on the way to a backend that parses the string itself.
    /// Otherwise it is rebuilt from the admitted parameters, which is the only
    /// form `fsconfig(2)` ever produces.
    ///
    /// A parameter that arrived as a pinned descriptor or a pathname renders
    /// its TEXT form here — `fd=17`, `usrjquota=/quota.user` — so a backend
    /// that reads its options out of a string sees exactly what the equivalent
    /// `mount -o` would have handed it. The descriptor case renders the number
    /// and [`FsContext::pinned_params`] carries the description that number
    /// named, because the number alone is stale the moment the caller closes
    /// the fd. # C: O(N_params)
    pub fn classic_mount_options(&self) -> String {
        if let Some(d) = &self.monolithic { return d.clone(); }
        let mut s = String::new();
        for p in &self.params {
            let rendered = match &p.value {
                FsValue::Flag => None,
                FsValue::String(v) => Some(v.clone()),
                FsValue::File { fd, .. } => Some(fd.to_string()),
                FsValue::Filename { path, .. } => Some(path.clone()),
                // No parameter type accepts a binary blob, so an admitted
                // parameter can never hold one and this arm is unreachable
                // through `vfs_parse_fs_param`. Rendering it as a bare word
                // rather than as bytes keeps a corrupt option string from ever
                // being handed to a backend.
                FsValue::Blob(_) => None,
            };
            if !s.is_empty() { s.push(','); }
            s.push_str(&p.key);
            if let Some(v) = rendered { s.push('='); s.push_str(&v); }
        }
        s
    }

    /// The admitted parameters whose value is an open file the kernel pinned
    /// when the parameter was parsed, in admission order. See
    /// [`crate::fs::FsConstructor`]. # C: O(N_params)
    pub fn pinned_params(&self) -> Vec<FsParameter> {
        self.params.iter().filter(|p| matches!(p.value, FsValue::File { .. })).cloned().collect()
    }

    /// One log entry, in the form `read(2)` on the context fd hands back
    /// verbatim: a level character, a space, the message, and a terminating
    /// newline. The newline is part of the stored string because the read
    /// returns exactly `strlen` bytes with no NUL, so a reader splitting on
    /// lines depends on it being there. The ring holds [`FC_LOG_MAX`] entries
    /// and drops the OLDEST on overflow — a filesystem that rejects a
    /// parameter early must not lose that message to a later one. # C: O(len)
    fn logfc(&mut self, level: char, msg: &str) {
        let mut e = String::with_capacity(msg.len() + 3);
        e.push(level);
        e.push(' ');
        e.push_str(msg);
        e.push('\n');
        if self.log.len() >= FC_LOG_MAX { self.log.remove(0); }
        self.log.push(e);
    }

    /// `fetch_message`: dequeue the OLDEST log entry for a reader whose buffer
    /// is `len` bytes.
    ///
    /// Three outcomes, and the difference between the last two is the whole
    /// point of the call: `Ok(Some(msg))` consumed one message; `Ok(None)` is
    /// an empty ring, which the caller reports as "no data available"; and
    /// `Err(Emsgsize)` is a message that does not fit, LEFT IN THE RING so the
    /// caller can retry with a bigger buffer. Consuming a message the reader
    /// cannot receive would lose it silently. # C: O(N_log)
    pub fn fetch_message(&mut self, len: usize) -> KResult<Option<String>> {
        let head = match self.log.first() { Some(h) => h, None => return Ok(None) };
        if head.len() > len { return Err(crate::types::VfsError::Emsgsize); }
        Ok(Some(self.log.remove(0)))
    }

    /// `read(2)` on the descriptor `fsopen(2)`/`fspick(2)` returned, whole.
    ///
    /// One message per call, oldest first, and the three outcomes are the
    /// point:
    /// - an empty ring is `ENODATA`, NOT a short read — end-of-file would tell
    ///   a caller the context is finished when it is merely quiet;
    /// - a message longer than the buffer is `EMSGSIZE` and STAYS QUEUED, so
    ///   the caller can retry larger; a truncating read would destroy the one
    ///   copy of the diagnostic;
    /// - otherwise the byte count, terminating newline included and no NUL.
    ///
    /// The file offset is ignored: the log is a queue, not a byte stream, and a
    /// seek cannot address a message already consumed. This lives here rather
    /// than in the descriptor's operations table because that table is
    /// `#![cfg(target_os = "oxide-kernel")]` — a decision written there cannot
    /// be tested. # C: O(N_log + len msg)
    pub fn read_message(&mut self, buf: &mut [u8]) -> KResult<usize> {
        match self.fetch_message(buf.len())? {
            None => Err(crate::types::VfsError::Enodata),
            Some(msg) => {
                let n = msg.len();
                buf[..n].copy_from_slice(msg.as_bytes());
                Ok(n)
            }
        }
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
