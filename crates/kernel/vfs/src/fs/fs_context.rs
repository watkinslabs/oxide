//! `struct fs_context` — the modern mount-API context (Linux
//! `fs/fs_context.c`, `include/linux/fs_context.h`).
//!
//! The new mount API (`fsopen`/`fsconfig`/`fsmount`/`fspick`/`move_mount`,
//! `docs/16`) builds a mount in PHASES around a long-lived context object
//! instead of the single monolithic `mount(2)` call:
//!
//! 1. `fsopen` → [`FsContext::for_mount`] (purpose [`FsContextPurpose::Mount`],
//!    phase [`FsContextPhase::CreateParams`]).
//! 2. `fsconfig(SET_STRING/SET_FLAG/SET_PATH)` → [`vfs_parse_fs_param`], one
//!    [`FsParameter`] at a time, ACCUMULATED on the context (no longer dropped).
//! 3. `fsconfig(CMD_CREATE)` → [`vfs_get_tree`]: run `get_tree` to materialise a
//!    [`SuperBlock`] and pin `fc->root`.
//! 4. `fsmount` → a detached `struct mount` over `fc->root` (mount/syscall lane).
//! 5. `fspick` → [`FsContext::for_reconfigure`] (purpose
//!    [`FsContextPurpose::Reconfigure`]) sharing the live SB; a later
//!    `fsconfig(CMD_RECONFIGURE)` → [`reconfigure_super`].
//!
//! This module is the VFS-LAYER object model the syscall handlers drive; the
//! handlers themselves (parse/validate/fetch user memory) live in the syscall
//! lane and are not defined here.

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
use crate::types::VfsError;

/// `KResult<T>` — the VFS error envelope (re-aliased for trait bodies).
pub type KResult<T> = core::result::Result<T, VfsError>;

/// `sb_flags_mask` the new mount API lets a user toggle on a superblock (Linux
/// `MS_RMT_MASK` ∪ the per-sb option bits `reconfigure_super` rewrites). Only
/// these `SB_*` bits are copied from `fc->sb_flags` into `sb->s_flags`; the
/// lifecycle bits (`SB_BORN`/`SB_ACTIVE`) are never user-settable. # C: O(1)
pub const SB_FLAGS_USER_MASK: u64 = SB_RDONLY
    | SB_NOSUID
    | SB_NODEV
    | SB_NOEXEC
    | SB_SYNCHRONOUS
    | SB_MANDLOCK
    | SB_DIRSYNC
    | SB_NOATIME
    | SB_NODIRATIME;

/// `enum fs_context_purpose` (Linux `include/linux/fs_context.h`). Distinguishes
/// a fresh mount from a submount clone from a live-SB reconfiguration so
/// `get_tree`/`reconfigure` dispatch and the permission checks differ.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FsContextPurpose {
    /// `FS_CONTEXT_FOR_MOUNT` — a brand-new mount (`fsopen`).
    Mount,
    /// `FS_CONTEXT_FOR_SUBMOUNT` — an automount/submount clone of a parent SB.
    Submount,
    /// `FS_CONTEXT_FOR_RECONFIGURE` — remount of an existing SB (`fspick`).
    Reconfigure,
}

/// `enum fs_context_phase` (Linux `include/linux/fs_context.h`) — the context
/// state machine. `fsconfig` commands are only legal in the matching phase
/// (params before create, create before mount), so an out-of-order command
/// fails rather than silently corrupting the build.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FsContextPhase {
    /// `FS_CONTEXT_CREATE_PARAMS` — accepting params for a new mount.
    CreateParams,
    /// `FS_CONTEXT_CREATING` — `get_tree` in progress.
    Creating,
    /// `FS_CONTEXT_AWAITING_MOUNT` — tree built, awaiting `fsmount`.
    AwaitingMount,
    /// `FS_CONTEXT_AWAITING_RECONF` — reconfigure context bound to a live SB.
    AwaitingReconf,
    /// `FS_CONTEXT_RECONF_PARAMS` — accepting params for a reconfigure.
    ReconfParams,
    /// `FS_CONTEXT_RECONFIGURING` — `reconfigure` in progress.
    Reconfiguring,
    /// `FS_CONTEXT_FAILED` — a fatal error occurred; only teardown is legal.
    Failed,
}

/// `enum fs_value_type` payload of one [`FsParameter`] (Linux
/// `include/linux/fs_parser.h`). v1 carries the two shapes `fsconfig` produces
/// from `SET_FLAG`/`SET_STRING`; blob/path/fd variants are noted for later.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FsValue {
    /// `fs_value_is_flag` — a bare key with no value (`fsconfig(SET_FLAG)`).
    Flag,
    /// `fs_value_is_string` — a `key=value` string (`fsconfig(SET_STRING)`).
    String(String),
}

/// `struct fs_parameter` (Linux `include/linux/fs_parser.h`) — ONE mount option
/// handed to [`vfs_parse_fs_param`]. The new API delivers options one structured
/// parameter at a time rather than as a single comma blob.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsParameter {
    /// `param->key` — the option name (`"size"`, `"ro"`, `"source"`).
    pub key: String,
    /// `param->{string,flag}` — the typed value.
    pub value: FsValue,
}

impl FsParameter {
    /// A `fs_value_is_flag` parameter (`fsconfig(SET_FLAG, key)`). # C: O(len key)
    pub fn flag(key: &str) -> Self { Self { key: key.to_string(), value: FsValue::Flag } }

    /// A `fs_value_is_string` parameter (`fsconfig(SET_STRING, key, value)`).
    /// # C: O(len key + len val)
    pub fn string(key: &str, value: &str) -> Self {
        Self { key: key.to_string(), value: FsValue::String(value.to_string()) }
    }

    /// The string payload, or `None` for a bare flag. # C: O(1)
    pub fn as_str(&self) -> Option<&str> {
        match &self.value { FsValue::String(s) => Some(s), FsValue::Flag => None }
    }
}

/// Outcome of [`FsContextOps::parse_param`] — Linux distinguishes "I consumed
/// this option" from `-ENOPARAM` ("not mine, try the generic handler"). Modelled
/// as a typed result instead of overloading an errno into the envelope.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ParamResult {
    /// The backend handled the parameter (Linux `return 0`).
    Consumed,
    /// The backend does not recognise the key (Linux `-ENOPARAM`); the caller
    /// falls through to the generic `source` handler.
    Declined,
}

/// `struct fs_context_operations` (Linux `include/linux/fs_context.h`) — the
/// per-fs vtable the context drives. A backend installs its own ops via
/// `init_fs_context`; a backend that predates the new API uses
/// [`LegacyFsContextOps`] (Linux `legacy_fs_context_ops`), whose `get_tree`
/// calls the old `file_system_type::mount`.
pub trait FsContextOps: Send + Sync {
    /// `parse_param` — consume one option. Default declines everything so the
    /// generic `source` handling in [`vfs_parse_fs_param`] runs. # C: FS-dependent
    fn parse_param(&self, _fc: &mut FsContext, _param: &FsParameter) -> KResult<ParamResult> {
        Ok(ParamResult::Declined)
    }

    /// `get_tree` — materialise the superblock and pin `fc->root`. Called once by
    /// [`vfs_get_tree`]. # C: FS-dependent
    fn get_tree(&self, fc: &mut FsContext) -> KResult<Arc<SuperBlock>>;

    /// `reconfigure` — apply parsed params to the LIVE superblock (remount).
    /// Default no-op (flag-only remount handled by [`reconfigure_super`]).
    /// # C: FS-dependent
    fn reconfigure(&self, _fc: &mut FsContext) -> KResult<()> { Ok(()) }

    /// `free` — release backend-private state on context teardown. Default no-op.
    /// # C: FS-dependent
    fn free(&self, _fc: &mut FsContext) {}
}

/// `legacy_fs_context_ops` (Linux `fs/fs_context.c`) — the adapter for a backend
/// that has no `init_fs_context`. Options are accumulated on the context and
/// replayed to the old `file_system_type::mount(src, opts)` at `get_tree`.
pub struct LegacyFsContextOps;

impl FsContextOps for LegacyFsContextOps {
    /// `legacy_parse_param`: defer `source` to the generic handler (Linux
    /// `vfs_parse_fs_param_source`), append every other option to the context's
    /// accumulated param list. # C: O(len key+val)
    fn parse_param(&self, fc: &mut FsContext, param: &FsParameter) -> KResult<ParamResult> {
        if param.key == "source" { return Ok(ParamResult::Declined); }
        fc.params.push(param.clone());
        Ok(ParamResult::Consumed)
    }

    /// `legacy_get_tree`: join the accumulated params into the comma-separated
    /// option string the old `->mount` expects, build the superblock, then stamp
    /// the user-settable `sb_flags` (e.g. `SB_RDONLY`) onto it. # C: O(N params)
    fn get_tree(&self, fc: &mut FsContext) -> KResult<Arc<SuperBlock>> {
        let opts = fc.legacy_options();
        let src = fc.source().unwrap_or("");
        let sb = fc.fs_type.mount(src, &opts)?;
        apply_sb_flags(&sb, fc.sb_flags, fc.sb_flags_mask);
        Ok(sb)
    }
}

/// Stamp the masked user `sb_flags` onto a superblock (the `SB_RDONLY` slice
/// also drives the dedicated RO writer-gate). # C: O(1)
fn apply_sb_flags(sb: &SuperBlock, sb_flags: u64, mask: u64) {
    let set = sb_flags & mask;
    let clear = !sb_flags & mask;
    sb.set_s_flags(set, clear);
    // Keep the dedicated RO writer-gate (`sb_start_write`) in sync with the bit.
    sb.set_readonly(set & SB_RDONLY != 0);
}

/// `struct fs_context`. One per in-flight mount/reconfigure (`16§6`).
pub struct FsContext {
    /// `fc->ops` — the fs_context_operations vtable.
    ops: Arc<dyn FsContextOps>,
    /// `fc->fs_type` — the filesystem being mounted/reconfigured.
    fs_type: Arc<dyn FileSystemType>,
    /// `fc->purpose`.
    purpose: FsContextPurpose,
    /// `fc->phase`.
    phase: FsContextPhase,
    /// `fc->sb_flags` — the `SB_*` bits to set on the superblock.
    sb_flags: u64,
    /// `fc->sb_flags_mask` — which `SB_*` bits this context may write.
    sb_flags_mask: u64,
    /// `fc->source` — the `dev_name`/source string (e.g. `/dev/vda1`).
    source: Option<String>,
    /// Accumulated parsed options (Linux: the legacy comma blob / the backend's
    /// parsed `fs_private` state). Held so `fsconfig` params are NEVER dropped.
    params: Vec<FsParameter>,
    /// `fc->root` — the root dentry once `get_tree` succeeds.
    root: Option<Arc<Dentry>>,
    /// The superblock `fc->root` belongs to (Linux `fc->root->d_sb`). Set by
    /// `get_tree`; for a reconfigure context it is the live SB being remounted.
    sb: Option<Arc<SuperBlock>>,
    /// `fc->fs_private` — backend scratch state. Default `()`.
    fs_private: Arc<dyn Any + Send + Sync>,
}

impl FsContext {
    /// `fs_context_for_mount` (Linux `fs/fs_context.c`) — a context for a NEW
    /// mount of `fs_type`. `sb_flags` carries the requested `SB_*` bits (masked to
    /// the user-settable set). Backends predating the new API get
    /// [`LegacyFsContextOps`]. # C: O(1)
    pub fn for_mount(fs_type: Arc<dyn FileSystemType>, sb_flags: u64) -> Self {
        Self::alloc(fs_type, FsContextPurpose::Mount, FsContextPhase::CreateParams,
            sb_flags, SB_FLAGS_USER_MASK)
    }

    /// `fs_context_for_submount` — an automount clone for `fs_type`. # C: O(1)
    pub fn for_submount(fs_type: Arc<dyn FileSystemType>, sb_flags: u64) -> Self {
        Self::alloc(fs_type, FsContextPurpose::Submount, FsContextPhase::CreateParams,
            sb_flags, SB_FLAGS_USER_MASK)
    }

    /// `fs_context_for_reconfigure` (Linux `fs/fs_context.c`) — a context bound to
    /// the LIVE superblock behind `root` (from `fspick`). A later
    /// [`reconfigure_super`] applies the parsed params/flags to `sb` in place.
    /// # C: O(1)
    pub fn for_reconfigure(sb: Arc<SuperBlock>, root: Arc<Dentry>, sb_flags: u64,
        sb_flags_mask: u64) -> Self {
        let fs_type = sb.s_type.clone();
        let mut fc = Self::alloc(fs_type, FsContextPurpose::Reconfigure,
            FsContextPhase::AwaitingReconf, sb_flags, sb_flags_mask & SB_FLAGS_USER_MASK);
        fc.root = Some(root);
        fc.sb = Some(sb);
        fc
    }

    /// Common allocator (`alloc_fs_context`). Picks [`LegacyFsContextOps`] as the
    /// default vtable (no `init_fs_context` registry yet). # C: O(1)
    fn alloc(fs_type: Arc<dyn FileSystemType>, purpose: FsContextPurpose,
        phase: FsContextPhase, sb_flags: u64, sb_flags_mask: u64) -> Self {
        Self {
            ops: Arc::new(LegacyFsContextOps),
            fs_type, purpose, phase,
            sb_flags, sb_flags_mask,
            source: None,
            params: Vec::new(),
            root: None,
            sb: None,
            fs_private: Arc::new(()),
        }
    }

    /// Install a backend-specific `fc->ops` (Linux `init_fs_context` replacing the
    /// legacy default). # C: O(1)
    pub fn set_ops(&mut self, ops: Arc<dyn FsContextOps>) { self.ops = ops; }

    /// `fc->fs_type`. # C: O(1)
    pub fn fs_type(&self) -> &Arc<dyn FileSystemType> { &self.fs_type }
    /// `fc->purpose`. # C: O(1)
    pub fn purpose(&self) -> FsContextPurpose { self.purpose }
    /// `fc->phase`. # C: O(1)
    pub fn phase(&self) -> FsContextPhase { self.phase }
    /// `fc->sb_flags`. # C: O(1)
    pub fn sb_flags(&self) -> u64 { self.sb_flags }
    /// `fc->sb_flags_mask`. # C: O(1)
    pub fn sb_flags_mask(&self) -> u64 { self.sb_flags_mask }
    /// `fc->source`. # C: O(1)
    pub fn source(&self) -> Option<&str> { self.source.as_deref() }
    /// `fc->root` — `Some` once `get_tree` (or a reconfigure bind) succeeded.
    /// # C: O(1)
    pub fn root(&self) -> Option<&Arc<Dentry>> { self.root.as_ref() }
    /// The superblock the context built / is reconfiguring. # C: O(1)
    pub fn sb(&self) -> Option<&Arc<SuperBlock>> { self.sb.as_ref() }
    /// Accumulated parsed options (Linux's never-dropped params). # C: O(1)
    pub fn params(&self) -> &[FsParameter] { &self.params }
    /// `fc->fs_private`. # C: O(1)
    pub fn fs_private(&self) -> &Arc<dyn Any + Send + Sync> { &self.fs_private }

    /// Set `fc->source` (`vfs_parse_fs_param_source`). # C: O(len src)
    pub fn set_source(&mut self, src: &str) { self.source = Some(src.to_string()); }
    /// Install `fc->fs_private` backend scratch. # C: O(1)
    pub fn set_fs_private(&mut self, p: Arc<dyn Any + Send + Sync>) { self.fs_private = p; }
    /// Mark the context fatally failed (Linux `FS_CONTEXT_FAILED`). # C: O(1)
    pub fn fail(&mut self) { self.phase = FsContextPhase::Failed; }

    /// Build the comma-separated legacy option string from accumulated params
    /// (`legacy_parse_param`'s replayed blob). Bare flags render as the key;
    /// `key=value` pairs render with the `=`. # C: O(total len)
    pub fn legacy_options(&self) -> String {
        let mut s = String::new();
        for p in &self.params {
            if !s.is_empty() { s.push(','); }
            s.push_str(&p.key);
            if let FsValue::String(v) = &p.value { s.push('='); s.push_str(v); }
        }
        s
    }
}

/// `vfs_parse_fs_param` (Linux `fs/fs_context.c`) — feed ONE option to the
/// context. The backend's `parse_param` gets first refusal; an unrecognised key
/// falls through to the generic `source` handler (`vfs_parse_fs_param_source`),
/// and anything still unclaimed is `Einval` (Linux "Unknown parameter"). A
/// second `source` is rejected (Linux "VFS: Multiple sources"). Only legal while
/// the context is accepting params. # C: FS-dependent
pub fn vfs_parse_fs_param(fc: &mut FsContext, param: &FsParameter) -> KResult<()> {
    match fc.phase {
        FsContextPhase::CreateParams | FsContextPhase::AwaitingReconf
        | FsContextPhase::ReconfParams => {}
        _ => return Err(VfsError::Ebusy),
    }
    if param.key.is_empty() { return Err(VfsError::Einval); }
    // A reconfigure context flips to its param-collecting phase on first param.
    if fc.phase == FsContextPhase::AwaitingReconf { fc.phase = FsContextPhase::ReconfParams; }

    let ops = fc.ops.clone();
    match ops.parse_param(fc, param)? {
        ParamResult::Consumed => return Ok(()),
        ParamResult::Declined => {}
    }
    vfs_parse_fs_param_source(fc, param)
}

/// `vfs_parse_fs_param_source` (Linux `fs/fs_context.c`) — the generic `source`
/// option handler the backend declines to. Non-`source` keys are `Einval`
/// (unknown parameter); a duplicate `source` is `Einval` (multiple sources); a
/// `source` flag with no string value is `Einval`. # C: O(len value)
pub fn vfs_parse_fs_param_source(fc: &mut FsContext, param: &FsParameter) -> KResult<()> {
    if param.key != "source" { return Err(VfsError::Einval); }
    match &param.value {
        FsValue::String(s) => {
            if fc.source.is_some() { return Err(VfsError::Einval); }
            fc.source = Some(s.clone());
            Ok(())
        }
        FsValue::Flag => Err(VfsError::Einval),
    }
}

/// `vfs_parse_fs_string` (Linux `fs/fs_context.c`) — convenience wrapping a
/// `key`/`value` into a string [`FsParameter`] for [`vfs_parse_fs_param`].
/// # C: O(len key+value)
pub fn vfs_parse_fs_string(fc: &mut FsContext, key: &str, value: &str) -> KResult<()> {
    vfs_parse_fs_param(fc, &FsParameter::string(key, value))
}

/// `vfs_get_tree` (Linux `fs/super.c`) — run the backend's `get_tree` to
/// materialise the superblock and pin `fc->root`. Re-running on a context that
/// already has a tree is `Ebusy` (Linux `if (fc->root) return -EBUSY`). On
/// success the context advances to [`FsContextPhase::AwaitingMount`] (awaiting
/// `fsmount`); a `get_tree` error fails the context. Validates that the backend
/// actually installed a root. # C: FS-dependent
pub fn vfs_get_tree(fc: &mut FsContext) -> KResult<()> {
    if fc.root.is_some() { return Err(VfsError::Ebusy); }
    if fc.phase != FsContextPhase::CreateParams { return Err(VfsError::Ebusy); }
    fc.phase = FsContextPhase::Creating;
    let ops = fc.ops.clone();
    let sb = match ops.get_tree(fc) {
        Ok(sb) => sb,
        Err(e) => { fc.phase = FsContextPhase::Failed; return Err(e); }
    };
    // The backend MUST have installed a root dentry (Linux WARNs + EINVAL if not).
    let root = match sb.s_root() {
        Some(r) => r,
        None => { fc.phase = FsContextPhase::Failed; return Err(VfsError::Einval); }
    };
    fc.sb = Some(sb);
    fc.root = Some(root);
    fc.phase = FsContextPhase::AwaitingMount;
    Ok(())
}

/// `reconfigure_super` (Linux `fs/super.c`) — apply a reconfigure context's
/// parsed params + `sb_flags` to its LIVE superblock in place (remount). Runs the
/// backend's `reconfigure` op, then copies the masked `sb_flags` slice into
/// `sb->s_flags` (Linux
/// `WRITE_ONCE(sb->s_flags, (s_flags & ~mask) | (sb_flags & mask))`), keeping the
/// dedicated `SB_RDONLY` writer-gate in sync. Only legal on a
/// [`FsContextPurpose::Reconfigure`] context bound to a SB. # C: FS-dependent
pub fn reconfigure_super(fc: &mut FsContext) -> KResult<()> {
    if fc.purpose != FsContextPurpose::Reconfigure { return Err(VfsError::Einval); }
    let sb = fc.sb.clone().ok_or(VfsError::Einval)?;
    match fc.phase {
        FsContextPhase::AwaitingReconf | FsContextPhase::ReconfParams => {}
        _ => return Err(VfsError::Ebusy),
    }
    fc.phase = FsContextPhase::Reconfiguring;
    let ops = fc.ops.clone();
    if let Err(e) = ops.reconfigure(fc) {
        fc.phase = FsContextPhase::Failed;
        return Err(e);
    }
    apply_sb_flags(&sb, fc.sb_flags, fc.sb_flags_mask);
    fc.phase = FsContextPhase::AwaitingReconf;
    Ok(())
}

/// Run `fc->ops->free` then drop the context (Linux `put_fs_context`). # C: O(1)
pub fn put_fs_context(mut fc: FsContext) {
    let ops = fc.ops.clone();
    ops.free(&mut fc);
}
