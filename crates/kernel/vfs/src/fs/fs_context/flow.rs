use alloc::sync::Arc;

use crate::superblock::{SB_DIRSYNC, SB_LAZYTIME, SB_MANDLOCK, SB_RDONLY, SB_SYNCHRONOUS};
use crate::types::VfsError;

use super::context::FsContext;
use super::ops::ParamResult;
use super::types::{FsContextPhase, FsContextPurpose, FsParameter, FsValue, KResult};
use crate::fs::FsFlags;

/// `vfs_clean_context()`: after a successful mount or reconfigure the context
/// is returned to the state an `fspick(2)` would have produced — the realized
/// `(sb, root)` stay, everything that described HOW to build them is discarded.
/// This is what makes a second `fsmount(2)` on the same context fd report EBUSY
/// instead of minting a second mount object from one superblock. # C: O(1)
pub fn vfs_clean_context(fc: &mut FsContext) {
    fc.fs_private = Arc::new(());
    fc.sb_flags = 0;
    fc.source = None;
    fc.create_exclusive = false;
    fc.params.clear();
    // The blob and the target described HOW and WHERE to build the tree; both
    // are spent once it exists, and a later reconfigure must not replay the
    // original `mount(2)` option string as if it had been asked for again.
    fc.monolithic = None;
    fc.mount_target = None;
    fc.purpose = FsContextPurpose::Reconfigure;
    fc.phase = FsContextPhase::AwaitingReconf;
}

/// `finish_clean_context()`: the deferred half of [`vfs_clean_context`], run at
/// the head of every `fsconfig(2)` command. A context parked in
/// `AwaitingReconf` is re-armed for parameters; any other phase is untouched.
/// One implementation, so the parameter path and the command path cannot
/// disagree about when the promotion happens. # C: O(1)
pub fn finish_clean_context(fc: &mut FsContext) -> KResult<()> {
    if fc.phase != FsContextPhase::AwaitingReconf { return Ok(()); }
    fc.phase = FsContextPhase::ReconfParams;
    Ok(())
}

/// `vfs_cmd_create()` — `FSCONFIG_CMD_CREATE` / `FSCONFIG_CMD_CREATE_EXCL`.
/// `capable` is the caller's `mount_capable(fc)` answer, sampled by the syscall
/// shim because the capability facts are scheduler state.
///
/// PHASE OUTRANKS PRIVILEGE: a context in the wrong phase reports EBUSY even
/// for a caller who would have been refused anyway, so a program cannot probe
/// its own privilege by watching this errno. Without the privilege rung an
/// unprivileged user-namespace holder could realize — through `fsopen` +
/// `fsconfig` — a superblock of a type `mount(2)` reserves for the initial user
/// namespace. # C: O(filesystem get_tree)
pub fn vfs_cmd_create(fc: &mut FsContext, exclusive: bool, capable: bool) -> KResult<()> {
    if fc.phase != FsContextPhase::CreateParams { return Err(VfsError::Ebusy); }
    if !capable { return Err(VfsError::Eperm); }
    fc.set_create_exclusive(exclusive);
    vfs_get_tree(fc)
}

/// `vfs_cmd_reconfigure()` — `FSCONFIG_CMD_RECONFIGURE`. `capable` is
/// `ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)`: privilege over the user
/// namespace the INSTANCE's ids are expressed in, which is not the same test
/// `may_mount()` applied when the context fd was opened. A refusal marks the
/// context failed, so the caller cannot retry the same reconfigure after
/// gaining privilege on a context that already reported the attempt.
/// # C: O(filesystem reconfigure)
pub fn vfs_cmd_reconfigure(fc: &mut FsContext, capable: bool) -> KResult<()> {
    match fc.phase {
        FsContextPhase::AwaitingReconf | FsContextPhase::ReconfParams => {}
        _ => return Err(VfsError::Ebusy),
    }
    if !capable { fc.phase = FsContextPhase::Failed; return Err(VfsError::Eperm); }
    let r = reconfigure_super(fc);
    if r.is_ok() { vfs_clean_context(fc); }
    r
}

pub fn vfs_parse_fs_param(fc: &mut FsContext, param: &FsParameter) -> KResult<()> {
    match fc.phase {
        FsContextPhase::CreateParams | FsContextPhase::AwaitingReconf | FsContextPhase::ReconfParams => {}
        _ => return Err(VfsError::Ebusy),
    }
    if param.key.is_empty() { return fc.invalf("VFS: Empty parameter name"); }
    finish_clean_context(fc)?;
    // The superblock-flag rung is keyed on the NAME alone and never looks at
    // the value — `ro=1`, `ro=0` and a bare `ro` all set `SB_RDONLY`, because
    // the reference consults this table before any value is examined. Gating it
    // on a bare word instead sent `mount -o ro=1` down to the filesystem table,
    // which does not describe `ro` and reported it an unknown parameter.
    if vfs_parse_sb_flag(fc, &param.key) { return Ok(()); }
    if let Some(sec) = fc.security.clone() {
        match sec.parse_param(fc, param)? {
            ParamResult::Consumed => return Ok(()),
            ParamResult::Declined => {}
        }
    }
    let ops = fc.ops.clone();
    match ops.parse_param(fc, param)? {
        ParamResult::Consumed => return Ok(()),
        ParamResult::Declined => {}
    }
    vfs_parse_fs_param_source(fc, param)
}

fn vfs_parse_sb_flag(fc: &mut FsContext, key: &str) -> bool {
    let (bit, set) = match key {
        "ro" => (SB_RDONLY, true),
        "rw" => (SB_RDONLY, false),
        "sync" => (SB_SYNCHRONOUS, true),
        "async" => (SB_SYNCHRONOUS, false),
        "dirsync" => (SB_DIRSYNC, true),
        "mand" => (SB_MANDLOCK, true),
        "nomand" => (SB_MANDLOCK, false),
        "lazytime" => (SB_LAZYTIME, true),
        "nolazytime" => (SB_LAZYTIME, false),
        _ => return false,
    };
    if set { fc.sb_flags |= bit; } else { fc.sb_flags &= !bit; }
    true
}

pub fn vfs_parse_fs_param_source(fc: &mut FsContext, param: &FsParameter) -> KResult<()> {
    if param.key != "source" { return fc.invalf("VFS: Unknown parameter"); }
    match &param.value {
        FsValue::String(s) => {
            if fc.source.is_some() { return fc.invalf("VFS: Multiple sources"); }
            fc.source = Some(s.clone());
            Ok(())
        }
        FsValue::Flag | FsValue::File { .. } | FsValue::Filename { .. } | FsValue::Blob(_) => {
            fc.invalf("VFS: source needs a string value")
        }
    }
}

pub fn vfs_parse_fs_string(fc: &mut FsContext, key: &str, value: &str) -> KResult<()> {
    vfs_parse_fs_param(fc, &FsParameter::string(key, value))
}

pub fn vfs_get_tree(fc: &mut FsContext) -> KResult<()> {
    if fc.root.is_some() { return Err(VfsError::Ebusy); }
    if fc.phase != FsContextPhase::CreateParams { return Err(VfsError::Ebusy); }
    if fc.fs_type.fs_flags().contains(FsFlags::FS_REQUIRES_DEV) && fc.source.is_none() {
        fc.phase = FsContextPhase::Failed;
        return fc.invalf("VFS: Filesystem requires a source device");
    }
    fc.phase = FsContextPhase::Creating;
    let ops = fc.ops.clone();
    let sb = match ops.get_tree(fc) {
        Ok(sb) => sb,
        Err(e) => { fc.phase = FsContextPhase::Failed; return Err(e); }
    };
    let root = match sb.s_root() {
        Some(r) => r,
        None => { fc.phase = FsContextPhase::Failed; return Err(VfsError::Einval); }
    };
    fc.sb = Some(sb.clone());
    fc.root = Some(root);
    if let Some(sec) = fc.security.clone() {
        if let Err(e) = sec.set_mnt_opts(fc, &sb) {
            fc.phase = FsContextPhase::Failed;
            return Err(e);
        }
    }
    fc.phase = FsContextPhase::AwaitingMount;
    Ok(())
}

/// `FSCONFIG_CMD_CREATE_EXCL`: create a tree without sharing an existing
/// matching superblock. # C: O(filesystem get_tree)
pub fn vfs_get_tree_exclusive(fc: &mut FsContext) -> KResult<()> {
    fc.set_create_exclusive(true);
    vfs_get_tree(fc)
}

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
    let set = fc.sb_flags & fc.sb_flags_mask;
    let clear = !fc.sb_flags & fc.sb_flags_mask;
    // The backend sees the same option string a classic `mount -o remount`
    // would have handed it, rebuilt from the parameters this context collected.
    let data = fc.classic_mount_options();
    if let Err(e) = sb.reconfigure_super(set, clear, &data) {
        fc.phase = FsContextPhase::Failed;
        return Err(e);
    }
    fc.phase = FsContextPhase::AwaitingReconf;
    Ok(())
}
