use crate::superblock::{SB_DIRSYNC, SB_LAZYTIME, SB_MANDLOCK, SB_RDONLY, SB_SYNCHRONOUS};
use crate::types::VfsError;

use super::context::{FsContext, apply_sb_flags};
use super::ops::ParamResult;
use super::types::{FsContextPhase, FsContextPurpose, FsParameter, FsValue, KResult};
use crate::fs::FsFlags;

pub fn vfs_parse_fs_param(fc: &mut FsContext, param: &FsParameter) -> KResult<()> {
    match fc.phase {
        FsContextPhase::CreateParams | FsContextPhase::AwaitingReconf | FsContextPhase::ReconfParams => {}
        _ => return Err(VfsError::Ebusy),
    }
    if param.key.is_empty() { return fc.invalf("VFS: Empty parameter name"); }
    if fc.phase == FsContextPhase::AwaitingReconf { fc.phase = FsContextPhase::ReconfParams; }
    if let FsValue::Flag = param.value {
        if vfs_parse_sb_flag(fc, &param.key) { return Ok(()); }
    }
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
        FsValue::Flag | FsValue::File(_) | FsValue::Filename { .. } | FsValue::Blob(_) => {
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
