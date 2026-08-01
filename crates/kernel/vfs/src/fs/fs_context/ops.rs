extern crate alloc;

use alloc::sync::Arc;

use crate::superblock::SuperBlock;

use super::context::{FsContext, apply_sb_flags};
use super::types::{FsParameter, FsValue, KResult};
use crate::fs::fs_parser::FsParamVerdict;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ParamResult { Consumed, Declined }

pub trait FsContextOps: Send + Sync {
    fn parse_param(&self, _fc: &mut FsContext, _param: &FsParameter) -> KResult<ParamResult> { Ok(ParamResult::Declined) }
    fn get_tree(&self, fc: &mut FsContext) -> KResult<Arc<SuperBlock>>;
    fn reconfigure(&self, _fc: &mut FsContext) -> KResult<()> { Ok(()) }
    fn free(&self, _fc: &mut FsContext) {}
}

pub struct ClassicMountFsContextOps;

impl FsContextOps for ClassicMountFsContextOps {
    /// A filesystem that declares no parameter table is the legacy backend: it
    /// takes a monolithic option string and cannot reject anything, so every
    /// key is swallowed here exactly as before.
    ///
    /// A filesystem that DOES declare one is admitted against it. A key outside
    /// the table is declined, which sends it to `source` and then to the
    /// "unknown parameter" report — that rejection is what lets an option
    /// support query get a truthful answer. A key inside the table given the
    /// wrong value shape is a different error and is reported here rather than
    /// declined, so it cannot be mistaken for a device name.
    fn parse_param(&self, fc: &mut FsContext, param: &FsParameter) -> KResult<ParamResult> {
        if param.key == "source" { return Ok(ParamResult::Declined); }
        match &param.value {
            FsValue::Flag | FsValue::String(_) => {}
            FsValue::File { .. } | FsValue::Filename { .. } | FsValue::Blob(_) => {
                return fc.invalf("VFS: classic mount: unsupported value type for parameter");
            }
        }
        if let Some(specs) = fc.fs_type.parameters() {
            match crate::fs::fs_parser::admit(specs, param) {
                FsParamVerdict::Accept(_) => {}
                FsParamVerdict::Unknown => return Ok(ParamResult::Declined),
                FsParamVerdict::WrongValueShape(_) => {
                    return fc.invalf("VFS: unexpected value for parameter");
                }
            }
        }
        fc.params.push(param.clone());
        Ok(ParamResult::Consumed)
    }

    fn get_tree(&self, fc: &mut FsContext) -> KResult<Arc<SuperBlock>> {
        let opts = fc.classic_mount_options();
        let sb = fc.fs_type.mount_with_flags(fc.source(), &opts, fc.sb_flags)?;
        apply_sb_flags(&sb, fc.sb_flags, fc.sb_flags_mask);
        Ok(sb)
    }
}

pub trait FsContextSecurity: Send + Sync {
    fn parse_param(&self, _fc: &mut FsContext, _param: &FsParameter) -> KResult<ParamResult> { Ok(ParamResult::Declined) }
    fn set_mnt_opts(&self, _fc: &mut FsContext, _sb: &Arc<SuperBlock>) -> KResult<()> { Ok(()) }
    fn free(&self, _fc: &mut FsContext) {}
}
