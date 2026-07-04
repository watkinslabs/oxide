extern crate alloc;

use alloc::sync::Arc;

use crate::superblock::SuperBlock;

use super::context::{FsContext, apply_sb_flags};
use super::types::{FsParameter, FsValue, KResult};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ParamResult { Consumed, Declined }

pub trait FsContextOps: Send + Sync {
    fn parse_param(&self, _fc: &mut FsContext, _param: &FsParameter) -> KResult<ParamResult> { Ok(ParamResult::Declined) }
    fn get_tree(&self, fc: &mut FsContext) -> KResult<Arc<SuperBlock>>;
    fn reconfigure(&self, _fc: &mut FsContext) -> KResult<()> { Ok(()) }
    fn free(&self, _fc: &mut FsContext) {}
}

pub struct LegacyFsContextOps;

impl FsContextOps for LegacyFsContextOps {
    fn parse_param(&self, fc: &mut FsContext, param: &FsParameter) -> KResult<ParamResult> {
        if param.key == "source" { return Ok(ParamResult::Declined); }
        match &param.value {
            FsValue::Flag | FsValue::String(_) => {}
            FsValue::File(_) | FsValue::Filename { .. } | FsValue::Blob(_) => {
                return fc.invalf("VFS: Legacy: unsupported value type for parameter");
            }
        }
        fc.params.push(param.clone());
        Ok(ParamResult::Consumed)
    }

    fn get_tree(&self, fc: &mut FsContext) -> KResult<Arc<SuperBlock>> {
        let opts = fc.legacy_options();
        let src = fc.source().unwrap_or("");
        let sb = fc.fs_type.mount(src, &opts)?;
        apply_sb_flags(&sb, fc.sb_flags, fc.sb_flags_mask);
        Ok(sb)
    }
}

pub trait FsContextSecurity: Send + Sync {
    fn parse_param(&self, _fc: &mut FsContext, _param: &FsParameter) -> KResult<ParamResult> { Ok(ParamResult::Declined) }
    fn set_mnt_opts(&self, _fc: &mut FsContext, _sb: &Arc<SuperBlock>) -> KResult<()> { Ok(()) }
    fn free(&self, _fc: &mut FsContext) {}
}
