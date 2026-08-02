extern crate alloc;

use alloc::sync::Arc;

use crate::superblock::SuperBlock;

use super::context::FsContext;
use super::types::{FsParameter, FsValue, KResult};
use crate::fs::fs_parser::FsParamVerdict;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ParamResult { Consumed, Declined }

pub trait FsContextOps: Send + Sync {
    fn parse_param(&self, _fc: &mut FsContext, _param: &FsParameter) -> KResult<ParamResult> { Ok(ParamResult::Declined) }
    /// `fs_context_operations::parse_monolithic` — how this backend consumes
    /// the `mount(2)` data blob. The default is the generic comma split, so a
    /// backend that says nothing gets the same per-key admission `fsconfig(2)`
    /// applies. # C: O(len data)
    fn parse_monolithic(&self, fc: &mut FsContext, data: &str) -> KResult<()> {
        super::monolithic::generic_parse_monolithic(fc, data)
    }
    fn get_tree(&self, fc: &mut FsContext) -> KResult<Arc<SuperBlock>>;
    fn reconfigure(&self, _fc: &mut FsContext) -> KResult<()> { Ok(()) }
    fn free(&self, _fc: &mut FsContext) {}
}

pub struct ClassicMountFsContextOps;

impl FsContextOps for ClassicMountFsContextOps {
    /// A filesystem that declares no parameter table is the legacy backend: it
    /// takes a monolithic option string and cannot reject a KEY, so every flag
    /// and string is swallowed here exactly as before. It can still reject a
    /// value it has no way to represent — there is no text form of an open file
    /// or a byte blob to put in a comma-separated string — and the reference
    /// refuses those on exactly that ground.
    ///
    /// A filesystem that DOES declare a table is admitted against it, and the
    /// table decides the value type as well as the key. THE TABLE IS CONSULTED
    /// FIRST: rejecting a file- or path-valued parameter before the lookup made
    /// every value-carrying `fsconfig(2)` command unreachable, so a filesystem
    /// declaring a descriptor-typed parameter could never be given one no
    /// matter what it declared.
    ///
    /// A key outside the table is declined, which sends it to `source` and then
    /// to the "unknown parameter" report — that rejection is what lets an
    /// option support query get a truthful answer. A key inside the table given
    /// the wrong value shape is a different error and is reported here rather
    /// than declined, so it cannot be mistaken for a device name.
    fn parse_param(&self, fc: &mut FsContext, param: &FsParameter) -> KResult<ParamResult> {
        if param.key == "source" { return Ok(ParamResult::Declined); }
        let specs = match fc.fs_type.parameters() {
            Some(specs) => specs,
            None => return match &param.value {
                FsValue::Flag | FsValue::String(_) => {
                    fc.params.push(param.clone());
                    Ok(ParamResult::Consumed)
                }
                _ => fc.invalf("VFS: Legacy: Can't set options with a file, path or blob"),
            },
        };
        match crate::fs::fs_parser::admit(specs, param) {
            FsParamVerdict::Accept(_) => {}
            FsParamVerdict::Unknown => return Ok(ParamResult::Declined),
            FsParamVerdict::WrongValueShape(_) => {
                return fc.invalf("VFS: unexpected value for parameter");
            }
        }
        fc.params.push(param.clone());
        Ok(ParamResult::Consumed)
    }

    /// A filesystem that publishes no parameter table cannot reject a key, so
    /// splitting its blob would only lose information (quoted values, key
    /// order, repeated keys) before handing the pieces back to a constructor
    /// that wants the string whole. Keep it verbatim — the pre-table
    /// behaviour, unchanged.
    ///
    /// A filesystem that DOES publish one takes the generic split, so every
    /// key it receives from `mount(2)` passed the same admission `fsconfig(2)`
    /// applies. # C: O(len data)
    fn parse_monolithic(&self, fc: &mut FsContext, data: &str) -> KResult<()> {
        if fc.fs_type.parameters().is_none() {
            fc.set_monolithic(data);
            return Ok(());
        }
        super::monolithic::generic_parse_monolithic(fc, data)
    }

    /// The `SB_*` word is stamped where the instance is CREATED, never here.
    ///
    /// `sget` either mints an instance — which the fill-super stamps with the
    /// request's flags — or hands back one that is already live and already
    /// carries the flags ITS mount asked for. Re-stamping the returned
    /// superblock could only ever change the second case, and changing it
    /// means one mount silently rewriting another's read-only state. The
    /// refusal that replaces it belongs to the party that knows whether the
    /// instance was reused (`superblock_from_filesystem`), not to a guess made
    /// from the flags after the fact.
    fn get_tree(&self, fc: &mut FsContext) -> KResult<Arc<SuperBlock>> {
        let opts = fc.classic_mount_options();
        let pinned = fc.pinned_params();
        let target = fc.mount_target().unwrap_or("");
        fc.fs_type.mount_at(fc.source(), target, &opts, fc.sb_flags, &pinned)
    }
}

pub trait FsContextSecurity: Send + Sync {
    fn parse_param(&self, _fc: &mut FsContext, _param: &FsParameter) -> KResult<ParamResult> { Ok(ParamResult::Declined) }
    fn set_mnt_opts(&self, _fc: &mut FsContext, _sb: &Arc<SuperBlock>) -> KResult<()> { Ok(()) }
    fn free(&self, _fc: &mut FsContext) {}
}
