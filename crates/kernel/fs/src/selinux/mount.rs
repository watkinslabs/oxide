use alloc::string::{String, ToString};
use alloc::sync::Arc;

use selinux_runtime::inode::MountOptions;
use vfs::fs::fs_context::{FsContext, FsContextSecurity, FsParameter, ParamResult};
use vfs::{SuperBlock, VfsError};

#[derive(Default)]
struct Options {
    context: Option<String>,
    fscontext: Option<String>,
    defcontext: Option<String>,
    rootcontext: Option<String>,
}

pub struct SelinuxFsContextSecurity {
    options: sync::Spinlock<Options, sync::Inode>,
}

pub fn factory() -> Arc<dyn FsContextSecurity> {
    Arc::new(SelinuxFsContextSecurity { options: sync::Spinlock::new(Options::default()) })
}

impl FsContextSecurity for SelinuxFsContextSecurity {
    fn parse_param(&self, _fc: &mut FsContext, param: &FsParameter) -> vfs::fs::KResult<ParamResult> {
        match param.key.as_str() {
            "context" | "fscontext" | "defcontext" | "rootcontext" => {}
            _ => return Ok(ParamResult::Declined),
        }
        let value = param.as_str().ok_or(VfsError::Einval)?;
        let mut options = self.options.lock();
        match param.key.as_str() {
            "context" if options.context.is_none() && options.defcontext.is_none() =>
                options.context = Some(value.to_string()),
            "fscontext" if options.fscontext.is_none() =>
                options.fscontext = Some(value.to_string()),
            "defcontext" if options.defcontext.is_none() && options.context.is_none() =>
                options.defcontext = Some(value.to_string()),
            "rootcontext" if options.rootcontext.is_none() =>
                options.rootcontext = Some(value.to_string()),
            _ => return Err(VfsError::Einval),
        }
        Ok(ParamResult::Consumed)
    }

    fn set_mnt_opts(&self, _fc: &mut FsContext, sb: &Arc<SuperBlock>) -> vfs::fs::KResult<()> {
        let options = self.options.lock();
        let context = options.context.as_deref();
        let fscontext = options.fscontext.as_deref();
        let defcontext = options.defcontext.as_deref();
        let rootcontext = options.rootcontext.as_deref();
        let fstype = sb.s_type.name().to_string();
        let security = selinux_runtime::with(|server| {
            selinux_runtime::inode::superblock_security(server, &fstype, &MountOptions {
                context, fscontext, defcontext, rootcontext,
            })
        });
        if let Some(security) = security { sb.set_security(Arc::new(security)); }
        Ok(())
    }
}

pub fn install() {
    vfs::fs::fs_context::set_security_factory(factory);
}
