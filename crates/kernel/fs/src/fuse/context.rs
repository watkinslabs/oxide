//! Linux-style typed mount context for the normal (non-block) FUSE type.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;

use sync::{Spinlock, TaskList as LockClass};
use vfs::fs::{FsContext, FsContextOps, FsParamVerdict, FsParameter, FsValue, ParamResult};
use vfs::{File, SuperBlock, VfsError, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT,
    S_IFREG, S_IFSOCK};

use super::{dev, fs::MountOpts, mount_from_context, FUSE_PARAMS};

struct Context {
    file: Option<Arc<File>>,
    rootmode: Option<u32>,
    user_id: Option<u32>,
    group_id: Option<u32>,
    default_permissions: bool,
    allow_other: bool,
    max_read: u32,
    subtype: Option<String>,
}

impl Context {
    fn new() -> Self {
        Self {
            file: None,
            rootmode: None,
            user_id: None,
            group_id: None,
            default_permissions: false,
            allow_other: false,
            max_read: u32::MAX,
            subtype: None,
        }
    }

    fn finish(&self) -> Result<(Arc<File>, MountOpts), VfsError> {
        let file = self.file.clone().ok_or(VfsError::Einval)?;
        Ok((file, MountOpts {
            rootmode: self.rootmode.ok_or(VfsError::Einval)?,
            user_id: self.user_id.ok_or(VfsError::Einval)?,
            group_id: self.group_id.ok_or(VfsError::Einval)?,
            default_permissions: self.default_permissions,
            allow_other: self.allow_other,
            max_read: self.max_read,
            subtype: self.subtype.clone(),
        }))
    }
}

fn state(fc: &mut FsContext) -> &Spinlock<Context, LockClass> {
    if fc.fs_private().downcast_ref::<Spinlock<Context, LockClass>>().is_none() {
        fc.set_fs_private(Arc::new(Spinlock::<Context, LockClass>::new(Context::new())));
    }
    fc.fs_private().downcast_ref::<Spinlock<Context, LockClass>>()
        .expect("fuse fs_context private state")
}

fn uint(param: &FsParameter, radix: u32) -> Result<u32, VfsError> {
    let text = param.as_str().ok_or(VfsError::Einval)?;
    if text.is_empty() { return Err(VfsError::Einval); }
    if radix == 10 {
        if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            return u32::from_str_radix(hex, 16).map_err(|_| VfsError::Einval);
        }
    }
    u32::from_str_radix(text, radix).map_err(|_| VfsError::Einval)
}

fn file(param: &FsParameter) -> Result<Arc<File>, VfsError> {
    let file = match &param.value {
        FsValue::File { file, .. } => file.clone(),
        FsValue::String(_) => {
            let fd = i32::try_from(uint(param, 10)?).map_err(|_| VfsError::Einval)?;
            resolve_fd(fd)?
        }
        _ => return Err(VfsError::Einval),
    };
    if !dev::is_fuse_dev(&file) { return Err(VfsError::Einval); }
    Ok(file)
}

#[cfg(target_os = "oxide-kernel")]
fn resolve_fd(fd: i32) -> Result<Arc<File>, VfsError> {
    sched::proclink::proc_fd_file(None, fd).ok_or(VfsError::Ebadf)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn resolve_fd(_fd: i32) -> Result<Arc<File>, VfsError> { Err(VfsError::Ebadf) }

fn valid_rootmode(mode: u32) -> bool {
    matches!(mode & S_IFMT as u32,
        S_IFREG | S_IFDIR | S_IFLNK | S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK)
}

/// Stateless operations object; all per-mount values live in `fc.fs_private`.
pub struct FuseContextOps;

impl FsContextOps for FuseContextOps {
    fn parse_param(&self, fc: &mut FsContext, param: &FsParameter)
        -> Result<ParamResult, VfsError>
    {
        match vfs::fs::admit_fs_param(FUSE_PARAMS, param) {
            FsParamVerdict::Unknown => return Ok(ParamResult::Declined),
            FsParamVerdict::WrongValueShape(_) => return fc.invalf("fuse: unexpected parameter value"),
            FsParamVerdict::Accept(_) => {}
        }
        if param.key == "source" {
            if fc.source().is_some() { return fc.invalf("fuse: multiple sources specified"); }
            fc.set_source(param.as_str().ok_or(VfsError::Einval)?);
            return Ok(ParamResult::Consumed);
        }
        if param.key == "fd" {
            let channel = file(param)?;
            state(fc).lock().file = Some(channel);
            return Ok(ParamResult::Consumed);
        }

        let mut ctx = state(fc).lock();
        match param.key.as_str() {
            "rootmode" => {
                let mode = uint(param, 8)?;
                if !valid_rootmode(mode) { return Err(VfsError::Einval); }
                ctx.rootmode = Some(mode);
            }
            "user_id" => ctx.user_id = Some(uint(param, 10)?),
            "group_id" => ctx.group_id = Some(uint(param, 10)?),
            "default_permissions" => ctx.default_permissions = true,
            "allow_other" => ctx.allow_other = true,
            "max_read" => ctx.max_read = uint(param, 10)?,
            "blksize" => return Err(VfsError::Einval),
            "subtype" => {
                if ctx.subtype.is_some() { return Err(VfsError::Einval); }
                ctx.subtype = Some(param.as_str().ok_or(VfsError::Einval)?.into());
            }
            _ => return Ok(ParamResult::Declined),
        }
        Ok(ParamResult::Consumed)
    }

    fn get_tree(&self, fc: &mut FsContext) -> Result<Arc<SuperBlock>, VfsError> {
        let (file, options) = state(fc).lock().finish()?;
        let fs = mount_from_context(options, &file)?;
        vfs::fs::superblock_from_filesystem(
            fc.fs_type().clone(), fs, None, "fuse".into(), fc.sb_flags(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::fs::{FsFlags, FsType, vfs_parse_fs_param};

    fn mount_context() -> FsContext {
        let ty = FsType::with_context_parameters(
            "fuse-test", super::super::FUSE_SUPER_MAGIC, FsFlags::empty(),
            Arc::new(FuseContextOps), FUSE_PARAMS,
        );
        FsContext::for_mount(ty, 0)
    }

    #[test]
    fn exact_libfuse_values_are_parsed_once_into_typed_state() {
        let mut fc = mount_context();
        for (key, value) in [
            ("rootmode", "40000"), ("user_id", "1000"), ("group_id", "1001"),
            ("max_read", "131072"), ("subtype", "fuse.portal"),
        ] {
            vfs_parse_fs_param(&mut fc, &FsParameter::string(key, value)).unwrap();
        }
        vfs_parse_fs_param(&mut fc, &FsParameter::flag("default_permissions")).unwrap();
        vfs_parse_fs_param(&mut fc, &FsParameter::flag("allow_other")).unwrap();
        let ctx = state(&mut fc).lock();
        assert_eq!(ctx.rootmode, Some(S_IFDIR | 0o000));
        assert_eq!(ctx.user_id, Some(1000));
        assert_eq!(ctx.group_id, Some(1001));
        assert_eq!(ctx.max_read, 131072);
        assert_eq!(ctx.subtype.as_deref(), Some("fuse.portal"));
        assert!(ctx.default_permissions && ctx.allow_other);
    }

    #[test]
    fn normal_fuse_refuses_fuseblk_only_blksize() {
        let mut fc = mount_context();
        assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::string("blksize", "512")),
            Err(VfsError::Einval));
    }

    #[test]
    fn rootmode_and_all_identity_fields_are_required() {
        let mut fc = mount_context();
        let ctx = state(&mut fc).lock();
        assert!(ctx.finish().is_err());
        drop(ctx);
        for (key, value) in [("rootmode", "40000"), ("user_id", "1000")] {
            vfs_parse_fs_param(&mut fc, &FsParameter::string(key, value)).unwrap();
        }
        let ctx = state(&mut fc).lock();
        assert!(ctx.group_id.is_none(), "group_id is required, never silently defaulted");
    }
}
