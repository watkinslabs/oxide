//! Linux-style typed mount context for autofs.

extern crate alloc;

use alloc::sync::Arc;
#[cfg(target_os = "oxide-kernel")]
use core::sync::atomic::Ordering;

use sync::{Spinlock, TaskList as LockClass};
use vfs::fs::{FsContext, FsContextOps, FsParamVerdict, FsParameter, FsValue, ParamResult};
use vfs::{File, SuperBlock, VfsError};

use super::{
    resolve_fd, AutofsFs, AutofsMountOptions, AutofsMountType, AUTOFS_PARAMS,
    AUTOFS_PROTO_VERSION,
};

struct Context {
    pipe: Option<Arc<File>>,
    uid: u32,
    gid: u32,
    pgrp: u32,
    pgrp_set: bool,
    min_proto: u32,
    max_proto: u32,
    mount_type: AutofsMountType,
    strict_expire: bool,
    ignore: bool,
}

impl Context {
    fn new() -> Self {
        let (uid, gid, pgrp) = current_identity();
        Self {
            pipe: None,
            uid,
            gid,
            pgrp,
            pgrp_set: false,
            min_proto: 4,
            max_proto: AUTOFS_PROTO_VERSION,
            mount_type: AutofsMountType::Indirect,
            strict_expire: false,
            ignore: false,
        }
    }

    fn mount_options(&self) -> Result<AutofsMountOptions, VfsError> {
        let pipe = self.pipe.clone().ok_or(VfsError::Einval)?;
        if self.max_proto < 4 || self.min_proto > AUTOFS_PROTO_VERSION {
            return Err(VfsError::Einval);
        }
        Ok(AutofsMountOptions {
            pipe,
            uid: self.uid,
            gid: self.gid,
            pgrp: self.pgrp,
            pgrp_set: self.pgrp_set,
            max_proto: self.max_proto,
            mount_type: self.mount_type,
            strict_expire: self.strict_expire,
            ignore: self.ignore,
        })
    }
}

#[cfg(target_os = "oxide-kernel")]
fn current_identity() -> (u32, u32, u32) {
    match sched::current() {
        Some(task) => (
            task.creds.fsuid.load(Ordering::Acquire),
            task.creds.fsgid.load(Ordering::Acquire),
            task.pgid(),
        ),
        None => (0, 0, 0),
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn current_identity() -> (u32, u32, u32) { (0, 0, 0) }

#[cfg(target_os = "oxide-kernel")]
fn pgrp_exists(pgrp: u32) -> bool { !sched::registry::tasks_in_pgrp(pgrp).is_empty() }

#[cfg(not(target_os = "oxide-kernel"))]
fn pgrp_exists(_pgrp: u32) -> bool { true }

fn state(fc: &mut FsContext) -> &Spinlock<Context, LockClass> {
    if fc.fs_private().downcast_ref::<Spinlock<Context, LockClass>>().is_none() {
        fc.set_fs_private(Arc::new(Spinlock::<Context, LockClass>::new(Context::new())));
    }
    fc.fs_private().downcast_ref::<Spinlock<Context, LockClass>>()
        .expect("autofs fs_context private state")
}

fn uint(param: &FsParameter) -> Result<u32, VfsError> {
    let text = param.as_str().ok_or(VfsError::Einval)?;
    let parsed = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))
        .map_or_else(|| text.parse::<u32>(), |hex| u32::from_str_radix(hex, 16));
    parsed.map_err(|_| VfsError::Einval)
}

fn file(param: &FsParameter) -> Result<Arc<File>, VfsError> {
    let file = match &param.value {
        FsValue::File { file, .. } => Ok(file.clone()),
        FsValue::String(_) => {
            let raw = uint(param)?;
            let fd = i32::try_from(raw).map_err(|_| VfsError::Einval)?;
            resolve_fd(fd)
        }
        _ => Err(VfsError::Einval),
    }?;
    let writable = file.flags().contains(vfs::OpenFlags::O_WRONLY)
        || file.flags().contains(vfs::OpenFlags::O_RDWR);
    if file.inode().file_type() != vfs::FileType::Fifo || !writable {
        return Err(VfsError::Ebadf);
    }
    Ok(file)
}

/// Stateless operations object; all per-mount values live in `fc.fs_private`.
pub struct AutofsContextOps;

impl FsContextOps for AutofsContextOps {
    fn parse_param(&self, fc: &mut FsContext, param: &FsParameter)
        -> Result<ParamResult, VfsError>
    {
        if param.key == "source" { return Ok(ParamResult::Declined); }
        match vfs::fs::admit_fs_param(AUTOFS_PARAMS, param) {
            FsParamVerdict::Unknown => return Ok(ParamResult::Declined),
            FsParamVerdict::WrongValueShape(_) => return fc.invalf("autofs: unexpected parameter value"),
            FsParamVerdict::Accept(_) => {}
        }
        if param.key == "fd" {
            let pipe = file(param)?;
            state(fc).lock().pipe = Some(pipe);
            return Ok(ParamResult::Consumed);
        }
        let mut ctx = state(fc).lock();
        match param.key.as_str() {
            "uid" => ctx.uid = uint(param)?,
            "gid" => ctx.gid = uint(param)?,
            "pgrp" => { ctx.pgrp = uint(param)?; ctx.pgrp_set = true; }
            "minproto" => ctx.min_proto = uint(param)?,
            "maxproto" => ctx.max_proto = uint(param)?,
            "indirect" => ctx.mount_type = AutofsMountType::Indirect,
            "direct" => ctx.mount_type = AutofsMountType::Direct,
            "offset" => ctx.mount_type = AutofsMountType::Offset,
            "strictexpire" => ctx.strict_expire = true,
            "ignore" => ctx.ignore = true,
            _ => return Ok(ParamResult::Declined),
        }
        Ok(ParamResult::Consumed)
    }

    fn get_tree(&self, fc: &mut FsContext) -> Result<Arc<SuperBlock>, VfsError> {
        let options = state(fc).lock().mount_options()?;
        if options.pgrp_set && !pgrp_exists(options.pgrp) { return Err(VfsError::Einval); }
        let fs = AutofsFs::from_context(options);
        vfs::fs::superblock_from_filesystem(
            fc.fs_type().clone(), fs, None, "autofs".into(), fc.sb_flags(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::fs::{FsFlags, FsType, vfs_get_tree, vfs_parse_fs_param};
    use vfs::{FileType, InodeBuilder, OpenFlags, default_file_ops, default_inode_ops, mk_mode};

    fn pinned_file() -> Arc<File> {
        let inode = InodeBuilder::new(9, mk_mode(FileType::Fifo, 0o600),
            default_inode_ops(), default_file_ops()).build();
        let dentry = vfs::dentry::Dentry::new_root(inode.clone());
        File::new(inode, dentry, OpenFlags::O_WRONLY)
    }

    fn regular_file() -> Arc<File> {
        let inode = InodeBuilder::new(10, mk_mode(FileType::Regular, 0o600),
            default_inode_ops(), default_file_ops()).build();
        let dentry = vfs::dentry::Dentry::new_root(inode.clone());
        File::new(inode, dentry, OpenFlags::O_WRONLY)
    }

    fn mount_context() -> FsContext {
        let ty = FsType::with_context_parameters(
            "autofs-test", super::super::AUTOFS_SUPER_MAGIC, FsFlags::empty(),
            Arc::new(AutofsContextOps), AUTOFS_PARAMS,
        );
        FsContext::for_mount(ty, 0)
    }

    #[test]
    fn typed_context_owns_values_and_builds_the_mount() {
        let mut fc = mount_context();
        vfs_parse_fs_param(&mut fc, &FsParameter::fd("fd", 55, pinned_file())).unwrap();
        for (key, value) in [
            ("uid", "1000"), ("gid", "1001"), ("pgrp", "44"),
            ("minproto", "5"), ("maxproto", "5"),
        ] {
            vfs_parse_fs_param(&mut fc, &FsParameter::string(key, value)).unwrap();
        }
        vfs_parse_fs_param(&mut fc, &FsParameter::flag("direct")).unwrap();
        vfs_parse_fs_param(&mut fc, &FsParameter::flag("strictexpire")).unwrap();
        vfs_get_tree(&mut fc).unwrap();
        let root = fc.sb().unwrap().s_root().unwrap().inode().unwrap();
        assert_eq!(root.uid(), Some(1000));
        assert_eq!(root.gid(), Some(1001));
    }

    #[test]
    fn incompatible_daemon_protocol_is_rejected_at_get_tree() {
        let mut fc = mount_context();
        vfs_parse_fs_param(&mut fc, &FsParameter::fd("fd", 55, pinned_file())).unwrap();
        vfs_parse_fs_param(&mut fc, &FsParameter::string("maxproto", "3")).unwrap();
        assert_eq!(vfs_get_tree(&mut fc), Err(VfsError::Einval));
    }

    #[test]
    fn fd_must_name_a_writable_pipe() {
        let mut fc = mount_context();
        assert_eq!(vfs_parse_fs_param(
            &mut fc, &FsParameter::fd("fd", 55, regular_file())), Err(VfsError::Ebadf));
    }
}
