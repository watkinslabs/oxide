use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;

use vfs::{DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, mk_mode};

const PROC_ROOT_DIR_MODE: u16 = 0o555;

use super::pid_dir::{make_proc_pid_dir, pid_to_kernel_tid};

pub struct ProcRootInode {
    children: BTreeMap<String, InodeRef>,
}

fn proc_root_lookup(d: &ProcRootInode, name: &str) -> KResult<InodeRef> {
    if let Some(i) = d.children.get(name) {
        return Ok(i.clone());
    }
    if name == "self" {
        return Ok(make_proc_pid_dir(0, true, true));
    }
    if let Some(i) = crate::reg::proc_reg().lookup_path(name) {
        return Ok(i);
    }
    let vpid: u32 = name.parse().map_err(|_| VfsError::Enoent)?;
    let tid = pid_to_kernel_tid(vpid).ok_or(VfsError::Enoent)?;
    Ok(make_proc_pid_dir(tid, false, true))
}

struct ProcRootOps;

impl InodeOps for ProcRootOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<ProcRootInode>().ok_or(VfsError::Einval)?;
        proc_root_lookup(d, name)
    }
}

impl FileOps for ProcRootOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<ProcRootInode>().ok_or(VfsError::Einval)?;
        let mut idx = ctx.pos as usize;
        let nstat = d.children.len();
        while idx < nstat {
            let (name, child) = d.children.iter().nth(idx).unwrap();
            let next = idx as u64 + 1;
            if !ctx.emit(name.as_str(), child.ino(), child.file_type(), next) {
                return Ok(());
            }
            idx += 1;
        }
        let vpids = sched::live::registry::live_vpids();
        let total = nstat + 1 + vpids.len();
        while idx < total {
            let dyn_idx = idx - nstat;
            let next = idx as u64 + 1;
            let mut buf = [0u8; 11];
            let s: &str = if dyn_idx == 0 {
                "self"
            } else {
                let mut t = vpids[dyn_idx - 1];
                let mut n = 0;
                if t == 0 {
                    buf[0] = b'0';
                    n = 1;
                } else {
                    while t > 0 {
                        buf[n] = b'0' + (t % 10) as u8;
                        t /= 10;
                        n += 1;
                    }
                }
                buf[..n].reverse();
                crate::util::decimal_str(&buf, n)
            };
            let ino = inode.lookup(s).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(s, ino, FileType::Directory, next) {
                return Ok(());
            }
            idx += 1;
        }
        Ok(())
    }
}

pub fn make_proc_root(children: BTreeMap<String, InodeRef>) -> InodeRef {
    InodeBuilder::new(
        crate::ids::PROC_ROOT,
        mk_mode(FileType::Directory, PROC_ROOT_DIR_MODE),
        Arc::new(ProcRootOps),
        Arc::new(ProcRootOps),
    )
    .private(Arc::new(ProcRootInode { children }))
    .build()
}
