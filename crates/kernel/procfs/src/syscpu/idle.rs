// `/sys/devices/system/cpu/cpu<N>/cpuidle/` and its `state<M>/` groups.
//
// The attribute contract belongs to the `cpuidle` crate; this module owns the
// inodes. A machine with no idle driver publishes no directory, because the
// state indexes every attribute is keyed by would have nothing behind them.
#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use cpuidle::attrs;
use vfs::{mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef,
          KResult, VfsError};

use super::SYSCPU_DIR_MODE;

/// Directory name of the idle group.
pub const DIR: &str = "cpuidle";

/// Whether an idle driver has published a state table. # C: O(1)
pub fn present() -> bool { cpuidle::driver().is_some() }

/// `i_private` for one attribute file. A `None` state means the attribute
/// belongs to the directory itself rather than to one state.
struct AttrData { cpu: usize, state: Option<usize>, name: String }

/// `i_private` for one directory.
struct DirData { cpu: usize, state: Option<usize> }

struct AttrOps;

impl InodeOps for AttrOps {}

impl FileOps for AttrOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }

    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = inode.private::<AttrData>().ok_or(VfsError::Einval)?;
        let driver = cpuidle::driver().ok_or(VfsError::Enoent)?;
        let body = match data.state {
            Some(state) => attrs::show_state(&driver, data.cpu, state, &data.name)?,
            None => attrs::show_dir(&driver, &data.name)?,
        };
        Ok(crate::dyn_file::read_at(&body, off, buf))
    }

    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let data = inode.private::<AttrData>().ok_or(VfsError::Einval)?;
        let driver = cpuidle::driver().ok_or(VfsError::Enoent)?;
        match data.state {
            Some(state) => attrs::store_state(&driver, data.cpu, state, &data.name, buf),
            None => attrs::store_dir(&driver, &data.name, buf),
        }
    }
}

fn make_attr(cpu: usize, state: Option<usize>, name: &str, mode: u16) -> InodeRef {
    InodeBuilder::new(crate::ids::CPU_IDLE_ATTR + cpu as Ino,
                      mk_mode(FileType::Regular, mode), Arc::new(AttrOps), Arc::new(AttrOps))
        .private(Arc::new(AttrData { cpu, state, name: String::from(name) }))
        .build()
}

/// The attribute table of one directory. # C: O(1)
fn table(state: Option<usize>) -> &'static [(&'static str, u16)] {
    if state.is_some() { attrs::STATE_ATTRS } else { attrs::DIR_ATTRS }
}

struct DirOps;

impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<DirData>().ok_or(VfsError::Einval)?;
        if !present() { return Err(VfsError::Enoent); }
        if data.state.is_none() {
            if let Some(state) = attrs::parse_state_dir(name) {
                if state >= attrs::state_count() { return Err(VfsError::Enoent); }
                return Ok(make_state_dir(data.cpu, state));
            }
        }
        let (attr, mode) = table(data.state).iter().find(|(attr, _)| *attr == name)
            .ok_or(VfsError::Enoent)?;
        Ok(make_attr(data.cpu, data.state, attr, *mode))
    }
}

impl FileOps for DirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let data = inode.private::<DirData>().ok_or(VfsError::Einval)?;
        if !present() { return Err(VfsError::Enoent); }
        let mut names: Vec<(String, FileType)> = table(data.state).iter()
            .map(|(attr, _)| (String::from(*attr), FileType::Regular)).collect();
        if data.state.is_none() {
            for state in 0..attrs::state_count() {
                names.push((attrs::state_dir(state), FileType::Directory));
            }
        }
        crate::readdir::emit_resolved(names, |n| inode.lookup(n).ok().map(|i| i.ino()), ctx)
    }
}

fn make_state_dir(cpu: usize, state: usize) -> InodeRef {
    InodeBuilder::new(crate::ids::CPU_IDLE_STATE_DIR + (cpu * cpuidle::limits::MAX_STATES
                          + state) as Ino,
                      mk_mode(FileType::Directory, SYSCPU_DIR_MODE),
                      Arc::new(DirOps), Arc::new(DirOps))
        .private(Arc::new(DirData { cpu, state: Some(state) }))
        .build()
}

/// `/sys/devices/system/cpu/cpu<N>/cpuidle` directory inode. # C: O(1)
pub fn make_idle_dir(cpu: usize) -> InodeRef {
    InodeBuilder::new(crate::ids::CPU_IDLE_DIR + cpu as Ino,
                      mk_mode(FileType::Directory, SYSCPU_DIR_MODE),
                      Arc::new(DirOps), Arc::new(DirOps))
        .private(Arc::new(DirData { cpu, state: None }))
        .build()
}
