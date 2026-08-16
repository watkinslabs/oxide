// `/sys/devices/system/cpu/cpu<N>/cpufreq/` and its `stats/` group.
//
// The attribute contract belongs to the `cpufreq` crate; this module owns the
// inodes that publish it and the resolution from a CPU number to the policy
// that governs it. A CPU with no policy has no directory at all rather than an
// empty one: a governor daemon reads an empty directory as a broken device.
#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use cpufreq::attrs;
use cpufreq::policy::Policy;
use vfs::{mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef,
          KResult, VfsError};

use super::SYSCPU_DIR_MODE;

/// Directory name of the scaling group.
pub const DIR: &str = "cpufreq";

/// Which group an attribute belongs to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Group { Policy, Stats }

/// `i_private` for one attribute file.
struct AttrData { cpu: usize, group: Group, name: String }

/// `i_private` for one of the two directories.
struct DirData { cpu: usize, group: Group }

/// The policy governing `cpu`, or nothing. # C: O(N_policies)
fn policy(cpu: usize) -> Option<Arc<Policy>> { cpufreq::policy_for(cpu) }

/// Whether `cpu` has a scaling policy at all. # C: O(N_policies)
pub fn present(cpu: usize) -> bool { policy(cpu).is_some() }

fn now_ns() -> u64 { timekeeper::monotonic_ns() }

struct AttrOps;

impl InodeOps for AttrOps {}

impl FileOps for AttrOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }

    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = inode.private::<AttrData>().ok_or(VfsError::Einval)?;
        let policy = policy(data.cpu).ok_or(VfsError::Enoent)?;
        let body = match data.group {
            Group::Policy => attrs::show(&policy, &data.name)?,
            Group::Stats => attrs::show_stats(&policy, &data.name, now_ns())?,
        };
        Ok(crate::dyn_file::read_at(&body, off, buf))
    }

    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let data = inode.private::<AttrData>().ok_or(VfsError::Einval)?;
        let policy = policy(data.cpu).ok_or(VfsError::Enoent)?;
        match data.group {
            Group::Policy => attrs::store(&policy, &data.name, buf, now_ns()),
            Group::Stats => attrs::store_stats(&policy, &data.name, buf, now_ns()),
        }
    }
}

/// One attribute file. # C: O(1)
fn make_attr(cpu: usize, group: Group, name: &str, mode: u16) -> InodeRef {
    InodeBuilder::new(crate::ids::CPU_SCALING_ATTR + cpu as Ino,
                      mk_mode(FileType::Regular, mode), Arc::new(AttrOps), Arc::new(AttrOps))
        .private(Arc::new(AttrData { cpu, group, name: String::from(name) }))
        .build()
}

/// The attribute table of one group. # C: O(1)
fn table(group: Group) -> &'static [(&'static str, u16)] {
    match group { Group::Policy => attrs::ATTRS, Group::Stats => attrs::STATS_ATTRS }
}

struct DirOps;

impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<DirData>().ok_or(VfsError::Einval)?;
        if !present(data.cpu) { return Err(VfsError::Enoent); }
        if data.group == Group::Policy && name == attrs::STATS_DIR {
            return Ok(make_dir(data.cpu, Group::Stats, crate::ids::CPU_SCALING_STATS_DIR));
        }
        let (attr, mode) = table(data.group).iter().find(|(attr, _)| *attr == name)
            .ok_or(VfsError::Enoent)?;
        Ok(make_attr(data.cpu, data.group, attr, *mode))
    }
}

impl FileOps for DirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let data = inode.private::<DirData>().ok_or(VfsError::Einval)?;
        if !present(data.cpu) { return Err(VfsError::Enoent); }
        let mut names: Vec<(String, FileType)> = table(data.group).iter()
            .map(|(attr, _)| (String::from(*attr), FileType::Regular)).collect();
        if data.group == Group::Policy {
            names.push((String::from(attrs::STATS_DIR), FileType::Directory));
        }
        crate::readdir::emit_resolved(names, |n| inode.lookup(n).ok().map(|i| i.ino()), ctx)
    }
}

fn make_dir(cpu: usize, group: Group, ino: Ino) -> InodeRef {
    InodeBuilder::new(ino + cpu as Ino, mk_mode(FileType::Directory, SYSCPU_DIR_MODE),
                      Arc::new(DirOps), Arc::new(DirOps))
        .private(Arc::new(DirData { cpu, group }))
        .build()
}

/// `/sys/devices/system/cpu/cpu<N>/cpufreq` directory inode. # C: O(1)
pub fn make_scaling_dir(cpu: usize) -> InodeRef {
    make_dir(cpu, Group::Policy, crate::ids::CPU_SCALING_DIR)
}
