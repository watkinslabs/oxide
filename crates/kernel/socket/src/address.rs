use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::{Error, KResult, SendContext};

pub(crate) enum InetAddress {
    None,
    V4 { ip: net::Ipv4Addr, port: u16 },
    V6 { ip: net::Ipv6Addr, port: u16, scope_id: u32 },
}

fn family(name: &[u8]) -> KResult<u16> {
    if name.len() < 2 { return Err(Error::Einval); }
    Ok(u16::from_ne_bytes(name[..2].try_into().unwrap()))
}

fn unix_path(name: &[u8]) -> KResult<Vec<u8>> {
    if name.len() <= 2 { return Err(Error::Einval); }
    let raw = &name[2..core::cmp::min(name.len(), 110)];
    if raw[0] == 0 { return Ok(raw.to_vec()); }
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    Ok(raw[..end].to_vec())
}

fn cred(task: &sched::Task) -> vfs::Cred {
    let effective = task.creds.cap_effective.load(Ordering::Acquire);
    let has = |cap: u32| effective & (1u64 << cap) != 0;
    let count = (task.creds.ngroups.load(Ordering::Acquire) as usize).min(vfs::CRED_NGROUPS);
    let mut groups = [0u32; vfs::CRED_NGROUPS];
    // SAFETY: running task's credential groups are single-mutator state per 13§5.
    unsafe { groups[..count].copy_from_slice(&(&*task.creds.groups.get())[..count]); }
    vfs::Cred {
        uid: task.creds.fsuid.load(Ordering::Acquire), gid: task.creds.fsgid.load(Ordering::Acquire),
        cap_dac_override: has(sched::cap::DAC_OVERRIDE),
        cap_dac_read_search: has(sched::cap::DAC_READ_SEARCH),
        cap_fowner: has(sched::cap::FOWNER), cap_chown: has(sched::cap::CHOWN),
        cap_fsetid: has(sched::cap::FSETID), ngroups: count as u32, groups,
    }
}

fn resolve_unix(ctx: &SendContext<'_>, path: Vec<u8>) -> KResult<net::UnixAddr> {
    if net::unix_path_is_abstract(&path) { return Ok(net::UnixAddr::from_sockaddr_path(path)); }
    let task = ctx.task();
    // SAFETY: running task owns root VFS path state under 13§5 single-mutator rules.
    let root = unsafe { (*task.root_vfs.get()).clone() }.or_else(|| {
        let ns = task.mount_namespace_id()?;
        let mnt_id = vfs::mount::root_mount_id(ns)?;
        let dentry = vfs::mount::root_dentry_for_mount_id(mnt_id)?;
        let inode = dentry.inode()?;
        Some(vfs::VfsPath { mnt_id, dentry, inode, last_component: None })
    }).or_else(|| {
        let dentry = vfs::namei::root_dentry()?; let inode = dentry.inode()?;
        Some(vfs::VfsPath { mnt_id: vfs::mount::MNT_ID_NONE, dentry, inode, last_component: None })
    }).ok_or(Error::Enoent)?;
    // SAFETY: running task owns cwd VFS path state under 13§5 single-mutator rules.
    let start = unsafe { (*task.cwd_vfs.get()).clone() }.unwrap_or_else(|| root.clone());
    let decoded = vfs::path_from_bytes(&path);
    let found = vfs::path_lookup_at_root_cred(start.dentry, start.mnt_id, root.dentry, root.mnt_id,
        &decoded, vfs::LookupFlags::default(), cred(task)).map_err(Error::from)?;
    if found.inode.file_type() != vfs::FileType::Socket { return Err(Error::Econnrefused); }
    Ok(net::UnixAddr::from_inode_bytes(path, &found.inode))
}

/// Decode one kernel-owned INET sockaddr without protocol side effects. # C: O(1)
pub(crate) fn inet(name: Option<&[u8]>) -> KResult<InetAddress> {
    let Some(name) = name else { return Ok(InetAddress::None); };
    match family(name)? {
        2 => {
            if name.len() < 16 { return Err(Error::Einval); }
            Ok(InetAddress::V4 { ip: net::Ipv4Addr::new(name[4], name[5], name[6], name[7]),
                port: u16::from_be_bytes(name[2..4].try_into().unwrap()) })
        }
        10 => {
            if name.len() < 28 { return Err(Error::Einval); }
            let mut ip = [0u8; 16]; ip.copy_from_slice(&name[8..24]);
            Ok(InetAddress::V6 { ip: net::Ipv6Addr(ip),
                port: u16::from_be_bytes(name[2..4].try_into().unwrap()),
                scope_id: u32::from_ne_bytes(name[24..28].try_into().unwrap()) })
        }
        _ => Err(Error::Eafnosupport),
    }
}

#[cfg(target_os = "oxide-kernel")]
impl InetAddress {
    /// Convert one validated INET address into protocol routing form. # C: O(1)
    pub(crate) fn remote(self) -> Option<net::sock::RemoteAddr> {
        match self {
            Self::None => None,
            Self::V4 { ip, port } => Some(net::sock::RemoteAddr::Inet { ip, port }),
            Self::V6 { ip, port, scope_id } =>
                Some(net::sock::RemoteAddr::Inet6 { ip, port, scope_id }),
        }
    }
}

/// Resolve one validated AF_UNIX destination in the sender context. # C: path lookup
pub(crate) fn unix(ctx: &SendContext<'_>, name: &[u8]) -> KResult<net::UnixAddr> {
    if family(name)? != 1 { return Err(Error::Eafnosupport); }
    resolve_unix(ctx, unix_path(name)?)
}
