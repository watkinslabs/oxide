use syscall::errno::Errno;

use super::{BPF_FS_MAGIC, BpfDelegation, BpfTokenInode, install_fd, make_bpf_token_inode};
use super::attr::Attr;
#[cfg(test)]
use super::uapi;

const TOKEN_FLAGS: usize = 0;
const TOKEN_BPFFS_FD: usize = 4;

/// Resolve the token object named by a command's token fd. # C: O(1)
pub(super) fn from_fd(fd: u32) -> Result<BpfTokenInode, Errno> {
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task owns the syscall's descriptor-table read; the
    // table is cloned before the returned inode is used.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let file = fdt.get(fd as i32).map_err(|_| Errno::Ebadf)?;
    file.inode().private::<BpfTokenInode>().copied().ok_or(Errno::Einval)
}

/// Create a token only from a live bpffs file description.  The token keeps
/// the source filesystem identity in its inode so later authorization can be
/// extended without inventing a second ownership table.
pub(super) fn create(a: &Attr) -> Result<i64, Errno> {
    let flags = a.u32_at(TOKEN_FLAGS);
    if flags != 0 { return Err(Errno::Einval); }
    let fd = a.u32_at(TOKEN_BPFFS_FD) as i32;
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: `cur` is the running task on this CPU, and the only writers of its
    // `fd_table` slot (execve, unshare, close_range, exit) run on the task
    // itself — it cannot be inside one of those while it executes this bpf
    // syscall, so no concurrent `replace_fd_table` can race the borrow.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let file = fdt.get(fd).map_err(|_| Errno::Ebadf)?;
    if file.inode().statfs_magic() != BPF_FS_MAGIC { return Err(Errno::Enodev); }
    // Linux accepts only the bpffs superblock root as the token's source.
    // Checking the inode's owning pseudo-tree, rather than its inode number,
    // keeps a child entry from being mistaken for the root and avoids a
    // second path registry beside kernfs's canonical tree.
    let Some(root) = file.inode().private::<kernfs::PseudoDir>() else {
        return Err(Errno::Einval);
    };
    if !root.is_root() { return Err(Errno::Einval); }
    let delegation = root.fs_private::<BpfDelegation>().unwrap_or_default();
    let inode = make_bpf_token_inode(BpfTokenInode {
        source_magic: BPF_FS_MAGIC,
        flags,
        allowed_cmds: delegation.allowed_cmds,
        allowed_maps: delegation.allowed_maps,
        allowed_progs: delegation.allowed_progs,
        allowed_attachs: delegation.allowed_attachs,
    });
    install_fd(inode, "bpf-token")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_uapi_offsets_are_fixed() {
        assert_eq!(TOKEN_FLAGS, 0);
        assert_eq!(TOKEN_BPFFS_FD, 4);
        assert_eq!(uapi::cmd::TOKEN_CREATE, 36);
    }
}
