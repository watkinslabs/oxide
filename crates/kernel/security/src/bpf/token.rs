use syscall::errno::Errno;

use super::{BPF_FS_MAGIC, BpfTokenInode, install_fd, make_bpf_token_inode};
use super::attr::Attr;
#[cfg(test)]
use super::uapi;

const TOKEN_FLAGS: usize = 0;
const TOKEN_BPFFS_FD: usize = 4;

/// Create a token only from a live bpffs file description.  The token keeps
/// the source filesystem identity in its inode so later authorization can be
/// extended without inventing a second ownership table.
pub(super) fn create(a: &Attr) -> Result<i64, Errno> {
    let flags = a.u32_at(TOKEN_FLAGS);
    if flags != 0 { return Err(Errno::Einval); }
    let fd = a.u32_at(TOKEN_BPFFS_FD) as i32;
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let file = fdt.get(fd).map_err(|_| Errno::Ebadf)?;
    if file.inode().statfs_magic() != BPF_FS_MAGIC { return Err(Errno::Enodev); }
    let inode = make_bpf_token_inode(BpfTokenInode { source_magic: BPF_FS_MAGIC, flags });
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
