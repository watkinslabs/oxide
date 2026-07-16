//! Dynamic `/sys/kernel` leaves owned by sysfs.

use alloc::sync::Arc;

use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Ino, Inode, InodeBuilder, KResult, VfsError};

use crate::{read_window, register, RO_PERM};

const INO_UEVENT_SEQNUM: Ino = 0x5107_0001;

struct UeventSeqnumOps;
impl FileOps for UeventSeqnumOps {
    fn read(&self, _inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = alloc::format!("{}\n", netlink::uevent_seqnum()).into_bytes();
        Ok(read_window(&body, off, buf))
    }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

fn make_uevent_seqnum_inode() -> vfs::InodeRef {
    InodeBuilder::new(INO_UEVENT_SEQNUM, mk_mode(FileType::Regular, RO_PERM),
        default_inode_ops(), Arc::new(UeventSeqnumOps))
        .build()
}

/// Register dynamic `/sys/kernel` sysfs leaves. # C: O(1)
pub fn init() {
    register("/sys/kernel/uevent_seqnum", make_uevent_seqnum_inode());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uevent_seqnum_reads_live_netlink_counter() {
        let before = netlink::uevent_seqnum();
        netlink::emit_uevent("change", "/devices/virtual/test/seq0", "test");
        let expected = before.wrapping_add(1);

        let inode = make_uevent_seqnum_inode();
        let mut buf = [0u8; 32];
        let n = inode.read(0, &mut buf).expect("read uevent_seqnum");
        let observed = core::str::from_utf8(&buf[..n]).expect("utf8").trim()
            .parse::<u64>().expect("decimal uevent sequence");
        // Linux's global sequence is monotonic and shared with concurrent
        // emitters; unrelated tests may advance it after our emission.
        assert!(observed >= expected as u64, "uevent_seqnum must not move backwards");
    }
}
