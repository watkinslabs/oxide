// `mknod(2)` / `mknodat(2)` decision logic — the type-validation gate
// and the type-dependent half of node creation. Ungated so the whole matrix is
// hosted-testable; the syscall shim keeps only path resolution, the dcache
// update, and the backend call.

use vfs::Devt;

/// `S_IFMT` and the node types `mknod(2)` names.
pub const S_IFMT:   u16 = 0o170000;
pub const S_IFSOCK: u16 = 0o140000;
pub const S_IFREG:  u16 = 0o100000;
pub const S_IFBLK:  u16 = 0o060000;
pub const S_IFDIR:  u16 = 0o040000;
pub const S_IFCHR:  u16 = 0o020000;
pub const S_IFIFO:  u16 = 0o010000;

/// `WHITEOUT_DEV` — the character device number
/// `0:0` an overlay filesystem plants to hide a lower-layer name. It is not a
/// device: node creation exempts it from BOTH the CAP_MKNOD requirement and
/// the device-cgroup policy, which is what lets an unprivileged overlay mount
/// record a deletion.
pub const WHITEOUT_DEV: u32 = 0;

/// Node type a `mode` word names. `None` is the caller's error: `S_IFDIR` is
/// `EPERM` (`mkdir(2)` is the only way to make a directory) and every other
/// bit pattern is `EINVAL`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NodeType { Reg, Chr, Blk, Fifo, Sock }

/// Outcome of [`may_mknod`] — the type, or the errno Linux reports for it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MayMknod { Ok(NodeType), Eperm, Einval }

/// `may_mknod` — validate the type half of `mode` BEFORE
/// any path resolution, so a bad type reports its errno regardless of whether
/// the path exists or the parent is writable. A zero type translates to
/// `S_IFREG` ("zero mode translates to S_IFREG"). # C: O(1)
pub fn may_mknod(mode: u16) -> MayMknod {
    match mode & S_IFMT {
        0 | S_IFREG => MayMknod::Ok(NodeType::Reg),
        S_IFCHR     => MayMknod::Ok(NodeType::Chr),
        S_IFBLK     => MayMknod::Ok(NodeType::Blk),
        S_IFIFO     => MayMknod::Ok(NodeType::Fifo),
        S_IFSOCK    => MayMknod::Ok(NodeType::Sock),
        S_IFDIR     => MayMknod::Eperm,
        _           => MayMknod::Einval,
    }
}

impl NodeType {
    /// `S_IFMT` bits this type stores in `i_mode`. # C: O(1)
    pub fn ifmt(self) -> u16 {
        match self {
            NodeType::Reg => S_IFREG, NodeType::Chr => S_IFCHR, NodeType::Blk => S_IFBLK,
            NodeType::Fifo => S_IFIFO, NodeType::Sock => S_IFSOCK,
        }
    }

    /// `dev` the new inode records. Only a device node carries one — Linux
    /// passes a hard `0` for FIFO and socket nodes (`vfs_mknod(..., 0)`)
    /// rather than the caller's argument, so a stray `dev` cannot become an
    /// `st_rdev` on a non-device. # C: O(1)
    pub fn node_dev(self, dev: u32) -> u32 {
        match self { NodeType::Chr | NodeType::Blk => dev, _ => 0 }
    }

    /// Does creating this node require CAP_MKNOD? Only character and block
    /// devices do — and NOT the `0:0` character whiteout, which `vfs_mknod`
    /// exempts by name. Requiring the capability for a whiteout made every
    /// unprivileged overlay deletion fail with EPERM. # C: O(1)
    pub fn needs_cap_mknod(self, dev: u32) -> bool {
        match self {
            NodeType::Chr => dev != WHITEOUT_DEV,
            NodeType::Blk => true,
            _             => false,
        }
    }

    /// Does creating this node consult device-cgroup policy? Same set as
    /// [`needs_cap_mknod`]: real device nodes only. # C: O(1)
    pub fn needs_devcg(self, dev: u32) -> bool { self.needs_cap_mknod(dev) }

    /// `(major, minor)` the device-cgroup check names. # C: O(1)
    pub fn dev_major_minor(dev: u32) -> (u32, u32) {
        let d = Devt::from_raw(dev);
        (d.major(), d.minor())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `may_mknod`'s full type matrix, including the two error types. Zero maps
    // to a regular file; `S_IFDIR` is EPERM (never EINVAL) so `mknod(dir)`
    // reports the same thing Linux does; any other value is EINVAL.
    #[test]
    fn type_matrix() {
        assert_eq!(may_mknod(0o0644), MayMknod::Ok(NodeType::Reg));
        assert_eq!(may_mknod(S_IFREG | 0o0644), MayMknod::Ok(NodeType::Reg));
        assert_eq!(may_mknod(S_IFCHR | 0o0600), MayMknod::Ok(NodeType::Chr));
        assert_eq!(may_mknod(S_IFBLK | 0o0600), MayMknod::Ok(NodeType::Blk));
        assert_eq!(may_mknod(S_IFIFO | 0o0666), MayMknod::Ok(NodeType::Fifo));
        assert_eq!(may_mknod(S_IFSOCK | 0o0666), MayMknod::Ok(NodeType::Sock));
        assert_eq!(may_mknod(S_IFDIR | 0o0755), MayMknod::Eperm);
        // S_IFLNK: symlink(2) territory, and the only remaining S_IFMT value.
        assert_eq!(may_mknod(0o120000), MayMknod::Einval);
    }

    // CAP_MKNOD is required for real device nodes only. The `0:0` character
    // whiteout is exempt (Linux `is_whiteout` in `vfs_mknod`) — the rule an
    // unprivileged overlay mount depends on. A BLOCK 0:0 is NOT a whiteout.
    #[test]
    fn cap_mknod_scope() {
        assert!(NodeType::Chr.needs_cap_mknod(0x0103));
        assert!(NodeType::Blk.needs_cap_mknod(0x0800));
        assert!(!NodeType::Chr.needs_cap_mknod(WHITEOUT_DEV));
        assert!(NodeType::Blk.needs_cap_mknod(WHITEOUT_DEV), "block 0:0 is not a whiteout");
        for t in [NodeType::Reg, NodeType::Fifo, NodeType::Sock] {
            assert!(!t.needs_cap_mknod(0x0103), "{t:?} is unprivileged");
        }
    }

    // A FIFO or socket records rdev 0 whatever the caller passed; a device
    // node records the argument verbatim (it is already the user wire form
    // `st_rdev` reports).
    #[test]
    fn node_dev_zeroed_for_non_devices() {
        assert_eq!(NodeType::Chr.node_dev(0x0103), 0x0103);
        assert_eq!(NodeType::Blk.node_dev(0x0800), 0x0800);
        assert_eq!(NodeType::Fifo.node_dev(0x0103), 0);
        assert_eq!(NodeType::Sock.node_dev(0x0103), 0);
        assert_eq!(NodeType::Reg.node_dev(0x0103), 0);
    }

    // The `dev` argument is the glibc wire encoding, so `/dev/null`'s 1:3
    // arrives as 0x103 and a high minor splits across the two minor fields.
    #[test]
    fn dev_decode_matches_wire_encoding() {
        assert_eq!(NodeType::dev_major_minor(0x0103), (1, 3));
        // major 8, minor 256: minor low byte 0, high bits in [20..32).
        assert_eq!(NodeType::dev_major_minor((8 << 8) | (0x100 << 12)), (8, 256));
    }
}
