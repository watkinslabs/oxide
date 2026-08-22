// Translation between a 9P server's answers and this kernel's inode fields.
// Every decision here is pure, so it is checked without a server or a device.

extern crate alloc;

use ninep::codec::{Qid, StatDotl};
use ninep::opts::{self, Access};
use ninep::uapi::{dotl, qid as qidbits, setattr as p9setattr, stats};
use vfs::setattr as vattr;
use vfs::{FileType, Iattr, Timespec64};

use super::attr::*;
use super::inode::admit_rename_flags;
use super::mount::attach_uid;

fn policy() -> AttrPolicy { AttrPolicy { nodev: false, dfltuid: 65534, dfltgid: 65534 } }

#[test]
fn an_inode_number_comes_from_the_qid_path_not_the_reported_ino() {
    // `st_ino` need not be unique across the trees a server exports; the qid
    // path is what the protocol guarantees, so aliasing two objects onto one
    // dcache entry is only avoided by using it.
    let q = Qid { ty: qidbits::QTFILE, version: 1, path: 0xDEAD_BEEF_CAFE };
    assert_eq!(qid_to_ino(&q), 0xDEAD_BEEF_CAFE);
}

#[test]
fn the_qid_type_names_the_file_class_before_any_attribute_round_trip() {
    assert_eq!(qid_file_type(&Qid { ty: qidbits::QTDIR, ..Default::default() }), FileType::Directory);
    assert_eq!(qid_file_type(&Qid { ty: qidbits::QTSYMLINK, ..Default::default() }), FileType::Symlink);
    assert_eq!(qid_file_type(&Qid { ty: qidbits::QTFILE, ..Default::default() }), FileType::Regular);
}

#[test]
fn a_dotl_mode_word_names_every_posix_class() {
    assert_eq!(mode_file_type(0o040755), FileType::Directory);
    assert_eq!(mode_file_type(0o100644), FileType::Regular);
    assert_eq!(mode_file_type(0o120777), FileType::Symlink);
    assert_eq!(mode_file_type(0o020666), FileType::CharDev);
    assert_eq!(mode_file_type(0o060660), FileType::BlockDev);
    assert_eq!(mode_file_type(0o010644), FileType::Fifo);
    assert_eq!(mode_file_type(0o140666), FileType::Socket);
}

#[test]
fn nodevmap_refuses_the_device_classes_and_leaves_the_rest_alone() {
    // A server on the far side of a VM boundary must not be able to hand a
    // guest a character-device node when the mount said not to.
    for m in [0o020666u32, 0o060660, 0o010644, 0o140666] {
        assert_eq!(mode_file_type(apply_nodev(m, true)), FileType::Regular, "{m:o}");
        assert_eq!(apply_nodev(m, true) & 0o7777, m & 0o7777, "{m:o} kept its permissions");
    }
    for m in [0o100644u32, 0o040755, 0o120777] {
        assert_eq!(apply_nodev(m, true), m, "{m:o}");
    }
    assert_eq!(apply_nodev(0o020666, false), 0o020666);
}

#[test]
fn an_out_of_range_nanosecond_is_clamped_rather_than_hiding_the_file() {
    // A server with a clock bug has a readable file, not an unreadable one.
    let t = attr_time(100, 5_000_000_000);
    assert_eq!(t.sec, 100);
    assert_eq!(t.nsec, 999_999_999);
    assert_eq!(attr_time(7, 8), Timespec64 { sec: 7, nsec: 8 });
}

#[test]
fn an_unpopulated_attribute_field_takes_the_mount_default_not_zero() {
    // A zero mode is a file nobody can open; a zero uid attributes the object
    // to root. Neither is what "the server did not say" means.
    let q = Qid { ty: qidbits::QTFILE, version: 1, path: 5 };
    let st = StatDotl { valid: 0, ..Default::default() };
    let f = facts_from_stat(&q, &st, policy());
    assert_eq!(f.uid, 65534);
    assert_eq!(f.gid, 65534);
    assert_ne!(f.mode & 0o7777, 0);
    assert_eq!(mode_file_type(f.mode), FileType::Regular);
    assert_eq!(f.nlink, 1);

    let qd = Qid { ty: qidbits::QTDIR, version: 1, path: 6 };
    let fd = facts_from_stat(&qd, &st, policy());
    assert_eq!(mode_file_type(fd.mode), FileType::Directory);
}

#[test]
fn a_populated_attribute_field_is_used_verbatim() {
    let q = Qid { ty: qidbits::QTFILE, version: 1, path: 9 };
    let st = StatDotl {
        valid: stats::ALL, qid: q, mode: 0o100600, uid: 1000, gid: 1001,
        nlink: 4, rdev: 0, size: 4321, blksize: 4096, blocks: 9,
        atime_sec: 1, mtime_sec: 2, ctime_sec: 3, ..Default::default()
    };
    let f = facts_from_stat(&q, &st, policy());
    assert_eq!((f.ino, f.mode, f.uid, f.gid, f.nlink, f.size, f.blocks), (9, 0o100600, 1000, 1001, 4, 4321, 9));
    assert_eq!(f.atime.sec, 1);
    assert_eq!(f.mtime.sec, 2);
    assert_eq!(f.ctime.sec, 3);
}

#[test]
fn setattr_only_selects_the_fields_the_caller_touched() {
    // A bit set for a field the caller did not change truncates the file or
    // resets its mode; a bit missing for one they did change silently drops it.
    let ia = Iattr { valid: vattr::ATTR_SIZE, size: 1234, ..Default::default() };
    let p = iattr_to_p9(&ia);
    assert_eq!(p.valid, p9setattr::SIZE);
    assert_eq!(p.size, 1234);
    assert_eq!(p.valid & p9setattr::MODE, 0);
    assert_eq!(p.valid & p9setattr::UID, 0);
}

#[test]
fn every_attribute_bit_has_a_protocol_counterpart() {
    let pairs = [
        (vattr::ATTR_MODE, p9setattr::MODE), (vattr::ATTR_UID, p9setattr::UID),
        (vattr::ATTR_GID, p9setattr::GID), (vattr::ATTR_SIZE, p9setattr::SIZE),
        (vattr::ATTR_ATIME, p9setattr::ATIME), (vattr::ATTR_MTIME, p9setattr::MTIME),
        (vattr::ATTR_CTIME, p9setattr::CTIME),
        (vattr::ATTR_ATIME_SET, p9setattr::ATIME_SET),
        (vattr::ATTR_MTIME_SET, p9setattr::MTIME_SET),
    ];
    for (from, to) in pairs {
        let ia = Iattr { valid: from, ..Default::default() };
        assert_eq!(iattr_to_p9(&ia).valid, to, "attr bit {from:#x}");
    }
    // A change carrying nothing this protocol expresses selects nothing, so no
    // message is sent rather than one that would clear every field.
    let ia = Iattr { valid: vattr::ATTR_FORCE, ..Default::default() };
    assert_eq!(iattr_to_p9(&ia).valid, 0);
}

#[test]
fn open_flags_are_rebuilt_from_named_protocol_constants() {
    assert_eq!(open_flags_to_dotl(0), dotl::RDONLY);
    assert_eq!(open_flags_to_dotl(1), dotl::WRONLY);
    assert_eq!(open_flags_to_dotl(2), dotl::RDWR);
    assert_eq!(open_flags_to_dotl(0o200000 | 0), dotl::RDONLY | dotl::DIRECTORY);
    let all = open_flags_to_dotl(1 | 0o100 | 0o1000 | 0o2000 | 0o2000000);
    assert_eq!(all & dotl::ACCESS_MASK, dotl::WRONLY);
    for bit in [dotl::CREATE, dotl::TRUNC, dotl::APPEND, dotl::CLOEXEC] {
        assert!(all & bit != 0, "missing {bit:o}");
    }
    // The access mode is a FIELD, not a set of bits: three means "no access",
    // and treating it as a mask would turn it into read plus write.
    assert_eq!(open_flags_to_dotl(3) & dotl::ACCESS_MASK, dotl::NOACCESS);
}

#[test]
fn the_lookup_mask_asks_for_what_a_stat_needs() {
    assert_eq!(LOOKUP_MASK & stats::MODE, stats::MODE);
    assert_eq!(LOOKUP_MASK & stats::SIZE, stats::SIZE);
    assert_eq!(LOOKUP_MASK & stats::UID, stats::UID);
    assert_eq!(LOOKUP_MASK & stats::GEN, stats::GEN);
}

#[test]
fn the_attach_identity_follows_the_access_mode() {
    let base = opts::parse("tag", "").unwrap();
    // Per-user modes attach as the caller, since the server checks against it.
    assert_eq!(attach_uid(&base, 1000), 1000);
    let user = opts::parse("tag", "access=user").unwrap();
    assert_eq!(attach_uid(&user, 1000), 1000);
    // One shared handle for everybody attaches as the mount's own identity.
    let any = opts::parse("tag", "access=any,dfltuid=65534").unwrap();
    assert_eq!(any.access, Access::Any);
    assert_eq!(attach_uid(&any, 1000), 65534);
    // An explicit identity is used whoever the caller is.
    let single = opts::parse("tag", "access=500").unwrap();
    assert_eq!(attach_uid(&single, 1000), 500);
}

#[test]
fn rename_admits_only_the_unflagged_protocol_operation() {
    assert!(admit_rename_flags(0).is_ok());
    for flags in [vfs::namei::RENAME_NOREPLACE, vfs::namei::RENAME_EXCHANGE] {
        assert_eq!(admit_rename_flags(flags).err(), Some(vfs::VfsError::Einval));
    }
}
