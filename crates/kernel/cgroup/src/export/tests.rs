// cgroup2's exported file handle. Ungated module, so these compile and run.
//
// The headline is the WIDTH: the cgroup-id reader in the service manager sizes
// its buffer to `sizeof(uint64_t)` and does not run the grow-and-retry
// protocol, so a handle wider than 8 bytes fails every one of its calls with
// EOVERFLOW — which is exactly what the generic 12-byte FID did, on every unit
// start.

use alloc::sync::Arc;

use vfs::export::fid::{FID_LEN, FID_LEN_PARENT, HANDLE_TYPE_INO_GEN_PARENT};
use vfs::export::kernfs_fid::{HANDLE_TYPE_KERNFS, KERNFS_FID_LEN};
use vfs::SuperOps;

use super::*;

/// The unified hierarchy is a process-wide singleton; realize it once so the
/// root cgroup exists and ids resolve.
fn hierarchy() -> u64 {
    let _ = crate::realize_tree();
    tree::ROOT
}

fn ops() -> Arc<dyn SuperOps> { super::super_ops() }

/// A plain (non-connectable) cgroup handle costs exactly 8 bytes, whether the
/// object is a directory or a control file.
#[test]
fn a_plain_cgroup_handle_costs_eight_bytes() {
    let o = ops();
    assert_eq!(o.export_fid_len(false, true), KERNFS_FID_LEN);
    assert_eq!(o.export_fid_len(false, false), KERNFS_FID_LEN);
    // A connectable DIRECTORY needs no parent in Linux's model either, so it
    // also fits the kernfs width.
    assert_eq!(o.export_fid_len(true, true), KERNFS_FID_LEN);
    assert!(KERNFS_FID_LEN < FID_LEN, "the generic FID is what did not fit");
}

/// The encoded payload is the directory's inode number, so a caller reading
/// `f_handle` as a `uint64_t` gets the same id `stat(2)` reports.
#[test]
fn the_encoded_payload_is_the_cgroup_directory_inode_number() {
    let root = hierarchy();
    let dir = inode::make_cg_dir(root);
    let mut buf = [0u8; FID_LEN_PARENT as usize];
    let (len, ty) = ops().export_encode_fh(&dir, None, &mut buf);
    assert_eq!(len, KERNFS_FID_LEN);
    assert_eq!(ty, HANDLE_TYPE_KERNFS);
    assert_eq!(u64::from_le_bytes(buf[..8].try_into().unwrap()), dir.ino());
}

/// Encode then decode then resolve: the handle names the same cgroup directory.
#[test]
fn a_cgroup_directory_handle_round_trips_to_the_same_inode() {
    let root = hierarchy();
    let o = ops();
    let dir = inode::make_cg_dir(root);
    let mut buf = [0u8; FID_LEN_PARENT as usize];
    let (len, ty) = o.export_encode_fh(&dir, None, &mut buf);
    assert_eq!(o.export_fid_len_for_type(ty), Some(len));
    let fid = o.export_decode_fh(&buf[..len as usize], ty).expect("decodes");
    let back = resolve_ino(fid.ino).expect("resolves to a live cgroup");
    assert_eq!(back.ino(), dir.ino());
    assert_eq!(crate::cgid_from_dir_inode(&back), Some(root));
}

/// A control file's number carries `(cgroup, file slot)`, so its handle
/// round-trips to the same file, not merely to its cgroup.
#[test]
fn a_control_file_handle_round_trips_to_the_same_file() {
    let root = hierarchy();
    let name = crate::node_file_names(root).into_iter().next().expect("root has control files");
    let f = inode::make_cg_file(root, name);
    let o = ops();
    let mut buf = [0u8; FID_LEN_PARENT as usize];
    let (len, ty) = o.export_encode_fh(&f, None, &mut buf);
    let fid = o.export_decode_fh(&buf[..len as usize], ty).expect("decodes");
    let back = resolve_ino(fid.ino).expect("resolves");
    assert_eq!(back.ino(), f.ino());
}

/// An inode number outside cgroupfs's regions is not cgroupfs's to resolve, and
/// a cgroup id with no live node is stale rather than a synthesized inode for a
/// cgroup that was removed.
#[test]
fn a_foreign_or_dead_number_does_not_resolve() {
    hierarchy();
    assert!(resolve_ino(1).is_none(), "not in a cgroup region");
    let dead = ids::dir_ino(0x00ff_fffe);
    assert!(!crate::node_exists(0x00ff_fffe), "id is not in the hierarchy");
    assert!(resolve_ino(dead).is_none(), "a dead cgroup id is stale");
}

/// The inode-number derivations invert exactly, which is what makes the
/// 8-byte handle a complete identity — up to each region's width, past which
/// the fold wraps ids onto lower ones (a directory id past `CGROUP_DIR`'s
/// 2^24, a control file past `CGROUP_FILE`'s 2^19 cgroups).
#[test]
fn the_inode_number_derivations_invert() {
    for cgid in [0u64, 1, 2, 4095, 0x0007_ffff] {
        assert_eq!(ids::cgid_of_dir_ino(ids::dir_ino(cgid)), Some(cgid), "dir {cgid}");
        for slot in [0u8, 1, 7, 255] {
            assert_eq!(ids::cgid_slot_of_file_ino(ids::file_ino(cgid, slot)),
                       Some((cgid, slot)), "file {cgid}/{slot}");
        }
    }
    // A directory id inverts across the whole directory region.
    assert_eq!(ids::cgid_of_dir_ino(ids::dir_ino(0x00ff_ffff)), Some(0x00ff_ffff));
    // Past the control-file region's cgroup width the packed number wraps, so
    // the inverse names a different cgroup. Stated here so a later widening of
    // the region has a test that says what it fixes.
    assert_ne!(ids::cgid_slot_of_file_ino(ids::file_ino(0x0008_0000, 3)),
               Some((0x0008_0000, 3)));
}

/// A connectable handle to a control file is the one shape the kernfs payload
/// cannot carry, so it falls back to the generic FID — a different
/// `handle_type`, so decode stays unambiguous.
#[test]
fn a_connectable_control_file_handle_uses_the_generic_fid() {
    let root = hierarchy();
    let o = ops();
    let name = crate::node_file_names(root).into_iter().next().expect("control files");
    let f = inode::make_cg_file(root, name);
    let dir = inode::make_cg_dir(root);
    assert_eq!(o.export_fid_len(true, false), FID_LEN_PARENT);
    let mut buf = [0u8; FID_LEN_PARENT as usize];
    let (len, ty) = o.export_encode_fh(&f, Some((dir.ino(), dir.i_generation())), &mut buf);
    assert_eq!(len, FID_LEN_PARENT);
    assert_eq!(ty, HANDLE_TYPE_INO_GEN_PARENT);
    let fid = o.export_decode_fh(&buf[..len as usize], ty).expect("decodes");
    assert_eq!(fid.ino, f.ino());
    assert_eq!(fid.parent, Some((dir.ino(), dir.i_generation())));
}

/// cgroupfs must claim it can decode, or `name_to_handle_at` refuses to mint
/// any handle at all (EOPNOTSUPP) before the width ever matters.
#[test]
fn cgroupfs_reports_that_it_can_decode_its_handles() {
    assert!(ops().export_can_decode_fh());
}
