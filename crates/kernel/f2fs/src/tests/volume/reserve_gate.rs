//! The root reserve, driven through the allocation path that consults it.
//!
//! Not a unit test on the decision — `reserve::tests` covers that — but proof
//! that `volume_has_room` reaches it: the volume is filled to exactly the
//! reserve, and the SAME write is refused or admitted according only to who
//! the installed credential probe says is asking.
//!
//! One test function, not several. The probe is process-wide state, so
//! separate `#[test]`s would race each other's install and clear under the
//! default parallel runner and produce a flake that reads like a real defect.

use sectors::MemImage;
use syscall::errno::Errno;

use crate::mode::S_IFREG;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 3);
const RESERVED_UID: u32 = 500;
const RESERVED_GID: u32 = 600;
/// Blocks held back. Two, so the write under test needs one and the volume
/// still has room for the direct node the second offset may want.
const HELD: u32 = 8;

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

/// A writable volume holding one file, filled so that exactly `HELD` blocks
/// remain, with the reserve set to all of them.
fn brimming() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &alloc::vec![1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    let left = v.cp.user_block_count - v.valid_block_count;
    v.cp.user_block_count -= left - u64::from(HELD);
    v.opts.reserve_root = HELD;
    v.opts.resuid = RESERVED_UID;
    v.opts.resgid = RESERVED_GID;
    (v, ino)
}

fn ordinary(_res_gid: u32) -> vfs::ReservedCaller {
    vfs::ReservedCaller { fsuid: 1000, in_res_group: false, cap_sys_resource: false }
}

fn the_reserved_uid(_res_gid: u32) -> vfs::ReservedCaller {
    vfs::ReservedCaller { fsuid: RESERVED_UID, in_res_group: false, cap_sys_resource: false }
}

fn in_the_reserved_group(res_gid: u32) -> vfs::ReservedCaller {
    vfs::ReservedCaller { fsuid: 1000, in_res_group: res_gid == RESERVED_GID,
                          cap_sys_resource: false }
}

fn privileged(_res_gid: u32) -> vfs::ReservedCaller {
    vfs::ReservedCaller { fsuid: 1000, in_res_group: false, cap_sys_resource: true }
}

/// Write one block past the first, which needs room the reserve is holding.
fn second_block(v: &mut Volume<MemImage>, ino: u32) -> Result<(), Errno> {
    v.write_file(ino, BLKSIZE as u64, &alloc::vec![2u8; BLKSIZE]).map(|_| ())
}

#[test]
fn the_reserve_is_spendable_by_exactly_the_parties_it_is_held_for() {
    // Kernel context: no probe, and the reserve is the kernel's to spend.
    vfs::clear_reserved_caller_hook();
    let (mut v, ino) = brimming();
    assert_eq!(second_block(&mut v, ino), Ok(()),
               "kernel context could not reach the space held for it");

    // The whole point of the row this closes: an ordinary caller is refused,
    // and the SAME volume in the SAME state admits the reserved parties. If
    // `volume_has_room` stopped consulting the probe, this line stays green
    // and every line below it goes red.
    vfs::set_reserved_caller_hook(ordinary);
    let (mut v, ino) = brimming();
    assert_eq!(second_block(&mut v, ino), Err(Errno::Enospc),
               "an ordinary caller spent the root reserve");

    vfs::set_reserved_caller_hook(the_reserved_uid);
    let (mut v, ino) = brimming();
    assert_eq!(second_block(&mut v, ino), Ok(()), "resuid= was not consulted");

    vfs::set_reserved_caller_hook(in_the_reserved_group);
    let (mut v, ino) = brimming();
    assert_eq!(second_block(&mut v, ino), Ok(()), "resgid= was not consulted");

    vfs::set_reserved_caller_hook(privileged);
    let (mut v, ino) = brimming();
    assert_eq!(second_block(&mut v, ino), Ok(()), "CAP_SYS_RESOURCE was not consulted");

    // A volume that reserved nothing hands nobody anything extra: with the
    // reserve at zero the ordinary caller and the privileged one see the same
    // full volume, so a passing case above cannot be the reserve being ignored.
    vfs::set_reserved_caller_hook(privileged);
    let (mut v, ino) = brimming();
    v.opts.reserve_root = 0;
    v.cp.user_block_count -= u64::from(HELD);
    assert_eq!(second_block(&mut v, ino), Err(Errno::Enospc),
               "a privileged caller invented space the volume does not have");

    vfs::clear_reserved_caller_hook();
}
