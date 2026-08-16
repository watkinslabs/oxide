//! What a mount does about a chain: refusing a broken one, and honouring what
//! the mount is allowed to write.

use crate::opts::Options;
use crate::test_image;
use crate::uapi::*;
use crate::volume::recover::fixture::*;
use crate::volume::recover::Recovery;
use crate::volume::Volume;
use crate::node::footer;
use sectors::MemImage;
use syscall::errno::Errno;

// ------------------------------------------------------- refusing a bad chain

#[test]
fn the_chain_stops_at_the_first_node_of_another_generation() {
    let (mut v, ino, body) = checkpointed(b"f");
    let (_, node) = append_block(&mut v, ino, 0xEE, true);
    let mut bytes = v.into_source().snapshot();
    let at = node as usize * BLKSIZE + NODE_FOOTER_OFF + FOOTER_CP_VER;
    bytes[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    let v = remount(bytes, true);
    assert_eq!(whole(&v, ino), body);
}

#[test]
fn a_chain_that_loops_is_refused() {
    let (mut v, ino, _) = checkpointed(b"f");
    let (_, first) = append_block(&mut v, ino, 0xE1, true);
    let (_, second) = append_block(&mut v, ino, 0xE2, true);
    let mut bytes = v.into_source().snapshot();
    poke_footer(&mut bytes, second, FOOTER_NEXT_BLKADDR, first);
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes);
    assert_eq!(Volume::mount_with(img, Options::defaults(), true).err(), Some(Errno::Einval),
               "a mount may not hand out a volume whose chain cannot be walked");
}

#[test]
fn a_chain_leaving_the_main_area_stops_where_it_leaves() {
    let (mut v, ino, _) = checkpointed(b"f");
    let (_, first) = append_block(&mut v, ino, 0xE1, true);
    append_block(&mut v, ino, 0xE2, true);
    let mut bytes = v.into_source().snapshot();
    poke_footer(&mut bytes, first, FOOTER_NEXT_BLKADDR, test_image::SIT_BLKADDR);
    let v = remount(bytes, true);
    let all = whole(&v, ino);
    assert!(all[BODY..].iter().all(|&x| x == 0xE1), "only the first link replayed");
}

#[test]
fn a_forward_pointer_at_the_blocks_own_address_stops_the_chain() {
    let (mut v, ino, _) = checkpointed(b"f");
    let (_, first) = append_block(&mut v, ino, 0xE1, true);
    append_block(&mut v, ino, 0xE2, true);
    let mut bytes = v.into_source().snapshot();
    poke_footer(&mut bytes, first, FOOTER_NEXT_BLKADDR, first);
    let v = remount(bytes, true);
    let all = whole(&v, ino);
    assert!(all[BODY..].iter().all(|&x| x == 0xE1));
}

// ------------------------------------------------------------- mount policies

#[test]
fn a_checkpoint_after_the_chain_leaves_nothing_to_replay() {
    let (mut v, ino, _) = checkpointed(b"f");
    append_block(&mut v, ino, 0xEE, true);
    v.commit().expect("commit");
    let mut v = crash(v);
    assert_eq!(v.recover().expect("recover"), Recovery::Clean);
}

#[test]
fn a_volume_whose_checkpoint_claims_a_clean_shutdown_is_scanned_anyway() {
    // The mark describes the checkpoint on the medium, not the time since. A
    // mount that wrote a chain and never checkpointed leaves it standing, so
    // skipping on it drops writes an `fsync` promised — silently, and for
    // good, because the next checkpoint retires the chain's blocks.
    let (mut v, ino) = checkpointed_unmounted(b"f");
    append_block(&mut v, ino, 0xEE, true);
    let bytes = v.into_source().snapshot();
    let probe = remount(bytes.clone(), false);
    assert!(probe.checkpoint().has(crate::flags::CP_UMOUNT_FLAG), "the mark is set");
    assert!(probe.has_fsync_data().expect("probe"), "and a chain follows it");
    let mut v = remount(bytes, true);
    assert!(!v.has_fsync_data().expect("probe"), "consumed by the mount");
    assert_eq!(v.recover_at_mount().expect("mount hook"), Recovery::Clean);
}

#[test]
fn a_volume_closed_by_a_sync_is_scanned() {
    let (mut v, ino, _) = checkpointed(b"f");
    append_block(&mut v, ino, 0xEE, true);
    let probe = crash_ro(v);
    assert!(probe.has_fsync_data().expect("probe"));
    let mut v = remount(probe.into_source().snapshot(), true);
    assert_eq!(v.recover_at_mount().expect("mount hook"), Recovery::Clean);
    assert!(!v.has_fsync_data().expect("probe"), "consumed by the mount, not skipped");
}

#[test]
fn a_sync_checkpoint_does_not_claim_a_clean_shutdown() {
    let (v, _, _) = checkpointed(b"f");
    assert!(!v.checkpoint().has(crate::flags::CP_UMOUNT_FLAG));
    let (v, _) = checkpointed_unmounted(b"f");
    assert!(v.checkpoint().has(crate::flags::CP_UMOUNT_FLAG));
}

#[test]
fn a_clean_volume_needs_no_recovery_at_mount() {
    let (v, _, _) = checkpointed(b"f");
    let mut v = crash(v);
    assert_eq!(v.recover_at_mount().expect("mount hook"), Recovery::Clean);
}

#[test]
fn a_read_only_mount_does_not_replay() {
    let (mut v, ino, body) = checkpointed(b"f");
    append_block(&mut v, ino, 0xEE, true);
    let mut v = crash_ro(v);
    assert_eq!(v.recover_at_mount().expect("mount hook"), Recovery::Skipped);
    assert_eq!(whole(&v, ino), body);
}

#[test]
fn a_read_only_mount_refuses_to_replay_directly() {
    let (mut v, ino, _) = checkpointed(b"f");
    append_block(&mut v, ino, 0xEE, true);
    let mut v = crash_ro(v);
    assert_eq!(v.recover().err(), Some(Errno::Erofs));
}

#[test]
fn a_read_only_medium_with_a_chain_refuses_the_mount() {
    let (mut v, ino, _) = checkpointed(b"f");
    append_block(&mut v, ino, 0xEE, true);
    let img = MemImage::from_bytes(BLKSIZE as u32, v.into_source().snapshot()).read_only();
    assert_eq!(Volume::mount_with(img, Options::defaults(), true).err(), Some(Errno::Erofs),
               "a chain that can never be replayed must not be mounted over");
}

#[test]
fn a_read_only_medium_without_a_chain_mounts() {
    let (v, _, _) = checkpointed(b"f");
    let img = MemImage::from_bytes(BLKSIZE as u32, v.into_source().snapshot()).read_only();
    let mut v = Volume::mount_with(img, Options::defaults(), true).expect("mount");
    assert_eq!(v.recover_at_mount().expect("mount hook"), Recovery::Clean);
}

/// The two options that suppress the replay are NOT the same request, and the
/// difference is where each is settled.
///
/// `norecovery` demands a mount that cannot write, and the option pass every
/// mount runs is what refuses it — before any chain is read, so the refusal
/// does not depend on there being one.
#[test]
fn norecovery_refuses_a_writable_mount_whether_or_not_there_is_a_chain() {
    let opts = Options { recovery: false, norecovery: true, ..Options::defaults() };
    let (mut v, ino, _) = checkpointed(b"f");
    append_block(&mut v, ino, 0xEE, true);
    assert_eq!(try_crash(v, true, opts).err(), Some(Errno::Einval));
    // Same answer on a volume with nothing to replay: it is the OPTION that
    // is refused, not the chain.
    let (v, _, _) = checkpointed(b"g");
    let img = MemImage::from_bytes(BLKSIZE as u32, v.into_source().snapshot());
    assert_eq!(Volume::mount_with(img, opts, true).err(), Some(Errno::Einval));
}

/// `disable_roll_forward` carries no such demand. It is legal on a writable
/// mount and its whole effect is that the chain is dropped — refusing it
/// would be refusing the option a caller reaches for precisely when it wants
/// the tail gone.
#[test]
fn disable_roll_forward_drops_the_chain_on_a_writable_mount() {
    let (mut v, ino, body) = checkpointed(b"f");
    append_block(&mut v, ino, 0xEE, true);
    let opts = Options { recovery: false, norecovery: false, ..Options::defaults() };
    let mut v = try_crash(v, true, opts).expect("mount");
    assert!(v.writable());
    assert_eq!(v.recover_at_mount().expect("mount hook"), Recovery::Skipped);
    // The file is as the last checkpoint left it: the tail is gone, which is
    // what was asked for.
    assert_eq!(whole(&v, ino), body);
}

#[test]
fn norecovery_drops_the_chain_on_a_mount_that_cannot_write() {
    let (mut v, ino, body) = checkpointed(b"f");
    append_block(&mut v, ino, 0xEE, true);
    let opts = Options { recovery: false, norecovery: true, ..Options::defaults() };
    let mut v = try_crash(v, false, opts).expect("mount");
    assert_eq!(v.recover_at_mount().expect("mount hook"), Recovery::Skipped);
    assert_eq!(whole(&v, ino), body);
}

#[test]
fn disable_roll_forward_on_a_clean_volume_is_not_an_error() {
    let (v, _, _) = checkpointed(b"f");
    let opts = Options { recovery: false, ..Options::defaults() };
    let img = MemImage::from_bytes(BLKSIZE as u32, v.into_source().snapshot());
    let mut v = Volume::mount_with(img, opts, true).expect("mount");
    assert_eq!(v.recover_at_mount().expect("mount hook"), Recovery::Clean);
}

/// A mount that put a chain back says so in its condition word, and keeps
/// saying it: a tool reading the word afterwards must be able to tell such a
/// mount from one that came up clean.
#[test]
fn a_mount_that_replayed_a_chain_says_so_in_its_condition_word() {
    use crate::sbflags::bits::IS_RECOVERED;
    let (mut v, ino, _) = checkpointed(b"f");
    append_block(&mut v, ino, 0xEE, true);
    // The mount runs the replay itself, so the volume it hands back is one
    // that has already recovered.
    let mut v = crash(v);
    assert_ne!(v.sb_status() & (1 << IS_RECOVERED), 0);
    // A latch: a checkpoint written afterwards does not retire it.
    v.commit().expect("commit");
    assert_ne!(v.sb_status() & (1 << IS_RECOVERED), 0);
    // And the NEXT mount, which put nothing back, does not inherit it.
    let again = crash(v);
    assert_eq!(again.sb_status() & (1 << IS_RECOVERED), 0);
}

/// A mount with nothing to put back does not claim it recovered anything.
#[test]
fn a_clean_mount_does_not_claim_a_recovery() {
    use crate::sbflags::bits::IS_RECOVERED;
    let (v, _, _) = checkpointed(b"f");
    let mut v = crash(v);
    assert_eq!(v.recover_at_mount().expect("hook"), Recovery::Clean);
    assert_eq!(v.sb_status() & (1 << IS_RECOVERED), 0);
    let _ = &mut v;
}

// ------------------------------------------------------------ what was walked

#[test]
fn the_walk_finds_exactly_the_marked_blocks() {
    let (mut v, ino, _) = checkpointed(b"f");
    append_block(&mut v, ino, 0xE1, false);
    let (_, marked) = append_block(&mut v, ino, 0xE2, true);
    let v = crash_ro(v);
    let found = v.scan_fsync_chain().expect("scan");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].addr, marked);
    assert_eq!(found[0].ino, ino);
    assert!(found[0].is_inode);
}

#[test]
fn the_chains_forward_pointers_advance() {
    let (mut v, ino, _) = checkpointed(b"f");
    let (_, first) = append_block(&mut v, ino, 0xE1, true);
    let (_, second) = append_block(&mut v, ino, 0xE2, true);
    assert_ne!(first, second);
    let v = crash_ro(v);
    let block = v.read_block(first).expect("block");
    let f = footer::parse(&block).expect("footer");
    assert_eq!(f.next_blkaddr, second, "each link must name the block that followed it");
    assert_ne!(f.next_blkaddr, first);
}

