// `open_by_handle_at(2)`'s reach test. The load-bearing property is that the
// owner compared is the MOUNT's view (`vfsuid`), not the raw stored one: on an
// idmapped mount those are different ids, and the raw compare gives the wrong
// answer in BOTH directions.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;

use vfs::dcache::{d_add, d_make_root};
use vfs::dentry::Dentry;
use vfs::idmap::Idmap;
use vfs::inode::InodeBuilder;
use vfs::superblock::next_anon_dev;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeRef, SuperBlock};

use crate::handle_policy::acceptable::{dentry_acceptable, inode_owner_reachable};
use crate::handle_policy::DecodeCtx;

fn owned(sb: &Arc<SuperBlock>, ino: u64, uid: u32, gid: u32, dir: bool) -> InodeRef {
    let ft = if dir { FileType::Directory } else { FileType::Regular };
    InodeBuilder::new(ino, mk_mode(ft, 0o755), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(sb)).owner(uid, gid).build()
}

/// Root + one child directory + one file, each with its own owner.
fn tree(root_uid: u32, mid_uid: u32, leaf_uid: u32)
    -> (Arc<SuperBlock>, Arc<Dentry>, Arc<Dentry>, Arc<Dentry>)
{
    let ty: Arc<dyn vfs::FileSystemType> = vfs::fs::FsType::new(
        "acceptfs", 0, vfs::fs::FsFlags::empty(),
        alloc::boxed::Box::new(|_, _, _, _, _| unreachable!("not mounted through ->mount")));
    let s_op: Arc<dyn vfs::SuperOps> = Arc::new(vfs::SimpleSuperOps {
        magic: 0, block_size: 4096, options: String::new() });
    let sb = SuperBlock::from_ops(ty, s_op, None, 0, next_anon_dev(), 4096,
                                  String::from("acceptfs"), Arc::new(()));
    let root_i = owned(&sb, 1, root_uid, root_uid, true);
    let rd = d_make_root(root_i, &sb);
    let md = d_add(&rd, "mid", owned(&sb, 2, mid_uid, mid_uid, true));
    let ld = d_add(&md, "leaf", owned(&sb, 3, leaf_uid, leaf_uid, false));
    (sb, rd, md, ld)
}

/// `check_perms` requires every level's owner to be namable; the ctx that asks
/// for neither check accepts unconditionally.
const NONE: DecodeCtx = DecodeCtx { check_perms: false, check_subtree: false, dir_only: false };
const PERMS: DecodeCtx = DecodeCtx { check_perms: true, check_subtree: false, dir_only: false };
const SUBTREE: DecodeCtx = DecodeCtx { check_perms: false, check_subtree: true, dir_only: false };

/// The global-capability holder's empty context accepts anything — that caller
/// could have walked to the object anyway.
#[test]
fn an_empty_context_accepts_unconditionally() {
    let (_sb, rd, _md, ld) = tree(0, 0, 0);
    assert!(dentry_acceptable(&NONE, &vfs::IDENTITY, &rd, &ld, |_, _| false),
        "no check requested means no check performed");
}

/// THE idmap test. The mount shifts fs ids `[0,65536)` up to `[100000,165536)`,
/// and the caller can name only the shifted window. Every inode on the path is
/// therefore acceptable — and the RAW ids are not in the caller's window at all,
/// so a comparison against `i_uid`/`i_gid` would refuse the whole chain.
#[test]
fn an_idmapped_mount_is_judged_on_the_vfsuid_not_the_raw_owner() {
    let map = Idmap::uniform(0, 100_000, 65_536);
    let (_sb, rd, _md, ld) = tree(0, 500, 1000);
    // The caller's namespace names exactly the mount's OUTPUT window.
    let caller_window = |uid: u32, gid: u32| {
        (100_000..165_536).contains(&uid) && (100_000..165_536).contains(&gid)
    };

    assert!(dentry_acceptable(&PERMS, &map, &rd, &ld, caller_window),
        "fs uids 1000/500/0 map to 101000/100500/100000 — all namable");
    // Fails-before: the raw ids 1000/500/0 are outside the caller's window, so
    // comparing them instead of the vfsuid rejects a path the caller owns.
    assert!(!dentry_acceptable(&PERMS, &vfs::IDENTITY, &rd, &ld, caller_window),
        "the same walk on a NON-idmapped mount is correctly refused");
}

/// The other direction: an idmapped mount that shifts ownership OUT of the
/// caller's range must REFUSE, where the raw compare would have accepted.
#[test]
fn an_idmap_that_shifts_ownership_away_refuses() {
    let map = Idmap::uniform(0, 100_000, 65_536);
    let (_sb, rd, _md, ld) = tree(0, 0, 0);
    let caller_owns_low = |uid: u32, gid: u32| uid < 1000 && gid < 1000;

    assert!(dentry_acceptable(&PERMS, &vfs::IDENTITY, &rd, &ld, caller_owns_low),
        "raw owner 0 is inside the caller's range");
    assert!(!dentry_acceptable(&PERMS, &map, &rd, &ld, caller_owns_low),
        "…but through the mount it is 100000, which the caller cannot name");
}

/// An owner the mount's idmap cannot translate at all is Linux's
/// `INVALID_VFSUID` — never a passthrough of the raw id, and never acceptable.
#[test]
fn an_untranslatable_owner_is_refused() {
    let map = Idmap::uniform(0, 100_000, 65_536);
    assert!(!inode_owner_reachable(&map, Some(70_000), Some(70_000), |_, _| true),
        "an fs id outside every extent has no vfs id to judge");
    assert!(!inode_owner_reachable(&map, None, Some(0), |_, _| true),
        "an inode with no owner to report cannot be shown reachable");
    assert!(inode_owner_reachable(&map, Some(7), Some(7), |u, g| u == 100_007 && g == 100_007),
        "a translatable owner is judged on its translated ids");
}

/// One unnamable ANCESTOR fails the whole walk, even when the object itself is
/// fine: the caller could not have reached it by walking.
#[test]
fn an_unnamable_ancestor_fails_the_walk() {
    let (_sb, rd, _md, ld) = tree(0, 9_999, 1_000);
    let names_all_but_9999 = |uid: u32, _g: u32| uid != 9_999;
    assert!(dentry_acceptable(&PERMS, &vfs::IDENTITY, &rd, &rd, names_all_but_9999),
        "the root's own owner is namable");
    assert!(!dentry_acceptable(&PERMS, &vfs::IDENTITY, &rd, &ld, names_all_but_9999),
        "the intermediate directory's owner has no name in the caller's namespace");
}

/// Containment: reaching a filesystem root without meeting the anchor is
/// acceptable only when the subtree check was not demanded.
#[test]
fn subtree_containment_requires_meeting_the_anchor() {
    let (_sb, rd, md, ld) = tree(0, 0, 0);
    assert!(dentry_acceptable(&SUBTREE, &vfs::IDENTITY, &rd, &ld, |_, _| true),
        "the leaf is under the root anchor");
    assert!(dentry_acceptable(&SUBTREE, &vfs::IDENTITY, &md, &ld, |_, _| true),
        "…and under the mid anchor");
    // An anchor that is NOT on the leaf's chain: the walk reaches the fs root
    // without meeting it.
    let (_sb2, other_root, _m2, _l2) = tree(0, 0, 0);
    assert!(!dentry_acceptable(&SUBTREE, &vfs::IDENTITY, &other_root, &ld, |_, _| true),
        "an object outside the anchor's subtree is refused");
}
