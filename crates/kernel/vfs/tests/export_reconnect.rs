//! `open_by_handle_at(2)`'s reconnect half, against a filesystem whose
//! directories carry a real `..` — the upward `get_parent` walk, the
//! acceptable-alias preference, and connectedness itself.
//!
//! The properties asserted are the ones a ONE-HOP reconnect cannot provide:
//!
//!   1. A directory decoded N levels below the last cached ancestor comes back
//!      CONNECTED — its parent chain reaches the filesystem root — for every N,
//!      not only N == 1.
//!   2. A non-directory whose PARENT is itself uncached still reconnects,
//!      because the parent goes through the same walk before the child is
//!      instantiated under it.
//!   3. A `..` chain that cycles terminates instead of spinning.
//!   4. A decoded inode that already has an acceptable dentry reuses it rather
//!      than minting a second one.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

mod common;

use vfs::file_ops::{DirContext, FileOps};
use vfs::fs::FileSystem;
use vfs::inode::{Inode, InodeBuilder};
use vfs::inode_ops::InodeOps;
use vfs::superblock::next_anon_dev;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeRef, KResult, SuperBlock,
          VfsError};

/// The whole filesystem: `ino -> (parent ino, entries, is_dir)`. Directories
/// carry a real `..` (the on-disk shape `generic_get_parent` reads), so this
/// fixture drives the SAME code path an on-disk mount does. Per-instance, never
/// global: the suite runs its tests concurrently.
#[derive(Default)]
struct Tree {
    parent:  BTreeMap<u64, u64>,
    entries: BTreeMap<u64, Vec<(String, u64)>>,
    is_dir:  BTreeMap<u64, bool>,
}

struct FsState {
    tree: Mutex<Tree>,
    sb:   Mutex<Weak<SuperBlock>>,
}

impl FsState {
    fn with<R>(&self, f: impl FnOnce(&mut Tree) -> R) -> R {
        f(&mut self.tree.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

/// Every inode carries the fs state in `i_private`, so `iterate` (which sees
/// only the inode) can read the tree.
fn state_of(inode: &Inode) -> Arc<FsState> {
    inode.i_private().clone().downcast::<FsState>().expect("dotfs inode carries its fs state")
}

struct DirFops;
impl FileOps for DirFops {
    /// Emits the dots, like every backend whose entries are on disk. Without
    /// them there is no `..` for the reconnect walk to read.
    fn iterate_emits_dots(&self) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let st = state_of(inode);
        let ino = inode.ino();
        let (parent, entries, dirs) = st.with(|t| (
            *t.parent.get(&ino).unwrap_or(&ino),
            t.entries.get(&ino).cloned().unwrap_or_default(),
            t.is_dir.clone(),
        ));
        if !ctx.emit(".", ino, FileType::Directory, 1) { return Ok(()); }
        if !ctx.emit("..", parent, FileType::Directory, 2) { return Ok(()); }
        for (i, (name, cino)) in entries.iter().enumerate() {
            let ft = if *dirs.get(cino).unwrap_or(&false) { FileType::Directory }
                     else { FileType::Regular };
            if !ctx.emit(name, *cino, ft, 3 + i as u64) { break; }
        }
        Ok(())
    }
}

struct DirIops;
impl InodeOps for DirIops {
    fn lookup(&self, _inode: &Inode, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}

const ROOT_INO: u64 = 1;

struct DotFs { st: Arc<FsState> }

impl FileSystem for DotFs {
    fn name(&self) -> &str { "dotfs" }
    fn root(&self) -> Option<InodeRef> { Some(build(&self.st, ROOT_INO, true)) }
    fn set_sb(&self, sb: Weak<SuperBlock>) -> KResult<()> {
        *self.st.sb.lock().unwrap_or_else(|e| e.into_inner()) = sb;
        Ok(())
    }
}

/// Construct one inode. Linked to the superblock once it exists, so it draws a
/// real generation and its dentries are recorded as aliases.
fn build(st: &Arc<FsState>, ino: u64, dir: bool) -> InodeRef {
    let mode = if dir { mk_mode(FileType::Directory, 0o755) }
               else { mk_mode(FileType::Regular, 0o644) };
    let (iop, fop): (Arc<dyn InodeOps>, Arc<dyn FileOps>) = if dir {
        (Arc::new(DirIops), Arc::new(DirFops))
    } else { (default_inode_ops(), default_file_ops()) };
    let weak = st.sb.lock().unwrap_or_else(|e| e.into_inner()).clone();
    InodeBuilder::new(ino, mode, iop, fop).sb(weak).private(st.clone()).build()
}

/// Mount a fresh instance.
fn mount() -> (Arc<FsState>, Arc<SuperBlock>) {
    let st = Arc::new(FsState { tree: Mutex::new(Tree::default()), sb: Mutex::new(Weak::new()) });
    st.with(|t| { t.is_dir.insert(ROOT_INO, true); });
    let fs = Arc::new(DotFs { st: st.clone() });
    // `set_sb` runs only AFTER the root inode is built, exactly as a real
    // fill-super does — so the root is sb-less and off every alias list, the
    // condition `connected_alias` has to handle through `s_root`.
    let sb = common::realize_sb(fs.clone(), None, next_anon_dev(), String::from("dotfs"));
    (st, sb)
}

/// Register an inode in the tree AND in the superblock's cache, as a backend's
/// `iget` would.
fn add(st: &Arc<FsState>, sb: &Arc<SuperBlock>, parent: u64, name: &str, ino: u64, dir: bool)
    -> InodeRef
{
    st.with(|t| {
        t.parent.insert(ino, parent);
        t.is_dir.insert(ino, dir);
        t.entries.entry(parent).or_default().push((String::from(name), ino));
    });
    sb.iget(ino, || build(st, ino, dir))
}

/// A decoded directory THREE levels below the root — with nothing between it
/// and the root cached as a dentry — comes back connected.
///
/// This is the multi-hop property: a one-level reconnect attaches the directory
/// under a still-disconnected parent, and `dentry_connected` is then false.
#[test]
fn directory_reconnects_through_every_intervening_level() {
    let (st, sb) = mount();
    // Held, not dentried: the generic backend resolves an inode from the CACHE,
    // so the levels in between must be cached but pathless — which is exactly
    // the state a one-hop reconnect leaves them in.
    let _a = add(&st, &sb, ROOT_INO, "a", 10, true);
    let _b = add(&st, &sb, 10, "b", 11, true);
    let leaf = add(&st, &sb, 11, "c", 12, true);

    let d = vfs::export::reconnect_path(&sb, &leaf).expect("a three-level chain reconnects");
    assert!(vfs::export::dentry_connected(&d), "the reconnected dentry must reach the root");
    assert_eq!(d.name(), "c");
    let b = d.parent().expect("has a parent").clone();
    assert_eq!(b.name(), "b");
    let a = b.parent().expect("grandparent").clone();
    assert_eq!(a.name(), "a");
    assert!(a.parent().expect("root").is_root());
}

/// The already-connected case short-circuits to the SAME dentry, so a directory
/// never acquires a second dentry through a handle decode.
#[test]
fn reconnecting_a_connected_directory_returns_its_existing_dentry() {
    let (st, sb) = mount();
    let dir = add(&st, &sb, ROOT_INO, "a", 10, true);
    let first = vfs::export::reconnect_path(&sb, &dir).expect("reconnects");
    let again = vfs::export::reconnect_path(&sb, &dir).expect("reconnects again");
    assert!(Arc::ptr_eq(&first, &again), "a directory has exactly one dentry");
}

/// A non-directory whose parent chain is entirely uncached: the parent is
/// reconnected first (through the same multi-hop walk), then the child is
/// instantiated under it. A reconnect that stopped at the parent's anonymous
/// alias would hand back a child with no renderable path.
#[test]
fn child_reconnects_under_a_multi_level_parent() {
    let (st, sb) = mount();
    let _a = add(&st, &sb, ROOT_INO, "a", 10, true);
    let parent = add(&st, &sb, 10, "b", 11, true);
    let child = add(&st, &sb, 11, "leaf.txt", 12, false);

    let pd = vfs::export::reconnect_path(&sb, &parent).expect("parent reconnects");
    let name = vfs::export::get_name(&parent, child.ino()).expect("name found");
    assert_eq!(name, "leaf.txt");
    let cd = vfs::export::reconnect_child(&pd, &name, &child).expect("child reconnects");
    assert!(vfs::export::dentry_connected(&cd), "the child must reach the root too");
}

/// A `..` chain that never reaches a root terminates. A corrupt image can claim
/// a cycle; the walk must report the handle unreconnectable rather than run
/// forever.
#[test]
fn a_cyclic_parent_chain_terminates() {
    let (st, sb) = mount();
    // 20 -> 21 -> 20, neither reachable from the root.
    st.with(|t| {
        t.parent.insert(20, 21); t.parent.insert(21, 20);
        t.is_dir.insert(20, true); t.is_dir.insert(21, true);
        t.entries.entry(21).or_default().push((String::from("x"), 20));
        t.entries.entry(20).or_default().push((String::from("y"), 21));
    });
    let a = sb.iget(20, || build(&st, 20, true));
    assert!(vfs::export::reconnect_path(&sb, &a).is_none(), "a cycle is not reconnectable");
}

/// A directory that is its own `..` without a published root dentry is not
/// reconnectable — the chain has nowhere left to climb.
#[test]
fn a_self_parented_directory_without_a_root_is_unreconnectable() {
    let (st, sb) = mount();
    st.with(|t| { t.parent.insert(30, 30); t.is_dir.insert(30, true); });
    let orphan = sb.iget(30, || build(&st, 30, true));
    assert!(vfs::export::reconnect_path(&sb, &orphan).is_none());
}

/// A non-directory is not reconnected by the directory walk — that shape is the
/// caller's `fh_to_parent` + `get_name` sequence, and confusing the two would
/// scan a regular file as if it were a directory.
#[test]
fn reconnect_path_refuses_a_non_directory() {
    let (st, sb) = mount();
    let f = add(&st, &sb, ROOT_INO, "f", 40, false);
    assert!(vfs::export::reconnect_path(&sb, &f).is_none());
}

/// `find_acceptable_alias` prefers an EXISTING dentry over the anonymous alias
/// a bare decode produces — and, when the first candidate is rejected, keeps
/// looking through the inode's other links instead of failing.
#[test]
fn an_acceptable_existing_alias_wins_over_a_fresh_one() {
    let (st, sb) = mount();
    let dir = add(&st, &sb, ROOT_INO, "a", 10, true);
    let child = add(&st, &sb, 10, "one.txt", 11, false);
    let pd = vfs::export::reconnect_path(&sb, &dir).expect("parent reconnects");
    let named = vfs::export::reconnect_child(&pd, "one.txt", &child).expect("named dentry");

    // A decode that accepts anything takes the dentry it was handed.
    let anon = vfs::export::fh_alias(child.clone());
    let any = vfs::export::find_acceptable_alias(&sb, &anon, |_| true).expect("accepts result");
    assert!(Arc::ptr_eq(&any, &anon), "the tested dentry wins when it is acceptable");

    // A decode that will only take a CONNECTED dentry finds the named one.
    let connected = vfs::export::find_acceptable_alias(&sb, &anon, vfs::export::dentry_connected)
        .expect("an acceptable alias exists");
    assert!(Arc::ptr_eq(&connected, &named), "the connected link is chosen over the alias");

    // Nothing acceptable => None, never a silent downgrade.
    assert!(vfs::export::find_acceptable_alias(&sb, &anon, |_| false).is_none());
}

/// A parentless anonymous alias is never "connected"; a dentry whose chain
/// reaches the superblock root is.
#[test]
fn connectedness_is_reaching_the_filesystem_root() {
    let (st, sb) = mount();
    let f = add(&st, &sb, ROOT_INO, "f", 50, false);
    assert!(vfs::export::dentry_connected(&sb.s_root().expect("root")));
    assert!(vfs::export::connected_alias(&sb, &f).is_none(), "no connected alias yet");

    let root_d = sb.s_root().expect("root");
    let named = vfs::export::reconnect_child(&root_d, "f", &f).expect("attach");
    assert!(vfs::export::dentry_connected(&named));
    let found = vfs::export::connected_alias(&sb, &f).expect("now there is one");
    assert!(Arc::ptr_eq(&found, &named));
}
