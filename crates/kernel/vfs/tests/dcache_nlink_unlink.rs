//! dcache/inode D30: couple `Inode::i_nlink` to the per-inode `i_dentry` alias
//! list on unlink. `d_unlink` (Linux `vfs_unlink` tail) drops one hard-link
//! name (`Inode::drop_link`) then tears the dentry down (`d_delete`); when the
//! LAST name goes, remaining unused aliases are pruned and the inode is retired
//! through the existing `iput`/`drop_inode`/`evict_inode` lifecycle — no
//! double-evict. Driven against a real ramfs SuperBlock so `i_sb()` resolves
//! and the alias list / icache eviction are exercised end to end.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::dcache::d_unlink;
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{FileType, InodeRef, KResult};

// These tests mutate the process-global dcache hash table; serialize them.
static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

struct RamFsType;
impl FileSystemType for RamFsType {
    fn name(&self) -> &str { "ramfs" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { Ok(mount_ramfs(0x51)) }
}
struct RamFsOps;
impl SuperOps for RamFsOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs { f_bsize: 4096, ..Default::default() }) }
}

fn ramdir(sb: &Arc<SuperBlock>, ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755), vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(sb)).build()
}
// A regular file built with two hard-link names already accounted (nlink=2).
fn ramfile(sb: &Arc<SuperBlock>, ino: u64, nlink: u32) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Regular, 0o644), vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(sb)).nlink(nlink).build()
}

fn mount_ramfs(s_dev: u64) -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(RamFsType), Arc::new(RamFsOps), 0x858458f6, s_dev, 4096, "ramfs".into(), Arc::new(()))
}

// Two names → one inode (hard link). Unlink one: the OTHER still resolves and
// nlink drops. Unlink the last: the inode is retired (evicted from the icache).
#[test]
fn hardlink_unlink_one_keeps_other_then_retires_on_last() {
    let _g = guard();
    let sb = mount_ramfs(1);
    let root = vfs::d_make_root(ramdir(&sb, 2), &sb);

    // Build the inode born `i_count == 1`, nlink 2 (two names about to bind).
    let inode: InodeRef = ramfile(&sb, 50, 2);
    assert_eq!(inode.i_count(), 1, "fresh build: born i_count == 1");

    // Bind two hard-link names; each alias grabs one `i_count` (1 + 2 = 3).
    let a = vfs::d_add(&root, "a", inode.clone());
    let b = vfs::d_add(&root, "b", inode.clone());
    assert_eq!(inode.i_count(), 3, "two aliases each count");
    assert_eq!(sb.i_aliases(50).len(), 2, "both names on the alias list");

    // Release the build/born reference (Linux `d_instantiate` consumes the iget
    // ref) so only the two durable alias holds remain (3 → 2).
    vfs::file::iput(inode.clone());
    assert_eq!(inode.i_count(), 2, "born ref released; two aliases remain");

    // --- unlink "a": NOT the last name ---------------------------------------
    let last = d_unlink(&a);
    assert!(!last, "two names → unlink one is not the last");
    assert_eq!(inode.nlink(), 1, "drop_link took nlink 2 → 1");
    assert!(a.is_negative(), "unlinked name detached → negative");
    assert_eq!(sb.i_aliases(50).len(), 1, "only the surviving name remains an alias");
    assert!(sb.ilookup(50).is_some(), "inode still linked → alive");

    // "b" still resolves to the same live inode.
    let hit = vfs::d_lookup(&root, "b").expect("surviving hard link still cached");
    let hit_inode = hit.inode().expect("b is positive");
    assert!(Arc::ptr_eq(&hit_inode, &inode), "b still names the same inode");

    // --- unlink "b": the LAST name → retire ----------------------------------
    let last = d_unlink(&b);
    assert!(last, "removing the only remaining name is the last");
    assert_eq!(inode.nlink(), 0, "nlink fully dropped");
    assert_eq!(sb.i_aliases(50).len(), 0, "alias list empty");
    assert!(sb.ilookup(50).is_none(), "no names + no refs → inode retired (evicted)");
}

// Unlinking the last name while an open File still pins the inode must NOT evict
// early; eviction is driven by the LAST `iput`, exactly once (no double-evict).
#[test]
fn last_unlink_with_open_fd_defers_eviction() {
    let _g = guard();
    let sb = mount_ramfs(2);
    let root = vfs::d_make_root(ramdir(&sb, 2), &sb);

    let inode: InodeRef = ramfile(&sb, 60, 1);
    let d = vfs::d_add(&root, "f", inode.clone());            // born1 + alias = 2
    let file = vfs::File::new(inode.clone(), d.clone(), vfs::OpenFlags::O_RDWR); // +file = 3
    vfs::file::iput(inode.clone());                            // release born: 3 → 2
    assert_eq!(inode.i_count(), 2, "alias + open file");

    // Unlink the only name: nlink → 0, alias dropped, but the open fd holds it.
    let last = d_unlink(&d);
    assert!(last, "the sole name was the last");
    assert_eq!(inode.nlink(), 0, "no names remain");
    assert_eq!(inode.i_count(), 1, "open file still pins the inode");
    assert!(sb.ilookup(60).is_some(), "unlinked-but-open inode not evicted early");

    // Last close → final iput → drop_inode(nlink 0, count 0) → evict, once.
    drop(file);
    assert!(sb.ilookup(60).is_none(), "last close retires the unlinked inode");
}
