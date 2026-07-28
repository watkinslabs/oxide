//! DIAGNOSTIC (env-gated, `#[ignore]`d, never in CI): reproduce the boot's
//! `[NAMEI] openat-create path="/var/log/journal/<id>/user-1000.journal" err=5`.
//! `openat` reports whatever `create_child` returns, and ext4's `create` ends
//! `wrap_file(ino).ok_or(VfsError::Eio)` — so EIO means `create_file` allocated
//! the inode and `read_inode` could not read it back. Drive the SAME VFS path
//! (realized SB, batching on, like the boot) and surface the true `MountError`.
//!   OXIDE_ROOTFS_IMG=../images/output/live-gnome-x86_64-root.img \
//!     cargo test -p ext4 --test journal_create_eio_repro -- --ignored --nocapture

extern crate alloc;
mod common;
use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const SECTOR: u32 = 512;
const MACHINE_ID: &str = "fa52435e5fe94e5cbb8bff1a050ba889";

fn open_vfs() -> Option<(Arc<ext4::rootfs::Ext4Mount>, Arc<vfs::SuperBlock>)> {
    common::boot_hosted_pmm();
    let path = std::env::var("OXIDE_ROOTFS_IMG").ok()?;
    let bytes = std::fs::read(&path).ok()?;
    eprintln!("loaded {} ({} bytes)", path, bytes.len());
    let cap = (bytes.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: bytes };
    disk.submit_sync(&mut req).unwrap();
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("open real rootfs (VFS layer)");
    // The boot mounts with cross-op batching enabled.
    m.state().mount.begin_batch();
    let fs: Arc<dyn vfs::fs::FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xE471_0DB1, String::from("ext4"));
    Some((m, sb))
}

/// Report the RAW backend result for `ino` so a `wrap_file` `None` is
/// attributable: which of the two `None` arms fired, and with what error.
fn explain(m: &ext4::rootfs::Ext4Mount, ino: u32, what: &str) {
    match m.state().mount.read_inode(ino) {
        Ok(i) => eprintln!("  {what}: read_inode(ino={ino}) OK mode={:#o} is_reg={} nlink={} size={}",
                           i.mode, i.is_reg(), i.links_count, i.size),
        Err(e) => eprintln!("  {what}: read_inode(ino={ino}) -> {e:?}  <-- wrap_file arm 1"),
    }
}

/// journald's create, through the exact VFS entry `openat(O_CREAT)` uses.
#[test]
#[ignore]
fn journald_user_journal_create_via_vfs() {
    let Some((m, _sb)) = open_vfs() else { eprintln!("SKIP: set OXIDE_ROOTFS_IMG"); return; };
    let st = m.state();
    let jdir = alloc::format!("/var/log/journal/{MACHINE_ID}");
    let _ = st.mkdir_at(b"/var/log", 0o755);
    let _ = st.mkdir_at(b"/var/log/journal", 0o755);
    let _ = st.mkdir_at(jdir.as_bytes(), 0o755);
    let dir = st.lookup_inode_any(jdir.as_bytes()).expect("journal dir inode");
    let ctx = vfs::CreateCtx::root();
    // journald creates system.journal, then user-<uid>.journal, plus rotations.
    for name in ["system.journal", "user-1000.journal"] {
        match dir.create_child(name, 0o640, &ctx) {
            Ok(i) => eprintln!("OK: created {jdir}/{name} ino={}", i.ino()),
            Err(e) => {
                eprintln!("REPRO: create {jdir}/{name} -> {e:?}");
                if let Some(ino) = st.lookup_child_ino(dir_ino(&dir), name) { explain(&m, ino, name); }
                panic!("REPRO: create {jdir}/{name} -> {e:?} (the boot's err=5)");
            }
        }
    }
}

fn dir_ino(i: &vfs::InodeRef) -> u32 { (i.ino() & 0xFFFF_FFFF) as u32 }

/// journald rotates: create → write → unlink → create again, many times, which
/// recycles inode numbers through the bitmap. A recycled ino whose table slot
/// or cached SB inode is stale is exactly the shape that makes `wrap_file`
/// return `None` for one create and not the next.
#[test]
#[ignore]
fn journald_rotation_churn_create_wrap() {
    let Some((m, _sb)) = open_vfs() else { eprintln!("SKIP: set OXIDE_ROOTFS_IMG"); return; };
    let st = m.state();
    let jdir = alloc::format!("/var/log/journal/{MACHINE_ID}");
    let _ = st.mkdir_at(b"/var/log", 0o755);
    let _ = st.mkdir_at(b"/var/log/journal", 0o755);
    let _ = st.mkdir_at(jdir.as_bytes(), 0o755);
    let dir = st.lookup_inode_any(jdir.as_bytes()).expect("journal dir inode");
    let ctx = vfs::CreateCtx::root();
    for round in 0..64u32 {
        let name = alloc::format!("user-1000@{round:08x}.journal");
        let created = match dir.create_child(&name, 0o640, &ctx) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("REPRO: round {round} create {name} -> {e:?}");
                panic!("REPRO (rotation round {round}): create {name} -> {e:?}");
            }
        };
        assert!(created.ino() != 0, "created inode has an ino");
        // Rotate: unlink every other one so inode numbers recycle.
        if round % 2 == 1 {
            let prev = alloc::format!("user-1000@{:08x}.journal", round - 1);
            match dir.unlink_child(&prev) {
                Ok(()) | Err(vfs::VfsError::Enoent) => {}
                Err(e) => panic!("rotation unlink {prev} -> {e:?}"),
            }
        }
        if round % 16 == 15 { m.state().mount.commit_batch().expect("commit_batch"); }
    }
    eprintln!("OK: 64 rotation rounds, no wrap_file failure");
}
