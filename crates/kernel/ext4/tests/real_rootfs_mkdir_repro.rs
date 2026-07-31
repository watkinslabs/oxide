//! DIAGNOSTIC (env-gated, #[ignore]'d, never in CI): open the REAL boot rootfs
//! image and reproduce the boot's `mkdir /var/log/journal/<machine-id> err=5`
//! (journald) with the TRUE MountError — the boot swallows it as EIO. Run with:
//!   OXIDE_ROOTFS_IMG=../images/output/live-gnome-x86_64-root.img \
//!     cargo test -p ext4 --test real_rootfs_mkdir_repro -- --ignored --nocapture
//! Skips cleanly if the env var is unset or the file is absent.

extern crate alloc;
mod common;
use alloc::sync::Arc;
use alloc::string::String;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const SECTOR: u32 = 512;

fn open_real() -> Option<(Arc<dyn BlockDevice>, ext4::Mount)> {
    let path = std::env::var("OXIDE_ROOTFS_IMG").ok()?;
    let bytes = std::fs::read(&path).ok()?;
    eprintln!("loaded {} ({} bytes)", path, bytes.len());
    let cap = (bytes.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: bytes, ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    let dev: Arc<dyn BlockDevice> = disk;
    let m = ext4::Mount::open(dev.clone()).expect("open real rootfs ext4");
    Some((dev, m))
}

#[test]
#[ignore]
fn real_journald_var_log_journal_mkdir() {
    let Some((_d, m)) = open_real() else { eprintln!("SKIP: set OXIDE_ROOTFS_IMG"); return; };
    // Resolve /var/log/journal (must exist in the image; journald pre-req).
    let vlj = match m.lookup_path(b"/var/log/journal") {
        Ok(ino) => { eprintln!("/var/log/journal ino={ino}"); ino }
        Err(e) => { eprintln!("/var/log/journal lookup: {e:?} — trying /var/log");
            match m.lookup_path(b"/var/log") { Ok(i)=>{eprintln!("/var/log ino={i}");
                m.create_dir(i, b"journal", 0o755, 0, 0).unwrap_or_else(|e| panic!("mkdir /var/log/journal: {e:?}"))
            } Err(e2)=>panic!("/var/log missing too: {e2:?}") } }
    };
    // The exact boot mkdir — surface the REAL MountError (boot showed EIO).
    let mid = "fa52435e5fe94e5cbb8bff1a050ba889";
    match m.create_dir(vlj, mid.as_bytes(), 0o755, 0, 0) {
        Ok(ino) => eprintln!("OK: created /var/log/journal/{mid} ino={ino}"),
        Err(e) => panic!("REPRO: mkdir /var/log/journal/{mid} -> {e:?} (the boot's swallowed EIO)"),
    }
}

/// The boot's rootfs mount runs with cross-op BATCHING enabled (framecache
/// flush drains one running jbd2 transaction). The pristine-image mkdir succeeds
/// per-op; reproduce the boot by enabling batching and creating a chain +
/// siblings in ONE running transaction (read-your-writes across the batch), then
/// commit + remount and verify. If create fails or the remount can't see it,
/// that's the batching bug behind the boot's `mkdir ... err=5`.
#[test]
#[ignore]
fn real_journal_mkdir_under_batching() {
    let Some((disk, m)) = open_real() else { eprintln!("SKIP: set OXIDE_ROOTFS_IMG"); return; };
    let vlj = m.lookup_path(b"/var/log/journal")
        .or_else(|_| m.lookup_path(b"/var/log").and_then(|i| m.create_dir(i, b"journal", 0o755, 0, 0)))
        .expect("/var/log/journal");
    m.begin_batch();
    let mid = "fa52435e5fe94e5cbb8bff1a050ba889";
    let leaf = match m.create_dir(vlj, mid.as_bytes(), 0o755, 0, 0) {
        Ok(i) => { eprintln!("batched mkdir /var/log/journal/{mid} ino={i}"); i }
        Err(e) => panic!("REPRO (batched): mkdir /var/log/journal/{mid} -> {e:?}"),
    };
    // journald then creates files INSIDE the machine-id dir in the same session.
    for i in 0..8 {
        let n = alloc::format!("system@{i:016x}.journal");
        match m.create_file(leaf, n.as_bytes(), 0o640, 0, 0) {
            Ok(_) => {}
            Err(e) => panic!("REPRO (batched): create {n} in fresh dir -> {e:?}"),
        }
    }
    m.commit_batch().expect("commit_batch");
    // Remount: everything must be on disk and consistent.
    drop(m);
    let m2 = ext4::Mount::open(disk).expect("remount");
    let l2 = m2.lookup_path(alloc::format!("/var/log/journal/{mid}").as_bytes())
        .unwrap_or_else(|e| panic!("REPRO: journal dir lost across remount: {e:?}"));
    assert_eq!(l2, leaf, "machine-id dir persisted");
    for i in 0..8 {
        let n = alloc::format!("/var/log/journal/{mid}/system@{i:016x}.journal");
        m2.lookup_path(n.as_bytes()).unwrap_or_else(|e| panic!("REPRO: journal file #{i} lost: {e:?}"));
    }
    eprintln!("OK: batched journal tree persisted across remount");
}

/// True for "the filesystem is legitimately out of room" — a clean stop for a
/// stress phase, NOT a bug. Anything else (Dir/BlockIo/Inode/Gdt/checksum/...)
/// is a genuine backend fault we want to CATCH.
fn is_capacity(e: &ext4::MountError) -> bool {
    matches!(e, ext4::MountError::NoSpace | ext4::MountError::DirFull)
}

/// HEAVY metadata churn on the REAL rootfs under BATCHING (the boot's mount mode)
/// to drive the fs into the mutated runtime state where the boot's
/// `mkdir /var/log/journal/<id> err=5` fires, then do that exact mkdir + verify
/// integrity across a remount. Every op must succeed OR fail with a capacity
/// error; any Dir/BlockIo/Inode/checksum fault panics with the true variant.
#[test]
#[ignore]
fn real_rootfs_metadata_stress_then_journal_mkdir() {
    let Some((disk, m)) = open_real() else { eprintln!("SKIP: set OXIDE_ROOTFS_IMG"); return; };
    let root = m.lookup_path(b"/").unwrap_or(2);
    let base = match m.create_dir(root, b"stress", 0o755, 0, 0) {
        Ok(i) => i,
        Err(ref e) if is_capacity(e) => { eprintln!("SKIP: no room for /stress"); return; }
        Err(e) => panic!("mkdir /stress -> {e:?}"),
    };
    m.begin_batch();
    let mut dirs: alloc::vec::Vec<u32> = alloc::vec![base];
    let mut made = 0usize;
    let mut ops = 0usize;
    let mut stopped_capacity = false;
    // Churn: create dirs, files inside them, symlinks, hardlinks; periodically
    // delete a subtree of files to recycle inodes/blocks (bitmap churn). Bounded
    // so a big image doesn't run forever.
    'outer: for round in 0..40 {
        // Pick a parent (round-robins across the growing dir set).
        let parent = dirs[round % dirs.len().max(1)];
        // 30 subdirs this round.
        for d in 0..30 {
            let name = alloc::format!("d_{round:02}_{d:02}");
            match m.create_dir(parent, name.as_bytes(), 0o755, 0, 0) {
                Ok(i) => { dirs.push(i); made += 1; ops += 1; }
                Err(ref e) if is_capacity(e) => { stopped_capacity = true; break 'outer; }
                Err(e) => panic!("stress mkdir {name} (round {round}) -> {e:?}"),
            }
            let dino = *dirs.last().unwrap();
            // 12 files in each fresh dir (fills the dir block -> growth path).
            for f in 0..12 {
                let fname = alloc::format!("f_{f:02}.dat");
                match m.create_file(dino, fname.as_bytes(), 0o644, 0, 0) {
                    Ok(_) => { ops += 1; }
                    Err(ref e) if is_capacity(e) => { stopped_capacity = true; break 'outer; }
                    Err(e) => panic!("stress create_file {fname} in d {dino} -> {e:?}"),
                }
            }
            // A fast + slow symlink.
            let _ = m.create_symlink(dino, b"sl", b"../..", 0, 0);
            let long = alloc::format!("/very/deep/{}/x", "seg/".repeat(16));
            match m.create_symlink(dino, b"ln", long.as_bytes(), 0, 0) {
                Ok(_) | Err(ext4::MountError::NoSpace) | Err(ext4::MountError::DirFull) => {}
                Err(e) => panic!("stress create_symlink slow -> {e:?}"),
            }
        }
        // Every few rounds, delete some files to churn the bitmaps.
        if round % 5 == 4 {
            if let Some(&victim_dir) = dirs.get(dirs.len().saturating_sub(3)) {
                for f in 0..12 {
                    let fname = alloc::format!("f_{f:02}.dat");
                    match m.unlink(victim_dir, fname.as_bytes()) {
                        // No VFS above this raw-`Mount` driver, so the test is
                        // the last reference and runs the eviction itself.
                        Ok(out) => if out.orphaned() { let _ = m.free_orphan_inode(out.ino); },
                        Err(ext4::MountError::NotFound) => {}
                        Err(e) => panic!("stress unlink {fname} -> {e:?}"),
                    }
                }
            }
        }
        // Periodic durability trigger (jbd2 commit), like fsync during boot.
        if round % 8 == 7 { m.commit_batch().unwrap_or_else(|e| panic!("commit_batch round {round} -> {e:?}")); }
    }
    eprintln!("churn done: made {made} dirs, {ops} ops, stopped_capacity={stopped_capacity}");

    // THE boot op, now against the churned fs: mkdir /var/log/journal/<id>.
    let vlj = m.lookup_path(b"/var/log/journal")
        .or_else(|_| m.lookup_path(b"/var/log").and_then(|i| m.create_dir(i, b"journal", 0o755, 0, 0)))
        .unwrap_or_else(|e| panic!("/var/log/journal after churn: {e:?}"));
    let mid = "fa52435e5fe94e5cbb8bff1a050ba889";
    match m.create_dir(vlj, mid.as_bytes(), 0o755, 0, 0) {
        Ok(i) => eprintln!("OK: journald mkdir succeeded post-churn ino={i}"),
        Err(ref e) if is_capacity(e) => eprintln!("journald mkdir hit capacity ({e:?}) — expected on a full image"),
        Err(e) => panic!("REPRO: mkdir /var/log/journal/{mid} post-churn -> {e:?} (the boot EIO)"),
    }
    m.commit_batch().expect("final commit_batch");

    // Integrity: remount and confirm the tree is walkable (no corruption).
    drop(m);
    let m2 = ext4::Mount::open(disk).expect("remount after stress");
    m2.lookup_path(b"/stress").unwrap_or_else(|e| panic!("REPRO: /stress lost/corrupt after remount: {e:?}"));
    eprintln!("OK: remount clean after metadata stress");
}

/// Drive the boot's ACTUAL VFS path — `RootfsState::mkdir_at`/`write_file`/
/// `symlink_at`/`rename_at`/`unlink_at` over the framecache-backed Ext4Mount —
/// against the real rootfs, mirroring journald+tmpfiles+udev's mixed workload
/// (mkdir the journal tree, write files into it, rename, unlink), then reopen
/// and verify. This is the layer above raw Mount that the boot uses; a
/// framecache/VFS-path bug that the low-level API can't see surfaces here.
#[test]
#[ignore]
fn real_rootfs_vfs_path_journald_workload() {
    common::boot_hosted_pmm();
    let path = match std::env::var("OXIDE_ROOTFS_IMG") { Ok(p) => p, Err(_) => { eprintln!("SKIP: set OXIDE_ROOTFS_IMG"); return; } };
    let bytes = match std::fs::read(&path) { Ok(b) => b, Err(_) => { eprintln!("SKIP: image unreadable"); return; } };
    let cap = (bytes.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: bytes, ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("open real rootfs (VFS layer)");
    let st = m.state();

    // journald: mkdir the persistent journal dir tree via the VFS path.
    let mid = "fa52435e5fe94e5cbb8bff1a050ba889";
    let jdir = alloc::format!("/var/log/journal/{mid}");
    let _ = st.mkdir_at(b"/var/log", 0o755);          // may already exist
    let _ = st.mkdir_at(b"/var/log/journal", 0o755);
    match st.mkdir_at(jdir.as_bytes(), 0o755) {
        Ok(()) => eprintln!("OK: VFS mkdir_at {jdir}"),
        Err(e) => panic!("REPRO (VFS path): mkdir_at {jdir} -> {e:?} (the boot EIO)"),
    }
    // tmpfiles/journald metadata churn through the VFS path (the boot's ops):
    // nested mkdir, symlink, rename, unlink — each must not EIO.
    for sub in ["a", "b", "c"] {
        let d = alloc::format!("{jdir}/{sub}");
        st.mkdir_at(d.as_bytes(), 0o755).unwrap_or_else(|e| panic!("REPRO (VFS): mkdir_at {d} -> {e:?}"));
    }
    st.symlink_at(b"a", alloc::format!("{jdir}/cur").as_bytes())
        .unwrap_or_else(|e| panic!("REPRO (VFS): symlink_at -> {e:?}"));
    match st.rename_at(alloc::format!("{jdir}/a").as_bytes(), alloc::format!("{jdir}/a2").as_bytes()) {
        Ok(()) | Err(vfs::VfsError::Enoent) => {}
        Err(e) => panic!("REPRO (VFS): rename_at -> {e:?}"),
    }
    match st.unlink_at(alloc::format!("{jdir}/cur").as_bytes()) {
        Ok(()) | Err(vfs::VfsError::Enoent) => {}
        Err(e) => panic!("REPRO (VFS): unlink_at -> {e:?}"),
    }
    // Overwrite an EXISTING small regular file via the framecache write path
    // (write_file is a single-block overwrite helper; pick a file that exists).
    for cand in [&b"/etc/hostname"[..], b"/etc/machine-id", b"/etc/os-release"] {
        if let Some(orig) = st.read_file(cand) {
            if orig.is_empty() { continue; }
            // Overwrite the first byte (write_file is a single-block, non-growing
            // overwrite helper), then confirm the framecache read sees it.
            let mut data = orig.clone();
            data[0] ^= 0xFF;
            match st.write_file(cand, &data) {
                Some(()) => {
                    let back = st.read_file(cand).expect("read-back after write");
                    assert_eq!(back[0], data[0], "framecache write visible to read");
                    eprintln!("OK: framecache write+read coherent on an existing file");
                }
                None => panic!("REPRO (VFS): write_file returned None on an existing regular file"),
            }
            break;
        }
    }
    let _ = ext4::rootfs::flush_all_dirty();
    eprintln!("OK: VFS-path journald workload clean");
}

#[test]
#[ignore]
fn real_run_udev_mkdir() {
    let Some((_d, m)) = open_real() else { eprintln!("SKIP: set OXIDE_ROOTFS_IMG"); return; };
    // /run is normally tmpfs at boot, but reproduce a mkdir at the ext4 /run dir
    // (the underlay udevd may land on). First show what /run resolves to.
    match m.lookup_path(b"/run") {
        Ok(ino) => {
            eprintln!("/run ino={ino}");
            match m.create_dir(ino, b"udev", 0o755, 0, 0) {
                Ok(c) => eprintln!("OK: created /run/udev ino={c}"),
                Err(e) => eprintln!("REPRO: mkdir /run/udev -> {e:?}"),
            }
        }
        Err(e) => eprintln!("/run lookup: {e:?}"),
    }
}

#[test]
#[ignore]
fn real_hwdb_tmpfile_publish() {
    common::boot_hosted_pmm();
    let path = match std::env::var("OXIDE_ROOTFS_IMG") { Ok(p) => p, Err(_) => { eprintln!("SKIP: set OXIDE_ROOTFS_IMG"); return; } };
    let bytes = match std::fs::read(&path) { Ok(b) => b, Err(_) => { eprintln!("SKIP: image unreadable"); return; } };
    let cap = (bytes.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: bytes, ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("open real rootfs");
    m.state().mount.begin_batch();
    let fs: Arc<dyn vfs::fs::FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xE471_0DB0, String::from("ext4"));
    let udev = m.state().lookup_inode_any(b"/etc/udev").expect("lookup /etc/udev");
    let old = udev.lookup("hwdb.bin").expect("existing hwdb.bin");
    let tmp = udev.tmpfile(0o640, &vfs::CreateCtx::root()).expect("create hwdb tmpfile");
    tmp.set_state(vfs::I_LINKABLE, 0);
    let mut newer = alloc::vec::Vec::new();
    for _ in 0..8 {
        newer.push(udev.tmpfile(0o600, &vfs::CreateCtx::root()).expect("create newer orphan"));
    }
    tmp.setattr(&vfs::IDENTITY, &vfs::Iattr {
        valid: vfs::ATTR_MODE,
        mode: 0o444,
        ..Default::default()
    }).expect("chmod anonymous hwdb");
    let payload = alloc::vec![0x48; 13_635_836];
    let dentry = vfs::Dentry::new(None, String::from("(hwdb)"), tmp.clone());
    let file = vfs::File::new(tmp.clone(), dentry, vfs::OpenFlags::O_WRONLY);
    assert_eq!(file.write(&payload).expect("buffer hwdb payload"), payload.len());
    tmp.i_mapping().expect("hwdb mapping").writeback().expect("write back hwdb payload");
    sb.sync_fs(true).expect("sync hwdb payload");

    assert_eq!(tmp.nlink(), 0, "anonymous hwdb starts unlinked");
    assert_eq!(udev.link_child(&tmp, "hwdb.bin", &vfs::CreateCtx::root()), Err(vfs::VfsError::Eexist));
    udev.link_child(&tmp, ".#hwdb.tmp", &vfs::CreateCtx::root()).expect("link temporary hwdb name");
    udev.rename_child(".#hwdb.tmp", &udev, "hwdb.bin", 0, &vfs::CreateCtx::root()).expect("replace hwdb.bin");
    assert_eq!(old.nlink(), 0);
    assert_eq!(udev.lookup("hwdb.bin").expect("published hwdb").ino(), tmp.ino());
    drop(newer);
    drop(file);
    drop(sb);
}
