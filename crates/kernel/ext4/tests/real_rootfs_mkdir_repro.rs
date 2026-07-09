//! DIAGNOSTIC (env-gated, #[ignore]'d, never in CI): open the REAL boot rootfs
//! image and reproduce the boot's `mkdir /var/log/journal/<machine-id> err=5`
//! (journald) with the TRUE MountError — the boot swallows it as EIO. Run with:
//!   OXIDE_ROOTFS_IMG=../images/output/live-gnome-x86_64-root.img \
//!     cargo test -p ext4 --test real_rootfs_mkdir_repro -- --ignored --nocapture
//! Skips cleanly if the env var is unset or the file is absent.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const SECTOR: u32 = 512;

fn open_real() -> Option<(Arc<dyn BlockDevice>, ext4::Mount)> {
    let path = std::env::var("OXIDE_ROOTFS_IMG").ok()?;
    let bytes = std::fs::read(&path).ok()?;
    eprintln!("loaded {} ({} bytes)", path, bytes.len());
    let cap = (bytes.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: bytes };
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
