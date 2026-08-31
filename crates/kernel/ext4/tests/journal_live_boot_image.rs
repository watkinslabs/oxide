//! A journalled root filesystem under the boot's own journal workload.
//!
//! The shipped rootfs is built without a journal, so a killed VM leaves torn
//! metadata that no recovery can undo and every later boot inherits. Turning
//! the journal on is the fix, and these cases are the workload that has to
//! survive it: a ~14 MB database rewritten early in sysinit, flushed through
//! the frame store, while the periodic journal owner commits and checkpoints
//! on its own thread. Ordered-mode data submission running outside the
//! transaction gate lost one cluster's block-bitmap update per few runs --
//! an extent pointing at blocks the bitmap calls free.
//!
//! Skips (passes) when the boot image, `tune2fs` or `e2fsck` are absent so CI
//! stays green.

extern crate alloc;
mod common;

use alloc::sync::Arc;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::Command;
use std::sync::Mutex;

use block::{BlockDevice, BlockOp, BlockRequest, KResult};

const SECTOR: u32 = 512;

struct RwFileDisk { f: Mutex<File>, cap: u64 }

impl BlockDevice for RwFileDisk {
    fn block_size(&self) -> u32 { SECTOR }
    fn capacity_blocks(&self) -> u64 { self.cap }
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        let off = req.start_block * SECTOR as u64;
        let len = (req.len_blocks * SECTOR) as usize;
        let mut f = self.f.lock().unwrap();
        f.seek(SeekFrom::Start(off)).unwrap();
        match req.op {
            BlockOp::Read => {
                if req.buffer.len() < len { req.buffer.resize(len, 0); }
                f.read_exact(&mut req.buffer[..len]).unwrap();
            }
            BlockOp::Write => { f.write_all(&req.buffer[..len]).unwrap(); }
            _ => {}
        }
        Ok(())
    }
    fn flush(&self) -> KResult<()> { self.f.lock().unwrap().flush().unwrap(); Ok(()) }
}

fn have(tool: &str) -> bool { Command::new(tool).arg("-V").output().is_ok() }

fn scratch(tag: &str) -> std::path::PathBuf {
    let mut d = std::env::temp_dir();
    d.push(std::format!("oxide-ext4-ialloc-uninit-{}-{tag}.img", std::process::id()));
    d
}

/// Build a two-group image whose second group mkfs leaves `INODE_UNINIT`.
fn fsck(path: &std::path::Path) -> (bool, std::string::String) {
    let out = Command::new("e2fsck").arg("-fn").arg(path).output().expect("e2fsck");
    let s = std::format!("{}{}",
        std::string::String::from_utf8_lossy(&out.stdout),
        std::string::String::from_utf8_lossy(&out.stderr));
    (out.status.success(), s)
}

fn open_rw(path: &std::path::Path) -> ext4::Mount {
    let f = OpenOptions::new().read(true).write(true).open(path).unwrap();
    let cap = f.metadata().unwrap().len() / SECTOR as u64;
    let disk: Arc<dyn BlockDevice> = Arc::new(RwFileDisk { f: Mutex::new(f), cap });
    ext4::Mount::open(disk).expect("mount")
}


/// A journalled copy of the real boot rootfs, the configuration the shipped
/// image does NOT use and that a boot cannot currently survive.
fn journalled_boot_image(tag: &str) -> Option<std::path::PathBuf> {
    let src = std::env::var("OXIDE_EXT4_BOOT_IMG")
        .unwrap_or_else(|_| std::string::String::from("/home/nd/oxide/images/out/gnome-x86_64-root.img"));
    if File::open(&src).is_err() { eprintln!("SKIP: no boot image at {src}"); return None; }
    if !have("e2fsck") { eprintln!("SKIP: e2fsck absent"); return None; }
    let path = scratch(tag);
    let _ = std::fs::remove_file(&path);
    std::fs::copy(&src, &path).expect("copy boot image");
    let st = Command::new("tune2fs").arg("-O").arg("has_journal").arg(&path).status().ok()?;
    if !st.success() { eprintln!("SKIP: tune2fs could not add a journal"); return None; }
    let (ok, log) = fsck(&path);
    assert!(ok, "journalled copy is dirty before any writing:\n{log}");
    Some(path)
}

/// `systemd-hwdb` rewrites a ~13.5 MB database early in every boot, and on a
/// journalled rootfs that write is the first thing to fail with EIO. One
/// writeback of that size is one transaction; the journal has to carry it.
#[test]
fn a_large_database_write_survives_on_a_journalled_boot_image() {
    let Some(path) = journalled_boot_image("hwdb") else { return };
    {
        let m = open_rw(&path);
        m.begin_batch();
        let _ = m.mark_state_dirty();
        let etc = m.lookup_path(b"/etc/udev").expect("/etc/udev");
        let ino = m.create_file(etc, b"hwdb.test.bin", 0o644, 0, 0).expect("create");
        // The real database, in the same shape the writeback issues it: a run
        // of adjacent cluster-sized chunks appended to one growing file.
        let chunk = std::vec![0x7Eu8; 128 * 1024];
        let total = 14 * 1024 * 1024usize;
        let mut off = 0u64;
        while (off as usize) < total {
            m.write_at(ino, off, &chunk)
                .unwrap_or_else(|e| panic!("write at {off} of {total}: {e:?}"));
            off += chunk.len() as u64;
        }
        m.commit_batch().expect("commit batch");
    }
    let (ok, log) = fsck(&path);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "journalled boot image inconsistent after the database write:\n{log}");
}

/// The path the boot actually takes: buffered writes into the frame store,
/// then one writeback. `writeback_idxs` puts every dirty page of that
/// writeback into a single deferred transaction, so this is where a journal
/// large enough for the file still has to be large enough for the flush.
#[test]
fn a_large_buffered_writeback_survives_on_a_journalled_boot_image() {
    let Some(path) = journalled_boot_image("writeback") else { return };
    common::boot_hosted_pmm();
    {
        let f = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let cap = f.metadata().unwrap().len() / SECTOR as u64;
        let dev: Arc<dyn BlockDevice> = Arc::new(RwFileDisk { f: Mutex::new(f), cap });
        let m = ext4::rootfs::Ext4Mount::open(dev).expect("mount through the VFS layer");
        let fs: Arc<dyn vfs::fs::FileSystem> = m.clone();
        let root = fs.root();
        let _sb = common::realize_sb(fs.clone(), root, 0xE471_0DB2, alloc::string::String::from("ext4"));
        // The boot mounts with cross-operation batching on.
        m.state().mount.begin_batch();
        let st = m.state();
        let dir = st.lookup_path(b"/etc/udev").expect("/etc/udev");
        let ino = st.mount.create_file(dir, b"hwdb.test.bin", 0o644, 0, 0).expect("create");
        let file = st.wrap_file(ino).expect("wrap");
        let chunk = std::vec![0x7Eu8; 64 * 1024];
        let total = 14 * 1024 * 1024u64;
        let mut off = 0u64;
        while off < total {
            file.write(off, &chunk).unwrap_or_else(|e| panic!("buffered write at {off}: {e:?}"));
            off += chunk.len() as u64;
        }
        file.i_mapping().expect("mapping")
            .writeback().unwrap_or_else(|e| panic!("writeback of {total} bytes: {e:?}"));
        st.mount.commit_batch().expect("commit batch");
    }
    let (ok, log) = fsck(&path);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "journalled boot image inconsistent after a large buffered writeback:\n{log}");
}

/// The boot runs the periodic journal owner alongside every mutator: it
/// checkpoints the previous pass's home blocks and commits the running batch
/// on its own thread. A hosted writeback that never sees that owner is not
/// the boot's journal workload.
#[test]
fn a_large_writeback_survives_the_periodic_journal_owner() {
    let Some(path) = journalled_boot_image("periodic") else { return };
    common::boot_hosted_pmm();
    {
        let f = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let cap = f.metadata().unwrap().len() / SECTOR as u64;
        let dev: Arc<dyn BlockDevice> = Arc::new(RwFileDisk { f: Mutex::new(f), cap });
        let m = ext4::rootfs::Ext4Mount::open(dev).expect("mount through the VFS layer");
        let fs: Arc<dyn vfs::fs::FileSystem> = m.clone();
        let root = fs.root();
        let _sb = common::realize_sb(fs.clone(), root, 0xE471_0DB3, alloc::string::String::from("ext4"));
        m.state().mount.begin_batch();
        let mount = m.state().mount.clone();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        ext4::commit_timer::register(&mount);
        let owner = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                // The timer's own monotonic base, advanced fast enough that
                // every pass is due.
                let mut now = 1u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    now = now.saturating_add(10_000_000_000);
                    ext4::commit_timer::tick(now);
                    std::thread::yield_now();
                }
            })
        };
        let st = m.state();
        let dir = st.lookup_path(b"/etc/udev").expect("/etc/udev");
        let mut failure: Option<alloc::string::String> = None;
        'files: for n in 0..3u32 {
            let name = std::format!("hwdb.test.{n}.bin");
            let ino = st.mount.create_file(dir, name.as_bytes(), 0o644, 0, 0).expect("create");
            let Some(file) = st.wrap_file(ino) else { failure = Some(std::format!("{name}: wrap")); break };
            let chunk = std::vec![0x7Eu8; 64 * 1024];
            let total = 14 * 1024 * 1024u64;
            let mut off = 0u64;
            while off < total {
                if let Err(e) = file.write(off, &chunk) {
                    failure = Some(std::format!("{name}: buffered write at {off}: {e:?}"));
                    break 'files;
                }
                off += chunk.len() as u64;
            }
            if let Err(e) = file.i_mapping().expect("mapping").writeback() {
                failure = Some(std::format!("{name}: writeback: {e:?}"));
                break;
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        owner.join().expect("periodic owner");
        let commit = mount.commit_batch();
        if let Some(f) = failure { let _ = std::fs::remove_file(&path); panic!("{f}"); }
        commit.expect("commit batch");
    }
    let (ok, log) = fsck(&path);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "journalled boot image inconsistent after concurrent commit/checkpoint:\n{log}");
}

/// Same workload one layer down, where the filesystem's own error survives:
/// the writeback owner turns every failure into one opaque errno, so the
/// reason a boot's large write fails is only visible here.
#[test]
fn the_periodic_owner_does_not_break_a_large_extent_write() {
    let Some(path) = journalled_boot_image("periodic-raw") else { return };
    let outcome = {
        let m = Arc::new(open_rw(&path));
        m.begin_batch();
        let _ = m.mark_state_dirty();
        ext4::commit_timer::register(&m);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let owner = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut now = 1u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    now = now.saturating_add(10_000_000_000);
                    ext4::commit_timer::tick(now);
                    std::thread::yield_now();
                }
            })
        };
        let dir = m.lookup_path(b"/etc/udev").expect("/etc/udev");
        let chunk = std::vec![0x7Eu8; 128 * 1024];
        let mut outcome = Ok(());
        'files: for n in 0..3u32 {
            let name = std::format!("hwdb.raw.{n}.bin");
            let ino = m.create_file(dir, name.as_bytes(), 0o644, 0, 0).expect("create");
            let mut off = 0u64;
            while off < 14 * 1024 * 1024 {
                if let Err(e) = m.write_at(ino, off, &chunk) {
                    outcome = Err(std::format!("{name} at {off}: {e:?}"));
                    break 'files;
                }
                off += chunk.len() as u64;
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        owner.join().expect("periodic owner");
        let _ = m.commit_batch();
        outcome
    };
    let _ = std::fs::remove_file(&path);
    outcome.unwrap_or_else(|e| panic!("large extent write under the periodic owner: {e}"));
}
