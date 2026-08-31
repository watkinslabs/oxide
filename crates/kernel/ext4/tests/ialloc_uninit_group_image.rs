//! Inode allocation that crosses into an `EXT4_BG_INODE_UNINIT` group must
//! leave the group descriptors, inode bitmap and superblock counters in the
//! state e2fsck expects, and the freshly allocated inode must read back.
//!
//! The boot rootfs has only a handful of free inodes below its first lazily
//! initialised group, so every boot's early service directories allocate
//! across that boundary. When the crossing loses the descriptor update the
//! directory entry still lands, the new inode reads back as an unused table
//! slot, and the create reports EIO -- which is what stops `PrivateTmp=`
//! services (resolved, dbus-broker, logind) from starting.
//!
//! Skips (passes) when `mke2fs`/`e2fsck` are absent so CI stays green.

extern crate alloc;
mod common;

use alloc::sync::Arc;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::Command;
use std::sync::Mutex;

use block::{BlockDevice, BlockOp, BlockRequest, KResult};

const SECTOR: u32 = 512;
/// Two groups, 256 inodes each; group 1 is left `INODE_UNINIT` by mkfs.
const IMAGE_BYTES: &str = "256M";
const INODES: &str = "512";

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
fn build_image(tag: &str) -> Option<std::path::PathBuf> { build_image_with(tag, "metadata_csum,64bit") }

fn build_image_with(tag: &str, features: &str) -> Option<std::path::PathBuf> {
    if !have("mke2fs") || !have("e2fsck") { eprintln!("SKIP: mke2fs/e2fsck absent"); return None; }
    let path = scratch(tag);
    let _ = std::fs::remove_file(&path);
    let st = Command::new("truncate").arg("-s").arg(IMAGE_BYTES).arg(&path).status().ok()?;
    if !st.success() { return None; }
    let st = Command::new("mke2fs")
        .args(["-q", "-t", "ext4", "-O", features, "-I", "256", "-b", "4096", "-N", INODES])
        .arg(&path).status().ok()?;
    if !st.success() { return None; }
    let (ok, log) = fsck(&path);
    assert!(ok, "freshly built image is dirty:\n{log}");
    Some(path)
}

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

/// Fill the initialised group's inodes so allocation crosses into the
/// `INODE_UNINIT` group, then check both what the caller saw and what the
/// filesystem recorded.
#[test]
fn allocation_crossing_into_an_uninit_group_stays_consistent() {
    let Some(path) = build_image("cross") else { return };
    let created = {
        let m = open_rw(&path);
        let ipg = m.sb.inodes_per_group;
        assert!(m.sb.group_count() >= 2, "fixture must have a second group");
        let dir = m.create_dir(2, b"cross", 0o755, 0, 0).expect("scratch dir");
        let mut created: std::vec::Vec<(u32, std::string::String)> = std::vec::Vec::new();
        // More than one group's worth of names, so the tail of the run is
        // served out of the lazily initialised group.
        for i in 0..(ipg + 8) {
            let name = std::format!("f{i:05}");
            match m.create_file(dir, name.as_bytes(), 0o644, 0, 0) {
                Ok(ino) => created.push((ino, name)),
                // Running out of inodes is the healthy answer; anything else
                // is the filesystem reporting its own state is wrong.
                Err(ext4::MountError::NoSpace) => break,
                Err(e) => panic!("create #{i} failed with {e:?}, not NoSpace"),
            }
        }
        let crossed = created.iter().filter(|(ino, _)| (*ino - 1) / ipg >= 1).count();
        assert!(crossed > 0, "fixture never reached the uninit group ({} created)", created.len());
        eprintln!("created={} of which {crossed} in the uninit group", created.len());
        // Every inode the allocator handed out must read back as the regular
        // file it just created.
        for (ino, name) in &created {
            let raw = m.read_inode(*ino)
                .unwrap_or_else(|e| panic!("read_inode({ino}) for {name}: {e:?}"));
            assert!(raw.is_reg(), "inode {ino} ({name}) did not read back as a regular file");
            assert!(raw.links_count >= 1, "inode {ino} ({name}) read back with no links");
        }
        created.len()
    };
    let (ok, log) = fsck(&path);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "after {created} creates across the uninit boundary the image is inconsistent:\n{log}");
}

/// Freeing an inode out of a group mkfs left `INODE_UNINIT` must go through
/// the same materialisation the allocator uses. Reading the stale on-disk
/// bitmap block instead lets the free act on bytes that describe nothing.
#[test]
fn freeing_from_an_uninit_group_stays_consistent() {
    let Some(path) = build_image("free") else { return };
    {
        let m = open_rw(&path);
        let ipg = m.sb.inodes_per_group;
        let dir = m.create_dir(2, b"freeing", 0o755, 0, 0).expect("scratch dir");
        let mut created: std::vec::Vec<(u32, std::string::String)> = std::vec::Vec::new();
        for i in 0..(ipg + 8) {
            let name = std::format!("f{i:05}");
            match m.create_file(dir, name.as_bytes(), 0o644, 0, 0) {
                Ok(ino) => created.push((ino, name)),
                Err(ext4::MountError::NoSpace) => break,
                Err(e) => panic!("create #{i} failed with {e:?}, not NoSpace"),
            }
        }
        // Remove everything that landed in the lazily initialised group.
        for (ino, name) in created.iter().filter(|(ino, _)| (*ino - 1) / ipg >= 1) {
            let out = m.unlink(dir, name.as_bytes())
                .unwrap_or_else(|e| panic!("unlink {name}: {e:?}"));
            assert_eq!(out.ino, *ino);
            if out.orphaned() {
                m.free_orphan_inode(out.ino)
                    .unwrap_or_else(|e| panic!("free {name} (ino {ino}): {e:?}"));
            }
        }
    }
    let (ok, log) = fsck(&path);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "after freeing inodes from the uninit group the image is inconsistent:\n{log}");
}

/// The boot mounts with cross-operation batching on, so the descriptor and
/// bitmap updates of an allocation live in the running transaction's shadow
/// until it commits. Crossing the lazily-initialised boundary inside a batch
/// must reach the device with the same result as an unbatched crossing.
#[test]
fn batched_allocation_crossing_into_an_uninit_group_stays_consistent() {
    let Some(path) = build_image("batched") else { return };
    {
        let m = open_rw(&path);
        m.begin_batch();
        let ipg = m.sb.inodes_per_group;
        let dir = m.create_dir(2, b"batched", 0o755, 0, 0).expect("scratch dir");
        let mut created: std::vec::Vec<(u32, std::string::String)> = std::vec::Vec::new();
        for i in 0..(ipg + 8) {
            let name = std::format!("f{i:05}");
            match m.create_file(dir, name.as_bytes(), 0o644, 0, 0) {
                Ok(ino) => created.push((ino, name)),
                Err(ext4::MountError::NoSpace) => break,
                Err(e) => panic!("create #{i} failed with {e:?}, not NoSpace"),
            }
        }
        let crossed = created.iter().filter(|(ino, _)| (*ino - 1) / ipg >= 1).count();
        assert!(crossed > 0, "fixture never reached the uninit group");
        eprintln!("batched created={} of which {crossed} in the uninit group", created.len());
        for (ino, name) in &created {
            let raw = m.read_inode(*ino)
                .unwrap_or_else(|e| panic!("read_inode({ino}) for {name}: {e:?}"));
            assert!(raw.is_reg(), "inode {ino} ({name}) did not read back as a regular file");
        }
        m.commit_batch().expect("commit batch");
    }
    let (ok, log) = fsck(&path);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "after a batched crossing the image is inconsistent:\n{log}");
}

/// Several contexts allocating at once is what the boot does: udev workers,
/// tmpfiles and the manager all create under `/var` together. The crossing
/// must stay consistent when more than one of them is inside it.
#[test]
fn concurrent_allocation_crossing_into_an_uninit_group_stays_consistent() {
    let Some(path) = build_image("concurrent") else { return };
    {
        let m = Arc::new(open_rw(&path));
        m.begin_batch();
        let ipg = m.sb.inodes_per_group;
        let mut handles = std::vec::Vec::new();
        for t in 0..4u32 {
            let m = m.clone();
            handles.push(std::thread::spawn(move || {
                let dir = m.create_dir(2, std::format!("t{t}").as_bytes(), 0o755, 0, 0)
                    .expect("scratch dir");
                let mut mine = std::vec::Vec::new();
                for i in 0..(ipg / 2) {
                    let name = std::format!("f{i:05}");
                    match m.create_file(dir, name.as_bytes(), 0o644, 0, 0) {
                        Ok(ino) => mine.push((ino, name)),
                        Err(ext4::MountError::NoSpace) => break,
                        Err(e) => panic!("thread {t} create #{i}: {e:?}"),
                    }
                }
                for (ino, name) in &mine {
                    let raw = m.read_inode(*ino)
                        .unwrap_or_else(|e| panic!("thread {t} read_inode({ino}) {name}: {e:?}"));
                    assert!(raw.is_reg(), "thread {t}: inode {ino} ({name}) is not a regular file");
                }
                mine.len()
            }));
        }
        let total: usize = handles.into_iter().map(|h| h.join().expect("thread")).sum();
        eprintln!("concurrent created={total}");
        m.commit_batch().expect("commit batch");
    }
    let (ok, log) = fsck(&path);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "after a concurrent crossing the image is inconsistent:\n{log}");
}

/// The boot image itself: it ships with only a handful of free inodes below
/// its first lazily initialised group, which is the state the synthetic
/// fixtures above cannot recreate (flex_bg puts the bitmaps and inode tables
/// of the crossing groups in a far group, and the last initialised group has
/// exactly one unused inode left). Drive the boot's own early sequence --
/// service private directories under `/var/tmp` and state files under
/// `/var/lib` -- against a writable copy.
#[test]
fn boot_image_early_service_directories_stay_consistent() {
    let src = std::env::var("OXIDE_EXT4_BOOT_IMG")
        .unwrap_or_else(|_| std::string::String::from("/home/nd/oxide/images/out/gnome-x86_64-root.img"));
    if File::open(&src).is_err() { eprintln!("SKIP: no boot image at {src}"); return; }
    if !have("mke2fs") || !have("e2fsck") { eprintln!("SKIP: mke2fs/e2fsck absent"); return; }
    let path = scratch("bootimg");
    let _ = std::fs::remove_file(&path);
    std::fs::copy(&src, &path).expect("copy boot image");
    let (ok0, log0) = fsck(&path);
    assert!(ok0, "source boot image is already dirty:\n{log0}");
    {
        let m = open_rw(&path);
        m.begin_batch();
        eprintln!("free_inodes={} groups={}", m.sb.free_inodes_count, m.sb.group_count());
        let var_tmp = m.lookup_path(b"/var/tmp").expect("/var/tmp");
        let var_lib = m.lookup_path(b"/var/lib").expect("/var/lib");
        // Each PrivateTmp= service gets a private directory with a `tmp` and a
        // `var-tmp` child; the boot starts dozens of them.
        for i in 0..24u32 {
            let dir = std::format!("systemd-private-{i:032x}-svc{i}.service-Xxxxxx");
            let priv_dir = m.create_dir(var_tmp, dir.as_bytes(), 0o700, 0, 0)
                .unwrap_or_else(|e| panic!("mkdir /var/tmp/{dir}: {e:?}"));
            for child in [b"tmp".as_slice(), b"var-tmp".as_slice()] {
                let ino = m.create_dir(priv_dir, child, 0o700, 0, 0)
                    .unwrap_or_else(|e| panic!("mkdir /var/tmp/{dir}/{}: {e:?}",
                                               std::string::String::from_utf8_lossy(child)));
                let raw = m.read_inode(ino)
                    .unwrap_or_else(|e| panic!("read_inode({ino}) under /var/tmp/{dir}: {e:?}"));
                assert!(raw.is_dir(), "inode {ino} under /var/tmp/{dir} is not a directory");
            }
        }
        // A state file with real content, like the catalog database.
        let payload = std::vec![0x5Au8; 512 * 1024];
        for i in 0..8u32 {
            let name = std::format!("state{i}.db");
            let ino = m.create_file(var_lib, name.as_bytes(), 0o644, 0, 0)
                .unwrap_or_else(|e| panic!("create /var/lib/{name}: {e:?}"));
            m.write_at(ino, 0, &payload)
                .unwrap_or_else(|e| panic!("write /var/lib/{name}: {e:?}"));
            let raw = m.read_inode(ino)
                .unwrap_or_else(|e| panic!("read_inode({ino}) for /var/lib/{name}: {e:?}"));
            assert!(raw.is_reg(), "/var/lib/{name} did not read back as a regular file");
        }
        m.commit_batch().expect("commit batch");
    }
    let (ok, log) = fsck(&path);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "after the boot's early service directories the image is inconsistent:\n{log}");
}

/// The boot does not only create: tmpfiles removes the previous boot's private
/// directories, services replace state files through a temporary name, and the
/// removals put inodes on the orphan list before they are freed. Run that
/// churn across the lazily-initialised boundary on the boot image.
#[test]
fn boot_image_create_and_remove_churn_stays_consistent() {
    let src = std::env::var("OXIDE_EXT4_BOOT_IMG")
        .unwrap_or_else(|_| std::string::String::from("/home/nd/oxide/images/out/gnome-x86_64-root.img"));
    if File::open(&src).is_err() { eprintln!("SKIP: no boot image at {src}"); return; }
    if !have("mke2fs") || !have("e2fsck") { eprintln!("SKIP: mke2fs/e2fsck absent"); return; }
    let path = scratch("bootchurn");
    let _ = std::fs::remove_file(&path);
    std::fs::copy(&src, &path).expect("copy boot image");
    let (ok0, log0) = fsck(&path);
    assert!(ok0, "source boot image is already dirty:\n{log0}");
    {
        let m = open_rw(&path);
        m.begin_batch();
        let var_tmp = m.lookup_path(b"/var/tmp").expect("/var/tmp");
        let payload = std::vec![0xA5u8; 256 * 1024];
        let mut live: std::collections::VecDeque<std::string::String> = std::collections::VecDeque::new();
        for i in 0..300u32 {
            let name = std::format!("churn{i:05}");
            let ino = m.create_file(var_tmp, name.as_bytes(), 0o644, 0, 0)
                .unwrap_or_else(|e| panic!("create /var/tmp/{name}: {e:?}"));
            m.write_at(ino, 0, &payload)
                .unwrap_or_else(|e| panic!("write /var/tmp/{name}: {e:?}"));
            let raw = m.read_inode(ino)
                .unwrap_or_else(|e| panic!("read_inode({ino}) for {name}: {e:?}"));
            assert!(raw.is_reg(), "/var/tmp/{name} did not read back as a regular file");
            live.push_back(name);
            if live.len() > 40 {
                let old = live.pop_front().unwrap();
                let out = m.unlink(var_tmp, old.as_bytes())
                    .unwrap_or_else(|e| panic!("unlink /var/tmp/{old}: {e:?}"));
                if out.orphaned() {
                    m.free_orphan_inode(out.ino)
                        .unwrap_or_else(|e| panic!("free /var/tmp/{old} (ino {}): {e:?}", out.ino));
                }
            }
        }
        for name in live {
            let out = m.unlink(var_tmp, name.as_bytes()).expect("unlink tail");
            if out.orphaned() { m.free_orphan_inode(out.ino).expect("free tail"); }
        }
        m.commit_batch().expect("commit batch");
    }
    let (ok, log) = fsck(&path);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "after boot-like create/remove churn the image is inconsistent:\n{log}");
}

/// An eviction that is cut short must leave the inode reachable.
///
/// The orphan record is the only thing on disk that names an inode with no
/// links, so it has to outlive every step that can still fail: the data
/// blocks, the external xattr block, and the inode slot itself. Splicing the
/// record out first and being interrupted afterwards strands the inode --
/// no links, no dtime, blocks still marked in use, and nothing that any
/// later mount can find it by.
///
/// The device below refuses every write past a cut point; sweeping the cut
/// across the whole eviction, and remounting after each one, asserts that the
/// journal plus the orphan record can always finish what was started.
struct CutoffDisk { inner: Mutex<File>, cap: u64, writes: std::sync::atomic::AtomicU64, cut: u64 }

impl BlockDevice for CutoffDisk {
    fn block_size(&self) -> u32 { SECTOR }
    fn capacity_blocks(&self) -> u64 { self.cap }
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        let off = req.start_block * SECTOR as u64;
        let len = (req.len_blocks * SECTOR) as usize;
        if req.op == BlockOp::Write {
            let n = self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n >= self.cut { return Err(block::BlockError::Eio); }
        }
        let mut f = self.inner.lock().unwrap();
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
    fn flush(&self) -> KResult<()> { Ok(()) }
}

/// `i_dtime` doubles as the orphan list's next pointer while an inode is on it.
fn dtime_of(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0x14], bytes[0x15], bytes[0x16], bytes[0x17]])
}

/// Walk the on-disk orphan list and report whether `ino` is on it.
fn on_orphan_list(m: &ext4::Mount, ino: u32) -> bool {
    let mut cur = match m.read_sb_last_orphan() { Ok(h) => h, Err(_) => return false };
    let mut guard = 4096u32;
    while cur != 0 && guard > 0 {
        if cur == ino { return true; }
        guard -= 1;
        let Ok((bytes, _)) = m.read_inode_bytes(cur) else { return false };
        cur = dtime_of(&bytes);
    }
    false
}

#[test]
fn an_interrupted_eviction_leaves_the_inode_on_the_orphan_list() {
    let Some(base) = build_image("cutoff") else { return };
    // How many device writes a complete create-write-unlink-evict takes, so
    // the sweep covers the whole eviction rather than guessing a range.
    let total = {
        let path = scratch("cutoff-count");
        std::fs::copy(&base, &path).expect("copy");
        let f = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let cap = f.metadata().unwrap().len() / SECTOR as u64;
        let disk = Arc::new(CutoffDisk {
            inner: Mutex::new(f), cap,
            writes: std::sync::atomic::AtomicU64::new(0), cut: u64::MAX,
        });
        let counter = disk.clone();
        let m = ext4::Mount::open(disk as Arc<dyn BlockDevice>).expect("mount");
        let ino = m.create_file(2, b"victim", 0o644, 0, 0).expect("create");
        m.write_at(ino, 0, &std::vec![0x3Cu8; 128 * 1024]).expect("write");
        let before = counter.writes.load(std::sync::atomic::Ordering::SeqCst);
        let out = m.unlink(2, b"victim").expect("unlink");
        assert!(out.orphaned());
        m.free_orphan_inode(out.ino).expect("evict");
        let after = counter.writes.load(std::sync::atomic::Ordering::SeqCst);
        let _ = std::fs::remove_file(&path);
        (before, after)
    };
    let (evict_start, evict_end) = total;
    assert!(evict_end > evict_start, "eviction issued no writes");
    eprintln!("eviction spans device writes {evict_start}..{evict_end}");
    for cut in evict_start..evict_end {
        let path = scratch(&std::format!("cutoff-{cut}"));
        std::fs::copy(&base, &path).expect("copy");
        let stranded = {
            let f = OpenOptions::new().read(true).write(true).open(&path).unwrap();
            let cap = f.metadata().unwrap().len() / SECTOR as u64;
            let disk = Arc::new(CutoffDisk {
                inner: Mutex::new(f), cap,
                writes: std::sync::atomic::AtomicU64::new(0), cut,
            });
            let m = ext4::Mount::open(disk as Arc<dyn BlockDevice>).expect("mount");
            // A read-write mount advertises "not cleanly unmounted" and, with a
            // journal, "needs recovery" for its whole window; without that stamp
            // nothing replays the log after the cut.
            let _ = m.mark_state_dirty();
            let Ok(ino) = m.create_file(2, b"victim", 0o644, 0, 0) else { let _ = std::fs::remove_file(&path); continue };
            if m.write_at(ino, 0, &std::vec![0x3Cu8; 128 * 1024]).is_err() { let _ = std::fs::remove_file(&path); continue }
            let Ok(out) = m.unlink(2, b"victim") else { let _ = std::fs::remove_file(&path); continue };
            if !out.orphaned() { let _ = std::fs::remove_file(&path); continue }
            let _ = m.free_orphan_inode(out.ino);
            out.ino
        };
        // What the NEXT mount sees, after whatever recovery it performs.
        let stranded = {
            let f = OpenOptions::new().read(true).write(true).open(&path).unwrap();
            let cap = f.metadata().unwrap().len() / SECTOR as u64;
            let disk: Arc<dyn BlockDevice> = Arc::new(RwFileDisk { f: Mutex::new(f), cap });
            let m = ext4::Mount::open(disk).expect("remount after the cut");
            (stranded, on_orphan_list(&m, stranded), m.read_inode_bytes(stranded).ok())
        };
        let (ino, listed, raw) = stranded;
        let _ = std::fs::remove_file(&path);
        if let Some((bytes, _)) = raw {
            // Either the eviction finished (dtime stamped) or it did not --
            // and if it did not, the orphan list must still name it.
            let links = u16::from_le_bytes([bytes[0x1A], bytes[0x1B]]);
            assert!(dtime_of(&bytes) != 0 || links != 0 || listed,
                "cut={cut}: inode {ino} has no links, no dtime and is off the orphan list");
        }
    }
}
