//! What the behavioural ext4 mount options DO to a real mounted filesystem.
//!
//! Each option's decision is unit-tested inside the crate; this file drives the
//! whole mount path against a real image and a device that records what it was
//! asked to do, so an option that is parsed and then dropped fails here rather
//! than looking correct in the option state.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::{Spinlock, TaskList};

use ext4::rootfs::Ext4Mount;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
/// Root directory inode; every ext4 filesystem's is 2.
const ROOT_INO: u32 = 2;
/// How many entries the ceiling probe is willing to create before it decides
/// the ceiling is not there.
const PROBE_ENTRIES: u32 = 150;

/// A device that records what it was asked to do. The RECORD is the point:
/// an option that never reaches the block layer leaves nothing here, and
/// looking at the mount's option state would not have noticed.
struct SpyDev {
    inner: Arc<MemDisk<TaskList>>,
    discards: AtomicUsize,
    /// Whether this device advertises a discard limit at all.
    can_discard: bool,
    /// I/O priority of every request submitted, in submission order.
    prios: Spinlock<Vec<i32>, TaskList>,
}

impl BlockDevice for SpyDev {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
    fn supports_discard(&self) -> bool { self.can_discard }
    fn submit_sync(&self, req: &mut BlockRequest) -> block::types::KResult<()> {
        self.prios.lock().push(req.ioprio);
        if req.op == BlockOp::Discard {
            self.discards.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }
        self.inner.submit_sync(req)
    }
    fn flush(&self) -> block::types::KResult<()> { self.inner.flush() }
}

fn spy(can_discard: bool) -> Arc<SpyDev> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let inner: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: Vec::from(IMAGE), ..Default::default()
    };
    inner.submit_sync(&mut req).expect("seed memdisk");
    Arc::new(SpyDev {
        inner, discards: AtomicUsize::new(0), can_discard,
        prios: Spinlock::new(Vec::new()),
    })
}

fn mount(dev: Arc<SpyDev>, data: &str) -> Arc<Ext4Mount> {
    Ext4Mount::open_with_data(dev as Arc<dyn BlockDevice>, None, data).expect("mounts")
}

// ── max_dir_size_kb= ───────────────────────────────────────────────────────

/// The ceiling refuses the directory GROWTH, which is the only operation it
/// can refuse. A 1 kB ceiling on a filesystem whose blocks are at least that
/// big means the root directory may never gain a block, so the first entry
/// that does not fit the blocks it already has fails.
#[test]
fn max_dir_size_kb_refuses_the_growth_that_would_cross_it() {
    let dev = spy(false);
    let m = mount(dev, "max_dir_size_kb=1");
    let mount = m.state().mount.clone();
    assert_eq!(mount.behaviour().max_dir_size_kb, 1);

    // Fill the root directory until either it refuses (the ceiling did its
    // job) or we run out of patience (it did not).
    let mut refused = false;
    for i in 0..PROBE_ENTRIES {
        let name = alloc::format!("ceiling-probe-{i:04}");
        match mount.create_file(ROOT_INO, name.as_bytes(), 0o644, 0, 0) {
            Ok(_) => continue,
            Err(ext4::MountError::NoSpace) => { refused = true; break; }
            Err(e) => panic!("unexpected error creating entry {i}: {e:?}"),
        }
    }
    assert!(refused, "a 1 kB directory ceiling must stop the directory growing");
}

/// The same filesystem with no ceiling grows past exactly the point the
/// ceiling stopped it — the positive control for the test above, so a check
/// that never fires cannot pass both.
#[test]
fn without_a_ceiling_the_same_directory_keeps_growing() {
    let dev = spy(false);
    let m = mount(dev, "");
    let mount = m.state().mount.clone();
    assert_eq!(mount.behaviour().max_dir_size_bytes(), None);

    for i in 0..PROBE_ENTRIES {
        let name = alloc::format!("ceiling-probe-{i:04}");
        if let Err(e) = mount.create_file(ROOT_INO, name.as_bytes(), 0o644, 0, 0) {
            panic!("unbounded directory refused entry {i}: {e:?}");
        }
    }
}

// ── discard / nodiscard ────────────────────────────────────────────────────

/// `-o discard` reaches the DEVICE, not just the option state.
#[test]
fn discard_hands_a_freed_block_back_to_the_device() {
    let dev = spy(true);
    let m = mount(dev.clone(), "discard");
    let mount = m.state().mount.clone();
    let blk = mount.alloc_block(0).expect("alloc");
    dev.discards.store(0, Ordering::SeqCst);
    mount.free_block(blk).expect("free");
    assert_eq!(dev.discards.load(Ordering::SeqCst), 1,
        "a discard mount trims the block it just freed");
}

/// The default does not. Without this the test above would pass on a mount
/// that trimmed unconditionally, which is a different (and much worse) bug.
#[test]
fn without_the_option_a_freed_block_is_not_trimmed() {
    let dev = spy(true);
    let m = mount(dev.clone(), "nodiscard");
    let mount = m.state().mount.clone();
    let blk = mount.alloc_block(0).expect("alloc");
    dev.discards.store(0, Ordering::SeqCst);
    mount.free_block(blk).expect("free");
    assert_eq!(dev.discards.load(Ordering::SeqCst), 0);
}

/// A device that advertises no discard limit is never asked. An unsupported
/// operation is not a capability probe.
#[test]
fn a_device_without_discard_support_is_not_asked() {
    let dev = spy(false);
    let m = mount(dev.clone(), "discard");
    let mount = m.state().mount.clone();
    let blk = mount.alloc_block(0).expect("alloc");
    dev.discards.store(0, Ordering::SeqCst);
    mount.free_block(blk).expect("free");
    assert_eq!(dev.discards.load(Ordering::SeqCst), 0);
}

// ── journal_ioprio= ────────────────────────────────────────────────────────

/// The priority rides on the block REQUESTS the journal submits, which is the
/// only place it can affect anything.
#[test]
fn journal_ioprio_reaches_the_requests_the_journal_submits() {
    let dev = spy(false);
    let m = mount(dev.clone(), "journal_ioprio=7");
    let mount = m.state().mount.clone();
    let want = sched::ioprio::prio_value(sched::ioprio::CLASS_BE, 7);
    assert_eq!(mount.behaviour().journal_ioprio, 7);

    dev.prios.lock().clear();
    mount.create_file(ROOT_INO, b"ioprio-probe", 0o644, 0, 0).expect("create");
    let seen = dev.prios.lock().clone();
    assert!(seen.iter().any(|p| *p == want),
        "no journal request carried the mount's priority; saw {seen:?}");
}

/// A mount that named no priority submits at the default, so the test above
/// cannot pass by every request happening to carry level 7.
#[test]
fn a_mount_naming_no_priority_submits_at_the_default() {
    let dev = spy(false);
    let m = mount(dev.clone(), "");
    let mount = m.state().mount.clone();
    let level7 = sched::ioprio::prio_value(sched::ioprio::CLASS_BE, 7);

    dev.prios.lock().clear();
    mount.create_file(ROOT_INO, b"ioprio-probe", 0o644, 0, 0).expect("create");
    let seen = dev.prios.lock().clone();
    assert!(!seen.is_empty(), "the operation submitted nothing to measure");
    assert!(!seen.iter().any(|p| *p == level7),
        "a default mount must not submit at level 7; saw {seen:?}");
}

// ── data= ──────────────────────────────────────────────────────────────────

/// `data=journal` puts file data THROUGH the journal: the write is staged in
/// the running transaction instead of going straight to its target, so nothing
/// reaches the data block until the transaction commits.
#[test]
fn data_journal_keeps_file_data_out_of_its_target_until_the_commit() {
    let dev = spy(false);
    let m = mount(dev.clone(), "data=journal");
    let mount = m.state().mount.clone();
    let bs = mount.sb.block_size as usize;
    let payload = alloc::vec![0xABu8; bs];
    let ino = one_block_file(&mount, b"journalled");

    mount.begin_batch();
    let node = mount.read_inode(ino).expect("inode");
    mount.write_file_block(&node, 0, &payload).expect("write");
    // `read_file_block` goes to the DEVICE, never to the running transaction's
    // shadow, so it answers "is this block on disk yet".
    assert_ne!(mount.read_file_block(&node, 0).expect("read"), payload,
        "journalled data must not reach its target before the commit");
    mount.commit_batch().expect("commit");
    assert_eq!(mount.read_file_block(&node, 0).expect("read"), payload,
        "and must reach it after");
}

/// `data=writeback` writes the block straight through, which is what makes the
/// mode cheaper and what makes the test above about the journal rather than
/// about batching.
#[test]
fn data_writeback_writes_the_block_straight_through() {
    let dev = spy(false);
    let m = mount(dev.clone(), "data=writeback");
    let mount = m.state().mount.clone();
    let bs = mount.sb.block_size as usize;
    let payload = alloc::vec![0xCDu8; bs];
    let ino = one_block_file(&mount, b"unjournalled");

    mount.begin_batch();
    let node = mount.read_inode(ino).expect("inode");
    mount.write_file_block(&node, 0, &payload).expect("write");
    assert_eq!(mount.read_file_block(&node, 0).expect("read"), payload,
        "unjournalled data goes to its target immediately");
}

/// Create `name` with exactly one data block already on disk, so a later write
/// to that block has somewhere to land and something to be compared against.
fn one_block_file(mount: &Arc<ext4::Mount>, name: &[u8]) -> u32 {
    let bs = mount.sb.block_size as usize;
    let ino = mount.create_file(ROOT_INO, name, 0o644, 0, 0).expect("create");
    mount.append_block(ino, &alloc::vec![0u8; bs]).expect("append");
    mount.commit_batch().expect("settle");
    ino
}

// ── noload / norecovery ────────────────────────────────────────────────────

/// Both spellings mount, and both land as the same answer. The refusal they
/// imply on a dirty log is unit-tested where the decision lives.
#[test]
fn both_spellings_of_suppressed_recovery_mount_and_agree() {
    for data in ["noload", "norecovery"] {
        let m = mount(spy(false), data);
        assert!(m.state().opts().behaviour.noload, "-o {data}");
    }
    assert!(!mount(spy(false), "").state().opts().behaviour.noload);
}

// ── the option table's remaining admissions ────────────────────────────────

/// `dax` names a device class this kernel has none of, and the reference
/// build without that class refuses the option rather than mounting a
/// filesystem whose files would silently not be direct-access.
#[test]
fn dax_is_refused_rather_than_silently_ignored() {
    let dev = spy(false) as Arc<dyn BlockDevice>;
    assert!(Ext4Mount::open_with_data(dev.clone(), None, "dax").is_err());
    assert!(Ext4Mount::open_with_data(dev, None, "dax=always").is_err());
}

/// `mb_optimize_scan=` takes 0 or 1 and nothing else, and each answer lands.
#[test]
fn mb_optimize_scan_takes_only_its_two_values() {
    let dev = spy(false) as Arc<dyn BlockDevice>;
    assert!(Ext4Mount::open_with_data(dev.clone(), None, "mb_optimize_scan=2").is_err());
    assert_eq!(mount(spy(false), "mb_optimize_scan=0").state().opts().behaviour.mb_optimize_scan,
        Some(false));
    assert_eq!(mount(spy(false), "mb_optimize_scan=1").state().opts().behaviour.mb_optimize_scan,
        Some(true));
    assert_eq!(mount(spy(false), "").state().opts().behaviour.mb_optimize_scan, None,
        "unnamed leaves the filesystem's own size to decide");
}

/// The geometry and reserve options land as the values that were written,
/// and `init_itable` carries both of its spellings.
#[test]
fn the_geometry_and_reserve_options_land_as_written() {
    let b = mount(spy(false), "stripe=64,resuid=1000,resgid=1001,init_itable=20")
        .state().opts().behaviour;
    assert_eq!(b.stripe, 64);
    assert_eq!(b.resuid, 1000);
    assert_eq!(b.resgid, 1001);
    assert_eq!(b.li_wait_mult, Some(20));

    let bare = mount(spy(false), "init_itable").state().opts().behaviour;
    assert_eq!(bare.li_wait_mult, Some(10), "the bare word takes the default multiplier");
    let off = mount(spy(false), "noinit_itable").state().opts().behaviour;
    assert_eq!(off.li_wait_mult, None);
}

/// A remount that names ONE option leaves the others where they were. The
/// options now live on the mount rather than beside it, and this is what would
/// break if a second copy appeared.
#[test]
fn a_remount_naming_one_option_leaves_the_rest_alone() {
    let m = mount(spy(false), "commit=30,discard,max_dir_size_kb=64");
    m.state().configure_mount_opts("nodiscard", false).expect("remount");
    let b = m.state().opts().behaviour;
    assert!(!b.discard, "the option the remount named changed");
    assert_eq!(b.commit_secs, 30, "and the ones it did not, did not");
    assert_eq!(b.max_dir_size_kb, 64);
    let _ = String::new();
}

// ── resuid= / resgid= ──────────────────────────────────────────────────────

/// Byte offset of `s_r_blocks_count_lo` in the image.
const R_BLOCKS_OFF: usize = 1024 + ext4::superblock::SB_OFF_R_BLOCKS_LO;

/// The same image with every free block reserved, so the reserve gate is the
/// only thing standing between a caller and an allocation.
fn all_reserved_dev() -> Arc<SpyDev> {
    let dev = spy(false);
    let mut sb = alloc::vec![0u8; SECTOR as usize * 4];
    let mut rd = BlockRequest {
        op: BlockOp::Read, start_block: 0, len_blocks: 4,
        buffer: core::mem::take(&mut sb), ..Default::default()
    };
    rd.buffer.resize(SECTOR as usize * 4, 0);
    dev.inner.submit_sync(&mut rd).expect("read sb");
    let mut image = rd.buffer;
    image[R_BLOCKS_OFF..R_BLOCKS_OFF + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut wr = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: 4,
        buffer: image, ..Default::default()
    };
    dev.inner.submit_sync(&mut wr).expect("write sb");
    dev
}

/// An unprivileged caller may not have the reserved blocks. Without the gate
/// the superblock's reserved count is a number nobody consults.
#[test]
fn an_unprivileged_caller_is_refused_the_reserved_blocks() {
    let m = mount(all_reserved_dev(), "");
    let mount = m.state().mount.clone();
    const UNPRIVILEGED: u32 = 1000;
    mount.set_alloc_cred_for_tests(UNPRIVILEGED, &[], false);
    assert_eq!(mount.alloc_block(0), Err(ext4::MountError::NoSpace));
}

/// The same filesystem serves root, whom the reserve is FOR — so the test
/// above measures the gate and not an image that had no free blocks.
#[test]
fn the_same_filesystem_still_serves_the_reserved_user() {
    let m = mount(all_reserved_dev(), "");
    let mount = m.state().mount.clone();
    const ROOT: u32 = 0;
    mount.set_alloc_cred_for_tests(ROOT, &[], false);
    mount.alloc_block(0).expect("root reaches the reserve");
}

/// `resuid=` moves the reserve to the named user, and away from root.
#[test]
fn resuid_moves_the_reserve_to_the_user_it_names() {
    let m = mount(all_reserved_dev(), "resuid=1000");
    let mount = m.state().mount.clone();
    mount.set_alloc_cred_for_tests(1000, &[], false);
    mount.alloc_block(0).expect("the named user reaches the reserve");

    let other = mount_all_reserved("resuid=1000");
    other.set_alloc_cred_for_tests(0, &[], false);
    assert_eq!(other.alloc_block(0), Err(ext4::MountError::NoSpace),
        "the reserve moved away from root");
}

/// `resgid=` admits a member of the named group.
#[test]
fn resgid_admits_a_member_of_the_group_it_names() {
    let member = mount_all_reserved("resgid=50");
    member.set_alloc_cred_for_tests(1000, &[10, 50], false);
    member.alloc_block(0).expect("a member reaches the reserve");

    let outsider = mount_all_reserved("resgid=50");
    outsider.set_alloc_cred_for_tests(1000, &[10, 51], false);
    assert_eq!(outsider.alloc_block(0), Err(ext4::MountError::NoSpace));
}

/// Metadata a caller cannot back out of reaches the reserve on its own
/// account, so a tree rewrite is never left half-built by a full disk.
#[test]
fn committed_metadata_reaches_the_reserve_without_a_credential() {
    let mount = mount_all_reserved("");
    mount.set_alloc_cred_for_tests(1000, &[], false);
    assert_eq!(mount.alloc_block(0), Err(ext4::MountError::NoSpace));
    mount.alloc_block_nofail(0).expect("committed metadata is not refused");
}

fn mount_all_reserved(data: &str) -> Arc<ext4::Mount> {
    mount(all_reserved_dev(), data).state().mount.clone()
}

// ── noload on a DIRTY log ──────────────────────────────────────────────────

/// Byte offset of `s_feature_incompat` in the image.
const INCOMPAT_OFF: usize = 1024 + ext4::superblock::SB_OFF_FEATURE_INCOMPAT;

/// The same image with its log marked as needing recovery.
fn dirty_log_dev() -> Arc<dyn BlockDevice> {
    let mut image = IMAGE.to_vec();
    let mut incompat = u32::from_le_bytes(
        image[INCOMPAT_OFF..INCOMPAT_OFF + 4].try_into().unwrap());
    incompat |= ext4::superblock::INCOMPAT_RECOVER;
    image[INCOMPAT_OFF..INCOMPAT_OFF + 4].copy_from_slice(&incompat.to_le_bytes());
    let cap = (image.len() as u64) / (SECTOR as u64);
    let inner: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: image, ..Default::default()
    };
    inner.submit_sync(&mut req).expect("seed memdisk");
    inner
}

/// A writable mount that suppresses REQUIRED recovery is refused. Writing into
/// a filesystem whose newest metadata is still only in the log corrupts it, so
/// there is no correct way to honour the option here.
///
/// This is what proves the option reaches the OPEN. The open replays the log,
/// so an implementation that parsed the option afterwards would already have
/// replayed by the time it read it — and would mount happily.
#[test]
fn suppressed_recovery_on_a_dirty_log_refuses_the_writable_mount() {
    assert!(Ext4Mount::open_with_data(dirty_log_dev(), None, "noload").is_err());
    assert!(Ext4Mount::open_with_data(dirty_log_dev(), None, "norecovery").is_err());
}

/// The same image without the option mounts — so the test above measures the
/// option and not the image.
#[test]
fn the_same_dirty_log_mounts_when_recovery_is_not_suppressed() {
    assert!(Ext4Mount::open_with_data(dirty_log_dev(), None, "").is_ok());
}
