//! `file_accessed` through a REAL `vfs::File::read` on a real tmpfs — the
//! end-to-end half of the atime contract. `crates/kernel/vfs/tests/atime_touch.rs`
//! pins the policy ladder; this file proves `read(2)`/`readv(2)`/`pread(2)`
//! actually reach it, and that `O_NOATIME` and the non-tracking file types do
//! not.
//!
//! Before F775 `read()` never touched atime at all: `AtimePolicy` had zero call
//! sites in the tree, so `ls -lu` reported the creation time of every file
//! forever.

use std::string::String;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use boot_info::{BootInfo, BootMemKind, BootMemRegion};
use fs::tmpfs::TmpfsFs;
use vfs::inode_ops::CreateCtx;
use vfs::{Dentry, File, OpenFlags, Timespec64};

static SERIAL: Mutex<()> = Mutex::new(());

const NOW_SEC: i64 = 1_700_000_000;
fn now_ns() -> u64 { (NOW_SEC as u64) * 1_000_000_000 }
fn ts(sec: i64) -> Timespec64 { Timespec64::from_secs(sec) }

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::inode_times::set_realtime_provider(now_ns);
    boot_hosted_pmm();
    g
}

static PMM: OnceLock<()> = OnceLock::new();
const HOSTED_PMM_POOL: usize = 16 * 1024 * 1024;

/// tmpfs commits REAL frames, so a write needs a live PMM.
fn boot_hosted_pmm() {
    PMM.get_or_init(|| {
        let layout = std::alloc::Layout::from_size_align(HOSTED_PMM_POOL, 4096).unwrap();
        // SAFETY: non-zero, page-aligned host allocation leaked for the test-binary lifetime.
        let buf = unsafe { std::alloc::alloc_zeroed(layout) } as u64;
        assert!(buf != 0, "hosted PMM pool allocation failed");
        let regions = [BootMemRegion { base_pa: 0, len: HOSTED_PMM_POOL as u64, kind: BootMemKind::Usable }];
        let info = BootInfo {
            memmap_count: 1, memmap_ptr: regions.as_ptr(), seed: [0u8; 32], boot_ns: 0,
            rsdp_pa: 0, hhdm_offset: buf, framebuffer: boot_info::BootFramebuffer::EMPTY, bsp_lapic_id: 0, _pad: 0,
        };
        // SAFETY: BootInfo names a live region slice for this call; HHDM maps to leaked host memory.
        unsafe { pmm::setup::init_from_boot_info(&info).expect("pmm init"); }
        pmm::setup::init_page_meta((HOSTED_PMM_POOL as u64) / 4096);
    });
}

/// A tmpfs file with `len` bytes and explicitly aged timestamps, plus an open
/// description over it. `mnt_id == 0` (no vfsmount) is Linux's internal-mount
/// identity: `mnt_flags == 0`, i.e. strictatime, so every read is expected to
/// stamp unless something else forbids it.
fn open_file(name: &str, flags: OpenFlags, atime: i64, mtime: i64) -> (Arc<TmpfsFs>, Arc<File>, vfs::InodeRef) {
    let tfs = TmpfsFs::new(String::from("atimefs"));
    let root = tfs.root_inode();
    let ino = root.create_child(name, 0o644, &CreateCtx::root()).expect("create");
    ino.write(0, b"payload").expect("write");
    ino.set_times(Some(ts(atime)), Some(ts(mtime)), ts(mtime)).expect("set_times");
    let d = Dentry::new_root(ino.clone());
    (tfs, File::new(ino.clone(), d, flags), ino)
}

#[test]
fn read_stamps_the_access_time() {
    let _g = guard();
    let (_fs, f, ino) = open_file("r", OpenFlags::O_RDONLY, NOW_SEC - 9_000, NOW_SEC - 9_000);
    assert_eq!(ino.atime().unwrap(), ts(NOW_SEC - 9_000));
    let mut buf = [0u8; 4];
    f.read(&mut buf).expect("read");
    assert_eq!(ino.atime().unwrap(), ts(NOW_SEC), "read(2) runs file_accessed");
}

#[test]
fn readv_stamps_the_access_time() {
    let _g = guard();
    let (_fs, f, ino) = open_file("rv", OpenFlags::O_RDONLY, NOW_SEC - 9_000, NOW_SEC - 9_000);
    let mut a = [0u8; 2];
    let mut b = [0u8; 2];
    let mut bufs: [&mut [u8]; 2] = [&mut a, &mut b];
    f.read_iter(&mut bufs).expect("readv");
    assert_eq!(ino.atime().unwrap(), ts(NOW_SEC));
}

#[test]
fn pread_stamps_the_access_time_without_moving_the_cursor() {
    let _g = guard();
    let (_fs, f, ino) = open_file("pr", OpenFlags::O_RDONLY, NOW_SEC - 9_000, NOW_SEC - 9_000);
    let mut buf = [0u8; 4];
    f.pread(&mut buf, 0).expect("pread");
    assert_eq!(ino.atime().unwrap(), ts(NOW_SEC));
    assert_eq!(f.pos(), 0, "pread leaves f_pos alone");
}

#[test]
fn o_noatime_suppresses_the_stamp() {
    let _g = guard();
    let (_fs, f, ino) = open_file("na", OpenFlags::O_RDONLY | OpenFlags::O_NOATIME,
                                 NOW_SEC - 9_000, NOW_SEC - 9_000);
    let mut buf = [0u8; 4];
    f.read(&mut buf).expect("read");
    assert_eq!(ino.atime().unwrap(), ts(NOW_SEC - 9_000),
        "O_NOATIME is checked in file_accessed, before touch_atime");
}

#[test]
fn a_zero_length_read_at_eof_still_stamps() {
    // Linux runs `file_accessed` unconditionally at the end of the read helper,
    // not `if (bytes_read > 0)` — opening and reading a file to EOF counts as
    // an access even when the last call returns 0.
    let _g = guard();
    let (_fs, f, ino) = open_file("eof", OpenFlags::O_RDONLY, NOW_SEC - 9_000, NOW_SEC - 9_000);
    let mut sink = [0u8; 64];
    f.read(&mut sink).expect("drain");
    ino.set_times(Some(ts(NOW_SEC - 9_000)), None, ts(NOW_SEC - 9_000)).expect("re-age");
    let n = f.read(&mut sink).expect("read at eof");
    assert_eq!(n, 0);
    assert_eq!(ino.atime().unwrap(), ts(NOW_SEC));
}

#[test]
fn a_read_never_disturbs_mtime_or_ctime() {
    let _g = guard();
    let (_fs, f, ino) = open_file("mt", OpenFlags::O_RDONLY, NOW_SEC - 9_000, NOW_SEC - 9_000);
    let (m0, c0) = (ino.mtime().unwrap(), ino.ctime().unwrap());
    let mut buf = [0u8; 4];
    f.read(&mut buf).expect("read");
    assert_eq!(ino.mtime().unwrap(), m0, "S_ATIME-only update leaves mtime");
    assert_eq!(ino.ctime().unwrap(), c0, "S_ATIME-only update leaves ctime");
}

#[test]
fn a_socket_read_does_not_stamp() {
    // Linux `sock_read_iter` has no `file_accessed`; oxide routes socket reads
    // through the same `File::read`, so the exclusion has to be explicit.
    let _g = guard();
    let tfs = TmpfsFs::new(String::from("sockfs"));
    let root = tfs.root_inode();
    root.mknod_child("s", (vfs::S_IFSOCK as u16) | 0o644, 0, &CreateCtx::root()).expect("mknod");
    let ino = root.lookup("s").expect("lookup sock");
    ino.set_times(Some(ts(NOW_SEC - 9_000)), Some(ts(NOW_SEC - 9_000)), ts(NOW_SEC - 9_000)).expect("times");
    vfs::atime::file_accessed(&File::new(ino.clone(), Dentry::new_root(ino.clone()), OpenFlags::O_RDONLY));
    assert_eq!(ino.atime().unwrap(), ts(NOW_SEC - 9_000));
}
