use super::*;
use vfs::fs::FileSystem;

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
        // Raw namespace callers serialize each parent; allocator concurrency is cross-parent.
        let dirs: Vec<_> = (0..4u32).map(|t| m.create_dir(2,
            std::format!("t{t}").as_bytes(), 0o755, 0, 0).expect("scratch dir")).collect();
        let start = Arc::new(std::sync::Barrier::new(dirs.len()));
        for (t, dir) in dirs.into_iter().enumerate() {
            let m = m.clone();
            let start = start.clone();
            handles.push(std::thread::spawn(move || {
                start.wait();
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
        assert!(total > ipg as usize, "allocation must cross the inode group boundary");
        m.commit_batch().expect("commit batch");
    }
    let (ok, log) = fsck(&path);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "after a concurrent crossing the image is inconsistent:\n{log}");
}

#[test]
fn canonical_same_parent_mkdir_serializes_and_persists() {
    let Some(path) = build_image("canonical-mkdir") else { return };
    common::boot_hosted_pmm();
    {
        let f = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let cap = f.metadata().unwrap().len() / SECTOR as u64;
        let disk = Arc::new(RwFileDisk { f: Mutex::new(f), cap });
        let fs = ext4::rootfs::Ext4Mount::open(disk).unwrap();
        let _sb = common::realize_sb(fs.clone(), fs.root(), 0, "ext4".into());
        let parent = fs.root().unwrap();
        let links = parent.nlink();
        fs.state().mount.begin_batch();
        let held = parent.inode_lock();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let mut workers = Vec::new();
        for t in 0..4 {
            let canonical = fs.root().unwrap();
            assert!(Arc::ptr_eq(&parent, &canonical), "same parent must share i_rwsem");
            let ready = ready_tx.clone();
            let done = done_tx.clone();
            workers.push(std::thread::spawn(move || {
                ready.send(()).unwrap();
                for i in 0..16 {
                    // Same boundary as namespace syscall callers: exclusion spans callback.
                    let _guard = canonical.inode_lock();
                    canonical.mkdir(&format!("worker{t}-{i}"), 0o755,
                        &vfs::CreateCtx::root()).expect("canonical mkdir");
                }
                done.send(()).unwrap();
            }));
        }
        let bound = std::time::Duration::from_secs(5);
        for _ in 0..4 { ready_rx.recv_timeout(bound).unwrap(); }
        let early = done_rx.recv_timeout(std::time::Duration::from_millis(100));
        drop(held);
        for worker in workers { worker.join().unwrap(); }
        assert!(matches!(early, Err(std::sync::mpsc::RecvTimeoutError::Timeout)),
            "mkdir must wait for the canonical parent's exclusive lock");
        assert_eq!(parent.nlink(), links + 64);
        for t in 0..4 { for i in 0..16 {
            fs.state().mount.lookup_path(format!("/worker{t}-{i}").as_bytes()).unwrap();
        } }
        fs.state().mount.commit_batch().unwrap();
    }
    let (ok, log) = fsck(&path);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "canonical concurrent mkdir image is inconsistent:\n{log}");
}
