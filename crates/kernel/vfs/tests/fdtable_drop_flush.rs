use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

struct FlushOps(Arc<AtomicUsize>);

impl vfs::FileOps for FlushOps {
    fn on_flush_file(&self, _file: &vfs::File, _owner: vfs::RecordOwner) -> vfs::KResult<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn file(flushes: &Arc<AtomicUsize>, ino: u64) -> Arc<vfs::File> {
    let ops: Arc<dyn vfs::FileOps> = Arc::new(FlushOps(flushes.clone()));
    let inode = vfs::InodeBuilder::new(ino, vfs::mk_mode(vfs::FileType::Regular, 0o600),
        vfs::default_inode_ops(), ops.clone()).build();
    let dentry = vfs::Dentry::new(None, "fdtable-drop".into(), inode.clone());
    vfs::File::new_at_fop(inode, dentry, vfs::OpenFlags::O_RDWR, 0, vfs::FileCred::root(), ops)
}

#[test]
fn final_fdtable_drop_flushes_each_open_reference() {
    let flushes = Arc::new(AtomicUsize::new(0));
    let table = vfs::FdTable::new();
    table.alloc(file(&flushes, 1)).unwrap();
    table.alloc(file(&flushes, 2)).unwrap();

    drop(table);

    assert_eq!(flushes.load(Ordering::SeqCst), 2);
}
