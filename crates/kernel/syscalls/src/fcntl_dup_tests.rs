use alloc::sync::Arc;
use std::sync::Mutex;

use vfs::{Dentry, FdTable, File, FileType, InodeBuilder, OpenFlags, VfsError,
          default_file_ops, default_inode_ops, mk_mode};

fn file(ino: u64) -> Arc<File> {
    let inode = InodeBuilder::new(
        ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(), default_file_ops(),
    ).build();
    let dentry = Dentry::new_root(Arc::clone(&inode));
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

struct ReuseContext {
    fdt: Arc<FdTable>,
    source: i32,
    original: Arc<File>,
    replacement: Arc<File>,
}

static REUSE: Mutex<Option<ReuseContext>> = Mutex::new(None);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn close_and_reuse_after_pin() {
    let reuse = REUSE.lock().unwrap();
    let ctx = reuse.as_ref().unwrap();
    ctx.fdt.close(ctx.source).unwrap();
    assert_eq!(ctx.fdt.alloc(Arc::clone(&ctx.replacement)).unwrap(), ctx.source);
}

fn duplicate_across_source_reuse(cloexec: bool) {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    super::fcntl_dup::set_post_pin_hook(None);
    *REUSE.lock().unwrap() = None;
    let fdt = Arc::new(FdTable::new());
    let original = file(0x7201);
    let replacement = file(0x7202);
    let source = fdt.alloc(Arc::clone(&original)).unwrap();

    *REUSE.lock().unwrap() = Some(ReuseContext {
        fdt: Arc::clone(&fdt), source, original: Arc::clone(&original),
        replacement: Arc::clone(&replacement),
    });
    super::fcntl_dup::set_post_pin_hook(Some(close_and_reuse_after_pin));
    let duplicate = super::fcntl_dup::duplicate_fd(&fdt, source, 0, cloexec, 8).unwrap();

    assert_ne!(duplicate, source);
    assert!(Arc::ptr_eq(&fdt.get(source).unwrap(), &replacement));
    assert!(Arc::ptr_eq(&fdt.get(duplicate).unwrap(), &original));
    assert_eq!(fdt.cloexec(duplicate).unwrap(), cloexec);

    // fork_clone snapshots file slots and descriptor flags under one lock.
    // Immediate exec therefore observes the published File/CLOEXEC pair.
    let exec_table = fdt.fork_clone();
    exec_table.close_on_exec();
    assert!(Arc::ptr_eq(&exec_table.get(source).unwrap(), &replacement));
    if cloexec {
        assert_eq!(exec_table.get(duplicate).unwrap_err(), VfsError::Ebadf);
    } else {
        assert!(Arc::ptr_eq(&exec_table.get(duplicate).unwrap(), &original));
    }
    let ctx = REUSE.lock().unwrap().take().unwrap();
    assert!(Arc::ptr_eq(&ctx.original, &original));
}

#[test]
fn f_dupfd_keeps_pinned_source_across_close_and_reuse() {
    duplicate_across_source_reuse(false);
}

#[test]
fn f_dupfd_cloexec_publishes_pinned_source_with_descriptor_flag() {
    duplicate_across_source_reuse(true);
}

#[test]
fn production_fcntl_routes_dup_commands_through_one_lookup_engine() {
    let syscall = include_str!("072_fcntl.rs");
    let engine = include_str!("fcntl_dup.rs");
    let duplicate_route = syscall.find("if matches!(cmd, F_DUPFD | F_DUPFD_CLOEXEC)").unwrap();
    let generic_lookup = syscall.find("let file = match fdt.get(fd)").unwrap();

    assert!(syscall.contains("crate::fcntl_dup::duplicate_fd("));
    assert!(syscall.contains("cmd == F_DUPFD_CLOEXEC"));
    assert!(duplicate_route < generic_lookup);
    assert_eq!(engine.matches("fdt.get(fd)").count(), 1);
    assert!(engine.contains("let file = pin_duplicate_source(fdt, fd)?;"));
    assert!(engine.contains("run_post_pin_hook();"));
    assert!(engine.contains("publish_duplicate(fdt, &file, min, cloexec, limit)"));
    assert!(engine.contains("fdt.dup_file_min_limit(file, min, cloexec, limit)"));
}
