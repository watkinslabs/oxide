extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;
use sync::{Modules as ModulesLockClass, Spinlock};
use vfs::{File, FileOps, Inode, InodeRef, KResult, VfsError};

use crate::linux_debugfs::{
    checked_size, errno_to_vfs, linux_ops, regular_inode_size, LinuxFile, LinuxFileOperations,
    LinuxInode,
};

struct DebugFileData {
    ops: usize,
    data: usize,
}

struct OpenedFile {
    inode: LinuxInode,
    file:  LinuxFile,
}

unsafe impl Send for OpenedFile {}

impl OpenedFile {
    fn new(data: usize) -> Self {
        Self {
            inode: LinuxInode { i_rdev: 0, private: data as *mut c_void },
            file:  LinuxFile { private_data: data as *mut c_void },
        }
    }

    fn open(&mut self, ops: &LinuxFileOperations) -> KResult<()> {
        if let Some(open) = ops.open {
            // SAFETY: open callback pointer comes from module-owned file_operations.
            let rc = unsafe { open(&mut self.inode, &mut self.file) };
            if rc < 0 { return Err(errno_to_vfs(-rc)); }
        }
        Ok(())
    }

    fn release(&mut self, ops: &LinuxFileOperations) {
        if let Some(release) = ops.release {
            // SAFETY: release callback belongs to the same file_operations used for open/read/write.
            let _ = unsafe { release(&mut self.inode, &mut self.file) };
        }
    }
}

struct ActiveDebugFile {
    ops: usize,
    opened: Spinlock<OpenedFile, ModulesLockClass>,
}

struct DebugFileOps;
impl FileOps for DebugFileOps {
    fn on_open_file(&self, file: &File) -> KResult<()> {
        let d = file.inode().private::<DebugFileData>().ok_or(VfsError::Einval)?;
        let ops = linux_ops(d.ops).ok_or(VfsError::Einval)?;
        let mut opened = OpenedFile::new(d.data);
        opened.open(ops)?;
        let active = Box::new(ActiveDebugFile { ops: d.ops, opened: Spinlock::new(opened) });
        file.set_private_data(Box::into_raw(active) as u64);
        Ok(())
    }

    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<DebugFileData>().ok_or(VfsError::Einval)?;
        let ops = linux_ops(d.ops).ok_or(VfsError::Einval)?;
        let read = ops.read.ok_or(VfsError::Einval)?;
        let mut opened = OpenedFile::new(d.data);
        opened.open(ops)?;
        let mut pos = off as i64;
        // SAFETY: callback pointer comes from module-owned file_operations; VFS passes a valid kernel buffer.
        let r = checked_size(unsafe { read(&mut opened.file, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut pos) });
        opened.release(ops);
        r
    }

    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let active = active_file(file)?;
        let ops = linux_ops(active.ops).ok_or(VfsError::Einval)?;
        let read = ops.read.ok_or(VfsError::Einval)?;
        let mut opened = active.opened.lock();
        let mut pos = off as i64;
        // SAFETY: callback pointer comes from module-owned file_operations; VFS passes a valid kernel buffer.
        checked_size(unsafe { read(&mut opened.file, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut pos) })
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<DebugFileData>().ok_or(VfsError::Einval)?;
        let ops = linux_ops(d.ops).ok_or(VfsError::Einval)?;
        let write = ops.write.ok_or(VfsError::Einval)?;
        let mut opened = OpenedFile::new(d.data);
        opened.open(ops)?;
        let mut pos = off as i64;
        // SAFETY: callback pointer comes from module-owned file_operations; VFS passes a valid kernel buffer.
        let r = checked_size(unsafe { write(&mut opened.file, buf.as_ptr() as *const c_char, buf.len(), &mut pos) });
        opened.release(ops);
        r
    }

    fn write_file(&self, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        let active = active_file(file)?;
        let ops = linux_ops(active.ops).ok_or(VfsError::Einval)?;
        let write = ops.write.ok_or(VfsError::Einval)?;
        let mut opened = active.opened.lock();
        let mut pos = off as i64;
        // SAFETY: callback pointer comes from module-owned file_operations; VFS passes a valid kernel buffer.
        checked_size(unsafe { write(&mut opened.file, buf.as_ptr() as *const c_char, buf.len(), &mut pos) })
    }

    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll_open_file(&self, file: &File) -> u32 {
        let Ok(active) = active_file(file) else { return 0 };
        let Some(ops) = linux_ops(active.ops) else { return 0 };
        let Some(poll) = ops.poll else { return vfs::inode::POLL_IN | vfs::inode::POLL_OUT };
        let mut opened = active.opened.lock();
        // SAFETY: poll callback pointer comes from module-owned file_operations; no wait queue is registered.
        unsafe { poll(&mut opened.file, null_mut()) }
    }

    fn on_release_file(&self, file: &File) {
        let ptr = file.private_data() as *mut ActiveDebugFile;
        if ptr.is_null() { return; }
        file.set_private_data(0);
        // SAFETY: pointer was installed by on_open_file for this File and is cleared before dropping.
        let active = unsafe { Box::from_raw(ptr) };
        if let Some(ops) = linux_ops(active.ops) {
            active.opened.lock().release(ops);
        }
    }
}

fn active_file(file: &File) -> KResult<&'static ActiveDebugFile> {
    let ptr = file.private_data() as *const ActiveDebugFile;
    if ptr.is_null() { return Err(VfsError::Einval); }
    // SAFETY: private_data owns an ActiveDebugFile from on_open_file until on_release_file.
    Ok(unsafe { &*ptr })
}

pub(crate) fn debug_file_inode(
    mode: u16,
    data: *mut c_void,
    fops: *const LinuxFileOperations,
    size: u64,
) -> InodeRef {
    let d = DebugFileData { ops: fops as usize, data: data as usize };
    regular_inode_size(mode, Arc::new(DebugFileOps), Arc::new(d), size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use vfs::{Dentry, FdTable, OpenFlags};
    use vfs::file::install_open_at;

    use crate::linux_debugfs::{debugfs_create_file, debugfs_remove};

    static ACTIVE_OPEN: AtomicUsize = AtomicUsize::new(0);
    static ACTIVE_READ: AtomicUsize = AtomicUsize::new(0);
    static ACTIVE_RELEASE: AtomicUsize = AtomicUsize::new(0);
    const ACTIVE_COOKIE: usize = 0x4f50_454e;

    unsafe extern "C" fn active_open(_inode: *mut LinuxInode, file: *mut LinuxFile) -> i32 {
        ACTIVE_OPEN.fetch_add(1, Ordering::SeqCst);
        // SAFETY: test callback is invoked with a valid LinuxFile by DebugFileOps.
        unsafe { (*file).private_data = ACTIVE_COOKIE as *mut c_void };
        0
    }

    unsafe extern "C" fn active_read(file: *mut LinuxFile, buf: *mut c_char, len: usize, _pos: *mut i64) -> isize {
        ACTIVE_READ.fetch_add(1, Ordering::SeqCst);
        // SAFETY: test callback is invoked with valid file/buffer pointers by DebugFileOps.
        let body: &[u8] = if unsafe { (*file).private_data as usize } == ACTIVE_COOKIE { b"ok\n" } else { b"bad\n" };
        let n = body.len().min(len);
        // SAFETY: destination buffer is provided by VFS for at least len bytes.
        unsafe { core::ptr::copy_nonoverlapping(body.as_ptr(), buf as *mut u8, n) };
        n as isize
    }

    unsafe extern "C" fn active_release(_inode: *mut LinuxInode, file: *mut LinuxFile) -> i32 {
        // SAFETY: the release hook of ACTIVE_FOPS is only reached through the debugfs file this
        // test created, so file is the same live LinuxFile active_open stamped with ACTIVE_COOKIE;
        // only that private_data word is read, and the file outlives the callback.
        if unsafe { (*file).private_data as usize } == ACTIVE_COOKIE {
            ACTIVE_RELEASE.fetch_add(1, Ordering::SeqCst);
        }
        0
    }

    static ACTIVE_FOPS: LinuxFileOperations = LinuxFileOperations {
        owner: null_mut(),
        open: Some(active_open),
        read: Some(active_read),
        write: None,
        unlocked_ioctl: None,
        release: Some(active_release),
        poll: None,
        mmap: None,
        llseek: null_mut(),
    };

    #[test]
    fn debugfs_file_open_state_lives_until_last_close() {
        ACTIVE_OPEN.store(0, Ordering::SeqCst);
        ACTIVE_READ.store(0, Ordering::SeqCst);
        ACTIVE_RELEASE.store(0, Ordering::SeqCst);

        let name = b"debugfs_active_file\0";
        let d = debugfs_create_file(
            name.as_ptr() as *const c_char,
            0o600,
            null_mut(),
            null_mut(),
            &ACTIVE_FOPS,
        );
        assert!(!d.is_null());
        let inode = tracefs::debug_root().lookup_path("debugfs_active_file").expect("debugfs active file");
        let fdt = FdTable::new();
        let dentry = Dentry::new_root(inode.clone());
        let fd = install_open_at(&fdt, inode, dentry, OpenFlags::O_RDONLY, 0, vfs::FileCred::root(), 1024, None)
            .expect("open debugfs file");
        {
            let file = fdt.get(fd).expect("fd file");
            let mut buf = [0u8; 8];
            let n = file.read(&mut buf).expect("first read");
            assert_eq!(&buf[..n], b"ok\n");
            let n = file.read(&mut buf).expect("second read");
            assert_eq!(&buf[..n], b"ok\n");
        }
        assert_eq!(ACTIVE_OPEN.load(Ordering::SeqCst), 1);
        assert_eq!(ACTIVE_READ.load(Ordering::SeqCst), 2);
        assert_eq!(ACTIVE_RELEASE.load(Ordering::SeqCst), 0);
        fdt.close(fd).expect("close debugfs fd");
        assert_eq!(ACTIVE_RELEASE.load(Ordering::SeqCst), 1);
        debugfs_remove(d);
    }
}
