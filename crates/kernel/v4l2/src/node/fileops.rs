//! The `/dev/videoN` file: open, release, poll, ioctl and mmap.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Spinlock, TaskList};
use vfs::{default_inode_ops, mk_mode, File, FileOps, FileType, Inode, InodeBuilder, InodeRef,
          KResult, PollSubscribers, SharedFrame, VfsError};

use crate::device::{self, FileHandle};
use crate::ids;
use crate::ioctl;
use crate::ioctl::Ctx;
use crate::uapi::ioctl as cmds;
use crate::usermem::MAX_ARG_BYTES;
use crate::vb2::poll as vb2poll;
use super::ctx::KernelCtx;

/// Backend state on a video inode: which device it addresses.
struct VideoInode { index: u32 }

/// `file->private_data`: the handle this open file description owns.
struct VideoOpen {
    handle: Arc<FileHandle>,
    fileio: Spinlock<Option<FileIo>, TaskList>,
    reading: AtomicBool,
}

struct FileIo { current: Option<(u32, usize)> }

const FILEIO_BUFFER_COUNT: u32 = 4;

struct VideoFileOps;

struct ReadGuard<'a>(&'a AtomicBool);

impl Drop for ReadGuard<'_> {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}

/// Borrow the handle this open file description owns. # C: O(1)
fn opened(file: &File) -> Option<&VideoOpen> {
    let raw = file.private_data();
    if raw == 0 { return None; }
    // SAFETY: on_open_file stores exactly one live Box<VideoOpen> per open
    // file description and on_release_file consumes it at the final close, so
    // the pointer names a live allocation for as long as the File exists.
    Some(unsafe { &*(raw as *const VideoOpen) })
}

/// Was the description opened non-blocking? # C: O(1)
fn nonblocking(file: &File) -> bool {
    file.flags().contains(vfs::OpenFlags::O_NONBLOCK)
}

impl FileOps for VideoFileOps {
    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &File) -> bool { true }

    /// # C: O(1)
    fn on_open_file(&self, file: &File) -> KResult<()> {
        let data = file.inode().private::<VideoInode>().ok_or(VfsError::Enodev)?;
        let dev = device::by_index(data.index).ok_or(VfsError::Enodev)?;
        let handle = device::open(&dev);
        let raw = Box::into_raw(Box::new(VideoOpen {
            handle, fileio: Spinlock::new(None), reading: AtomicBool::new(false),
        })) as u64;
        file.set_private_data(raw);
        Ok(())
    }

    /// # C: O(buffers)
    fn on_release_file(&self, file: &File) {
        let raw = file.private_data();
        file.set_private_data(0);
        if raw == 0 { return; }
        // SAFETY: the final File release consumes the unique Box installed by
        // on_open_file; nothing else holds this pointer.
        let open = unsafe { Box::from_raw(raw as *mut VideoOpen) };
        device::close(&open.handle);
    }

    /// Readiness: the buffer queue's, plus the priority bit when an event is
    /// waiting for this handle. # C: O(1)
    fn poll_open_file(&self, file: &File) -> u32 {
        let Some(open) = opened(file) else { return vb2poll::POLL_ERR };
        let device = open.handle.device.clone();
        if !device.registered() { return vb2poll::POLL_ERR; }
        let pending = open.handle.events.lock().pending();
        let state = device.state.lock();
        vb2poll::poll_mask(&state.queue, pending)
    }

    /// A video device is not a stream of bytes. The read interface exists in
    /// the ABI, but a device that declares only the streaming capability has
    /// no read method, and that is what an application tests before using it.
    /// # C: O(1)
    fn read(&self, _inode: &Inode, _off: u64, _buf: &mut [u8]) -> KResult<usize> {
        Err(VfsError::Einval)
    }

    #[cfg(target_os = "oxide-kernel")]
    fn read_file(&self, file: &File, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let open = opened(file).ok_or(VfsError::Enodev)?;
        if buf.is_empty() { return Ok(0); }
        if open.handle.device.device_caps & crate::uapi::flags::CAP_READWRITE == 0 {
            return Err(VfsError::Einval);
        }
        if open.reading.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            return Err(VfsError::Ebusy);
        }
        let _guard = ReadGuard(&open.reading);
        let ctx = KernelCtx::new(nonblocking(file));
        init_fileio(open)?;
        let (index, offset, size, frames) = dequeue_fileio(open, &ctx)?;
        let count = core::cmp::min(buf.len(), size.saturating_sub(offset));
        let copied = super::frames::read_plane(&frames, offset, &mut buf[..count]);
        if copied == 0 { return Err(VfsError::Eio); }
        let end = offset.saturating_add(copied);
        if end >= size { requeue_fileio(open, index)?; }
        else { open.fileio.lock().as_mut().ok_or(VfsError::Enodev)?.current = Some((index, end)); }
        Ok(copied)
    }
    /// # C: O(1)
    fn write(&self, _inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(VfsError::Einval)
    }

    /// Resolve a `mmap(2)` offset to the page backing it.
    ///
    /// The pages are refcounted kernel RAM, so they go out through the shared
    /// frame path, which installs one reference per page-table entry. A
    /// physical-range mapping would count none, and the queue freeing its own
    /// reference would then free a page the application still has mapped.
    /// # C: O(buffers * planes)
    fn mmap_shared_frame(&self, inode: &Inode, off: u64) -> KResult<Option<SharedFrame>> {
        let data = inode.private::<VideoInode>().ok_or(VfsError::Einval)?;
        let device = device::by_index(data.index).ok_or(VfsError::Enodev)?;
        let state = device.state.lock();
        let cookie = (off / super::frames::PAGE_BYTES as u64) * super::frames::PAGE_BYTES as u64;
        // The cookie names a plane; the remainder selects the page within it.
        let mut base = cookie;
        loop {
            if let Some((bi, pi)) = state.queue.plane_by_offset(base as u32) {
                let page = ((off - base) / super::frames::PAGE_BYTES as u64) as usize;
                let plane = &state.queue.bufs[bi].planes[pi];
                return Ok(plane.frames.get(page).map(|pa| SharedFrame { pa: *pa, map_ref_held: false }));
            }
            if base < super::frames::PAGE_BYTES as u64 { return Ok(None); }
            base -= super::frames::PAGE_BYTES as u64;
            // A cookie more than one plane away from any plane base is not a
            // mapping of this device; walking further would be a scan of the
            // whole offset space.
            if cookie - base > (crate::vb2::MAX_BUFFERS as u64) * super::frames::PAGE_BYTES as u64 {
                return Ok(None);
            }
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
fn init_fileio(open: &VideoOpen) -> KResult<()> {
    let device = &open.handle.device;
    let mut fileio = open.fileio.lock();
    if fileio.is_some() { return Ok(()); }
    let ops = device.ops.clone();
    let alloc = device.alloc.clone();
    let handed = {
        let mut state = device.state.lock();
        if state.queue.streaming || state.queue.is_busy() { return Err(VfsError::Ebusy); }
        let format = state.format;
        let made = crate::vb2::reqbufs::reqbufs(
            &mut state.queue, open.handle.id, crate::uapi::flags::BUF_TYPE_VIDEO_CAPTURE,
            crate::uapi::flags::MEMORY_MMAP, FILEIO_BUFFER_COUNT,
            |want| ops.queue_setup(want, &format), alloc.as_ref(),
        ).map_err(|err| VfsError::from_errno(err as i32))?;
        if made == 0 || state.queue.bufs.iter().any(|buf| buf.planes.len() != 1) {
            crate::vb2::reqbufs::free_buffers(&mut state.queue, alloc.as_ref());
            return Err(VfsError::Ebusy);
        }
        for index in 0..made {
            let req = crate::vb2::QbufIn {
                index, buf_type: state.queue.buf_type, memory: crate::uapi::flags::MEMORY_MMAP,
                field: crate::uapi::flags::FIELD_NONE, flags: 0,
                planes: [crate::vb2::PlaneIn::default(); crate::uapi::layout::MAX_PLANES],
                num_planes: 1, bytesused: 0,
            };
            if crate::vb2::qbuf::qbuf(&mut state.queue, open.handle.id, &req).is_err() {
                crate::vb2::reqbufs::free_buffers(&mut state.queue, alloc.as_ref());
                return Err(VfsError::Einval);
            }
        }
        let buf_type = state.queue.buf_type;
        crate::vb2::stream::streamon(&mut state.queue, open.handle.id, buf_type)
            .map_err(|err| VfsError::from_errno(err as i32))?
    };
    if !handed.is_empty() {
        if let Err(err) = ops.start_streaming(&handed) {
            let mut state = device.state.lock();
            crate::vb2::stream::streamon_failed(&mut state.queue, &handed);
            crate::vb2::reqbufs::free_buffers(&mut state.queue, alloc.as_ref());
            return Err(VfsError::from_errno(err as i32));
        }
    }
    *fileio = Some(FileIo { current: None });
    Ok(())
}

#[cfg(target_os = "oxide-kernel")]
fn dequeue_fileio(open: &VideoOpen, ctx: &KernelCtx) -> KResult<(u32, usize, usize, alloc::vec::Vec<u64>)> {
    let device = &open.handle.device;
    loop {
        let mut state = device.state.lock();
        if let Some((index, offset)) = open.fileio.lock().as_ref().and_then(|io| io.current) {
            let buf = state.queue.buffer(index).ok_or(VfsError::Einval)?;
            let plane = buf.planes.first().ok_or(VfsError::Einval)?;
            return Ok((index, offset, plane.bytesused as usize, plane.frames.clone()));
        }
        match crate::vb2::qbuf::dqbuf_ready(&state.queue, ctx.nonblocking())
            .map_err(|err| VfsError::from_errno(err as i32))? {
            Some(_) => {
                let buf_type = state.queue.buf_type;
                let index = crate::vb2::qbuf::dqbuf(&mut state.queue, open.handle.id, buf_type)
                    .map_err(|err| VfsError::from_errno(err as i32))?;
                let buf = state.queue.buffer(index).ok_or(VfsError::Einval)?;
                let plane = buf.planes.first().ok_or(VfsError::Einval)?;
                let size = plane.bytesused as usize;
                let frames = plane.frames.clone();
                open.fileio.lock().as_mut().ok_or(VfsError::Enodev)?.current = Some((index, 0));
                return Ok((index, 0, size, frames));
            }
            None => {
                drop(state);
                device.state.lock().queue.waiting_in_dqbuf = true;
                let waited = ctx.wait_for_buffer(device);
                device.state.lock().queue.waiting_in_dqbuf = false;
                waited.map_err(|err| VfsError::from_errno(err as i32))?;
            }
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
fn requeue_fileio(open: &VideoOpen, index: u32) -> KResult<()> {
    let device = &open.handle.device;
    let handoff = {
        let mut state = device.state.lock();
        let req = crate::vb2::QbufIn {
            index, buf_type: state.queue.buf_type, memory: crate::uapi::flags::MEMORY_MMAP,
            field: crate::uapi::flags::FIELD_NONE, flags: 0,
            planes: [crate::vb2::PlaneIn::default(); crate::uapi::layout::MAX_PLANES],
            num_planes: 1, bytesused: 0,
        };
        let handoff = crate::vb2::qbuf::qbuf(&mut state.queue, open.handle.id, &req)
            .map_err(|err| VfsError::from_errno(err as i32))?;
        open.fileio.lock().as_mut().ok_or(VfsError::Enodev)?.current = None;
        handoff
    };
    if handoff { device.ops.buf_queue(index); }
    Ok(())
}

/// Build the `/dev/videoN` inode. # C: O(1)
pub fn make_inode(index: u32) -> InodeRef {
    let inode = InodeBuilder::new(ids::INO_TAG | index as u64,
                                  mk_mode(FileType::CharDev, 0o660),
                                  default_inode_ops(), Arc::new(VideoFileOps))
        .private(Arc::new(VideoInode { index }))
        .poll_subs(PollSubscribers::new())
        .build();
    super::publish::attach_inode(index, &inode);
    inode
}

/// Is this inode a video node? # C: O(1)
pub fn is_video_inode(inode: &InodeRef) -> bool { inode.private::<VideoInode>().is_some() }

/// Entry point for the shared `sys_ioctl` dispatch chain.
///
/// Returns `None` for an inode this subsystem does not own, so a command on a
/// foreign file falls through to whoever does own it. The argument is copied
/// in whole, worked on as bytes and copied back — the reference's shape, and
/// what keeps the command surface itself free of user-memory access.
/// # C: per command
pub fn handle_ioctl(file: &Arc<File>, req: u64, arg: u64) -> Option<i64> {
    if !is_video_inode(&file.inode()) { return None; }
    if !cmds::is_v4l2(req) { return Some(-(syscall::errno::Errno::Enotty.as_i32() as i64)); }
    let Some(open) = opened(file) else {
        return Some(-(syscall::errno::Errno::Enodev.as_i32() as i64));
    };
    let size = cmds::ioc_size(req);
    if size > MAX_ARG_BYTES { return Some(-(syscall::errno::Errno::Einval.as_i32() as i64)); }
    let ctx = KernelCtx::new(nonblocking(file));
    let mut buf = [0u8; MAX_ARG_BYTES];
    let dir = cmds::ioc_dir(req);
    if size != 0 && dir & cmds::IOC_WRITE != 0 {
        if let Err(e) = uaccess::copy_from_user(&mut buf[..size], arg) {
            return Some(-(e.as_i32() as i64));
        }
    }
    match ioctl::dispatch(&open.handle, req, &mut buf[..size], &ctx) {
        Ok(()) => {
            if size != 0 && dir & cmds::IOC_READ != 0 {
                if let Err(e) = uaccess::copy_to_user(arg, &buf[..size]) {
                    return Some(-(e.as_i32() as i64));
                }
            }
            Some(0)
        }
        Err(e) => Some(-(e.as_i32() as i64)),
    }
}
