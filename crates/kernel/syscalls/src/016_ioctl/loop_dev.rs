#![cfg(any(target_os = "oxide-kernel", test))]

//! `LOOP_*` and `LOOP_CTL_*`: the ABI shim over the loop driver.
//!
//! Parse, validate, fetch, call one work function, encode. Every rule the
//! calls below depend on — which flags may move, what a window may be, which
//! device numbers exist, when a removal is refused — belongs to `drv_loop`
//! and is tested there. What is decided HERE, and nowhere else, is which node
//! a request arrived on and how the wire struct crosses the user boundary.

use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::{File, Fmode};

use drv_loop::uapi;

const EFAULT: i64 = -(Errno::Efault.as_i32() as i64);

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The device number of `/dev/loop-control`, as a packed `dev_t`.
fn is_control_node(inode: &vfs::InodeRef) -> bool {
    let rdev = inode.rdev();
    let is_char = inode.file_type() == vfs::FileType::CharDev;
    drv_loop::classify(is_char, vfs::kdev_major(rdev), vfs::kdev_minor(rdev)) == drv_loop::Node::Control
}

/// The loop device a block node names, or `None` when the node is not one.
/// The minor IS the device number: `/dev/loop3` is minor 3, which is what
/// makes a `mknod`-created node work without consulting any table.
fn device_of(inode: &vfs::InodeRef) -> Option<Arc<drv_loop::LoopDevice>> {
    let devt = vfs::device_inode_devt(inode)?;
    match drv_loop::classify(false, devt.major(), devt.minor()) {
        drv_loop::Node::Device(number) => drv_loop::registry::device(number),
        _ => None,
    }
}

/// Answer a `/dev/loop-control` request. `Some(rv)` when the node is the
/// control device, whatever the command — an unknown command on it is
/// `ENOSYS`, which is what the reference reports and what `losetup` probes
/// with. # C: O(N_devices)
pub(super) fn handle_loop_control_ioctl(inode: &vfs::InodeRef, req: u64, arg: u64) -> Option<i64> {
    if !is_control_node(inode) { return None; }
    let parm = arg as i64;
    Some(match req as u32 {
        uapi::LOOP_CTL_ADD => match drv_loop::registry::add(parm) { Ok(n) => n as i64, Err(e) => err(e) },
        uapi::LOOP_CTL_REMOVE => match drv_loop::registry::remove(parm) { Ok(n) => n as i64, Err(e) => err(e) },
        uapi::LOOP_CTL_GET_FREE => match drv_loop::registry::get_free() { Ok(n) => n as i64, Err(e) => err(e) },
        _ => err(Errno::Enosys),
    })
}

/// Answer a `/dev/loopN` request. `None` when the node is not a loop device,
/// so an ordinary block ioctl on it still reaches the block handler.
/// # C: O(N_devices)
pub(super) fn handle_loop_ioctl(file: &File, req: u64, arg: u64) -> Option<i64> {
    let dev = device_of(file.inode())?;
    let cmd = req as u32;
    // Only the loop commands are ours. BLKGETSIZE64 and friends on the same
    // node belong to the block handler, which runs after this.
    if !drv_loop::is_device_command(cmd) { return None; }
    Some(match cmd {
        uapi::LOOP_SET_FD => set_fd(&dev, arg),
        uapi::LOOP_CONFIGURE => configure(&dev, arg),
        uapi::LOOP_CLR_FD => encode(drv_loop::ioctl::clr_fd(&dev)),
        uapi::LOOP_SET_STATUS64 => set_status64(&dev, arg),
        uapi::LOOP_GET_STATUS64 => get_status64(&dev, arg),
        uapi::LOOP_SET_STATUS => set_status_old(&dev, arg),
        uapi::LOOP_GET_STATUS => get_status_old(&dev, arg),
        uapi::LOOP_SET_CAPACITY => match drv_loop::ioctl::set_capacity(&dev) { Ok(_) => 0, Err(e) => err(e) },
        uapi::LOOP_SET_BLOCK_SIZE => encode(drv_loop::ioctl::set_block_size(&dev, arg as u32)),
        uapi::LOOP_SET_DIRECT_IO => encode(drv_loop::ioctl::set_direct_io(&dev, arg != 0)),
        // Swapping the backing description of a live device is the one
        // command with no work function yet; refusing it is honest, and a
        // caller falls back to clear-then-set.
        uapi::LOOP_CHANGE_FD => err(Errno::Einval),
        _ => err(Errno::Enosys),
    })
}

fn encode(r: Result<(), Errno>) -> i64 { match r { Ok(()) => 0, Err(e) => err(e) } }

/// Resolve a descriptor into a backing store, with the access mode the
/// description was opened with. The mode is read from the description rather
/// than from the file's permissions: a read-only description of a writable
/// file still yields a read-only device.
fn backing_from_fd(fd: u64) -> Result<(Arc<dyn drv_loop::Backing>, bool), Errno> {
    let cur = sched::live::current().ok_or(Errno::Ebadf)?;
    // SAFETY: the running task on this CPU with preemption off is the sole
    // reader of its own fd-table slot, which is the same contract every other
    // descriptor-resolving arm of this shim runs under.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let file = fdt.get(fd as i32).map_err(|_| Errno::Ebadf)?;
    // A loop device backed by itself is a cycle whose first read never
    // terminates, so it is refused before anything is bound.
    if device_of(file.inode()).is_some() { return Err(Errno::Ebusy); }
    let writable = file.f_mode().contains(Fmode::WRITE);
    let backing = Arc::new(drv_loop::FileBacking::new(file, writable));
    Ok((backing as Arc<dyn drv_loop::Backing>, writable))
}

fn set_fd(dev: &drv_loop::LoopDevice, arg: u64) -> i64 {
    match backing_from_fd(arg) {
        Ok((backing, writable)) => encode(drv_loop::ioctl::set_fd(dev, backing, writable)),
        Err(e) => err(e),
    }
}

fn configure(dev: &drv_loop::LoopDevice, arg: u64) -> i64 {
    let mut raw = [0u8; core::mem::size_of::<uapi::LoopConfig>()];
    if uaccess::copy_from_user(&mut raw, arg).is_err() { return EFAULT; }
    // SAFETY: LoopConfig is repr(C) and every field is a plain integer or a
    // byte array, so every bit pattern of its size is a valid value.
    let config: uapi::LoopConfig = unsafe { core::ptr::read_unaligned(raw.as_ptr().cast()) };
    match backing_from_fd(config.fd as u64) {
        Ok((backing, writable)) =>
            encode(drv_loop::ioctl::configure(dev, backing, writable, config.info, config.block_size)),
        Err(e) => err(e),
    }
}

fn set_status64(dev: &drv_loop::LoopDevice, arg: u64) -> i64 {
    let mut raw = [0u8; core::mem::size_of::<uapi::LoopInfo64>()];
    if uaccess::copy_from_user(&mut raw, arg).is_err() { return EFAULT; }
    // SAFETY: LoopInfo64 is repr(C) over plain integers and byte arrays.
    let info: uapi::LoopInfo64 = unsafe { core::ptr::read_unaligned(raw.as_ptr().cast()) };
    encode(drv_loop::ioctl::set_status(dev, info))
}

fn get_status64(dev: &drv_loop::LoopDevice, arg: u64) -> i64 {
    let info = match drv_loop::ioctl::get_status(dev) { Ok(i) => i, Err(e) => return err(e) };
    // SAFETY: reading a repr(C) struct of plain integers as its own bytes.
    let bytes = unsafe {
        core::slice::from_raw_parts((&info as *const uapi::LoopInfo64).cast::<u8>(),
                                    core::mem::size_of::<uapi::LoopInfo64>())
    };
    if uaccess::copy_to_user(arg, bytes).is_err() { return EFAULT; }
    0
}

fn set_status_old(dev: &drv_loop::LoopDevice, arg: u64) -> i64 {
    let mut raw = [0u8; core::mem::size_of::<uapi::LoopInfo>()];
    if uaccess::copy_from_user(&mut raw, arg).is_err() { return EFAULT; }
    // SAFETY: LoopInfo is repr(C) over plain integers and byte arrays.
    let old: uapi::LoopInfo = unsafe { core::ptr::read_unaligned(raw.as_ptr().cast()) };
    match drv_loop::info64_from_old(&old) {
        Ok(info) => encode(drv_loop::ioctl::set_status(dev, info)),
        Err(e) => err(e),
    }
}

fn get_status_old(dev: &drv_loop::LoopDevice, arg: u64) -> i64 {
    let info = match drv_loop::ioctl::get_status(dev) { Ok(i) => i, Err(e) => return err(e) };
    let old = match drv_loop::old_from_info64(&info) { Ok(o) => o, Err(e) => return err(e) };
    // SAFETY: reading a repr(C) struct of plain integers as its own bytes.
    let bytes = unsafe {
        core::slice::from_raw_parts((&old as *const uapi::LoopInfo).cast::<u8>(),
                                    core::mem::size_of::<uapi::LoopInfo>())
    };
    if uaccess::copy_to_user(arg, bytes).is_err() { return EFAULT; }
    0
}
