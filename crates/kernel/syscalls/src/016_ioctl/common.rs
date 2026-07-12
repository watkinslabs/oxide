use syscall::errno::Errno;

use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

pub(super) const FIONREAD:  u64 = 0x541B;
pub(super) const FIONBIO:   u64 = 0x5421;
pub(super) const FIONCLEX:  u64 = 0x5450;
pub(super) const FIOCLEX:   u64 = 0x5451;
pub(super) const FIOASYNC:  u64 = 0x5452;
pub(super) const FIOQSIZE:  u64 = 0x5460;
pub(super) const FIGETBSZ:  u64 = 0x0000_0002;
pub(super) const SIOCOUTQ:  u64 = 0x5411;
pub(super) const INT_BYTES: u64 = 4;
pub(super) const LOFF_BYTES: u64 = 8;

const O_ASYNC: u32 = 0o20000;

/// Linux `do_vfs_ioctl` common cases that run before driver/file-specific
/// `unlocked_ioctl`. # C: O(1)
pub(super) fn handle_common_ioctl(
    file: &alloc::sync::Arc<vfs::File>,
    fdt: &alloc::sync::Arc<vfs::FdTable>,
    fd: i32,
    req: u64,
    arg: u64,
) -> Option<i64> {
    match req {
        FIOCLEX => Some(match fdt.set_cloexec(fd, true) {
            Ok(()) => 0,
            Err(e) => -(e as i64),
        }),
        FIONCLEX => Some(match fdt.set_cloexec(fd, false) {
            Ok(()) => 0,
            Err(e) => -(e as i64),
        }),
        FIONBIO => Some(ioctl_fionbio(file, arg)),
        FIOASYNC => Some(ioctl_fioasync(file, arg)),
        FIOQSIZE => Some(ioctl_fioqsize(file, arg)),
        FIGETBSZ => Some(ioctl_figetbsz(file, arg)),
        FIONREAD if file.inode().file_type() == vfs::FileType::Regular => {
            Some(ioctl_regular_fionread(file, arg))
        }
        _ => None,
    }
}

/// Socket/pipe queue-count ioctls used after regular-file common handling.
/// # C: O(1)
pub(super) fn handle_nonchar_queue_ioctl(file: &vfs::File, req: u64, arg: u64) -> Option<i64> {
    match req {
        FIONREAD | SIOCOUTQ => {
            if let Err(rv) = validate_user_buf_writable(arg, INT_BYTES, 1) { return Some(rv); }
            let n: u32 = if req == FIONREAD
                && (file.inode().poll_file(file.pos()) & vfs::POLL_IN) != 0 { 1 } else { 0 };
            // SAFETY: arg validated writable for one Linux int out-param.
            unsafe { core::ptr::write_volatile(arg as *mut u32, n); }
            Some(0)
        }
        _ => None,
    }
}

/// Linux `ioctl_fionbio`: read caller int and toggle `O_NONBLOCK`. # C: O(1)
fn ioctl_fionbio(file: &vfs::File, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, INT_BYTES, 1) { return rv; }
    // SAFETY: arg validated readable for one Linux int input.
    let on = unsafe { core::ptr::read_volatile(arg as *const i32) } != 0;
    let mut fl = file.flags();
    if on { fl |= vfs::OpenFlags::O_NONBLOCK; } else { fl &= !vfs::OpenFlags::O_NONBLOCK; }
    file.set_fl(fl);
    0
}

/// Linux `ioctl_fioasync`: read caller int and toggle `FASYNC`. # C: O(1)
fn ioctl_fioasync(file: &alloc::sync::Arc<vfs::File>, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, INT_BYTES, 1) { return rv; }
    // SAFETY: arg validated readable for one Linux int input.
    let on = unsafe { core::ptr::read_volatile(arg as *const i32) } != 0;
    let was_async = file.is_async();
    let mut fl = file.flags();
    let async_flag = vfs::OpenFlags::from_bits_retain(O_ASYNC);
    if on { fl |= async_flag; } else { fl &= !async_flag; }
    file.set_fl(fl);
    let now_async = file.is_async();
    if now_async && !was_async {
        register_fasync(file);
    } else if was_async && !now_async {
        vfs::file::fasync_unregister(file);
    }
    0
}

/// Kernel target wires SIGIO delivery before adding the file to fasync. Hosted
/// tests do not build `sched::live`, but still exercise the flag/registry path.
/// # C: O(1)
#[cfg(not(test))]
fn register_fasync(file: &alloc::sync::Arc<vfs::File>) {
    sched::live::sigpend::install_sigio_hook();
    vfs::file::fasync_register(file);
}

/// # C: O(1)
#[cfg(test)]
fn register_fasync(file: &alloc::sync::Arc<vfs::File>) {
    vfs::file::fasync_register(file);
}

/// Linux `FIOQSIZE`: dirs, regular files, and symlinks copy `loff_t` bytes.
/// # C: O(1)
fn ioctl_fioqsize(file: &vfs::File, arg: u64) -> i64 {
    match file.inode().file_type() {
        vfs::FileType::Directory | vfs::FileType::Regular | vfs::FileType::Symlink => {}
        _ => return -(Errno::Enotty.as_i32() as i64),
    }
    if let Err(rv) = validate_user_buf_writable(arg, LOFF_BYTES, 1) { return rv; }
    // SAFETY: arg validated writable for one Linux loff_t out-param.
    unsafe { core::ptr::write_volatile(arg as *mut i64, file.inode().size() as i64); }
    0
}

/// Linux `FIGETBSZ`: copy superblock `s_blocksize`, or `EINVAL` if absent.
/// # C: O(1)
fn ioctl_figetbsz(file: &vfs::File, arg: u64) -> i64 {
    let bs = match file.inode().i_sb() {
        Some(sb) if sb.s_blocksize != 0 => sb.s_blocksize,
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    if let Err(rv) = validate_user_buf_writable(arg, INT_BYTES, 1) { return rv; }
    // SAFETY: arg validated writable for one Linux int out-param.
    unsafe { core::ptr::write_volatile(arg as *mut i32, bs as i32); }
    0
}

/// Linux regular-file `FIONREAD`: `i_size - f_pos` copied as an int. # C: O(1)
fn ioctl_regular_fionread(file: &vfs::File, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_writable(arg, INT_BYTES, 1) { return rv; }
    let n = (file.inode().size() as i64).saturating_sub(file.pos() as i64) as i32;
    // SAFETY: arg validated writable for one Linux int out-param.
    unsafe { core::ptr::write_volatile(arg as *mut i32, n); }
    0
}
