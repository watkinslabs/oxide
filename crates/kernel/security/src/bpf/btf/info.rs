use syscall::errno::Errno;

use super::super::{attr::Attr, uapi, user};
use super::attr;
use super::object::BtfObject;

const INFO_SIZE: usize = 32;
const DATA_PTR_OFF: usize = 0;
const DATA_SIZE_OFF: usize = 8;
const ID_OFF: usize = 12;
const NAME_PTR_OFF: usize = 16;
const NAME_LEN_OFF: usize = 24;
const KERNEL_BTF_OFF: usize = 28;
const U32_SIZE: usize = core::mem::size_of::<u32>();
const U64_SIZE: usize = core::mem::size_of::<u64>();
const EMPTY_NAME_SIZE: u32 = 1;
const EMPTY_NAME: [u8; EMPTY_NAME_SIZE as usize] = [0];

fn get_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(bytes[off..off + U32_SIZE].try_into().unwrap())
}

fn get_u64(bytes: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes(bytes[off..off + U64_SIZE].try_into().unwrap())
}

fn put_u32(bytes: &mut [u8], off: usize, value: u32) {
    bytes[off..off + U32_SIZE].copy_from_slice(&value.to_ne_bytes());
}

fn object_from_fd(fd: i32) -> Result<alloc::sync::Arc<vfs::File>, Errno> {
    let cur = sched::current().ok_or(Errno::Ebadfd)?;
    // SAFETY: the running task pins its descriptor table throughout this syscall.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadfd)?.clone();
    let file = fdt.get(fd).map_err(|_| Errno::Ebadfd)?;
    if file.inode().private::<BtfObject>().is_none() { return Err(Errno::Einval); }
    Ok(file)
}

/// Copy the descriptor's BTF information using the extensible info protocol.
/// # C: O(requested info bytes + copied object bytes)
pub(crate) fn get_info_by_fd(a: &Attr, attr_ptr: u64) -> Result<i64, Errno> {
    let (fd, requested_len, info_ptr) = attr::object_info(a)?;
    let file = object_from_fd(fd)?;
    let object = file.inode().private::<BtfObject>().ok_or(Errno::Einval)?;
    let requested = requested_len as usize;
    if requested > uapi::ATTR_MAX_USER_SIZE { return Err(Errno::E2big); }
    if requested > INFO_SIZE
        && !user::all_zero(
            info_ptr.checked_add(INFO_SIZE as u64).ok_or(Errno::Efault)?,
            requested - INFO_SIZE,
        )? {
        return Err(Errno::E2big);
    }

    let copied = core::cmp::min(requested, INFO_SIZE);
    let mut info = [0u8; INFO_SIZE];
    if copied != 0 { user::read_bytes(info_ptr, &mut info[..copied])?; }
    let data_ptr = get_u64(&info, DATA_PTR_OFF);
    let data_capacity = get_u32(&info, DATA_SIZE_OFF) as usize;
    let name_ptr = get_u64(&info, NAME_PTR_OFF);
    let name_capacity = get_u32(&info, NAME_LEN_OFF);

    let data_len = core::cmp::min(data_capacity, object.raw().len());
    if data_len != 0 { user::write_bytes(data_ptr, &object.raw()[..data_len])?; }
    if (name_ptr != 0) != (name_capacity != 0) { return Err(Errno::Einval); }
    if name_capacity != 0 { user::write_bytes(name_ptr, &EMPTY_NAME)?; }

    put_u32(&mut info, DATA_SIZE_OFF, object.raw().len() as u32);
    put_u32(&mut info, ID_OFF, object.id());
    put_u32(&mut info, NAME_LEN_OFF, EMPTY_NAME_SIZE);
    put_u32(&mut info, KERNEL_BTF_OFF, 0);
    if copied != 0 { user::write_bytes(info_ptr, &info[..copied])?; }

    let len_ptr = attr_ptr
        .checked_add(uapi::off::object_info::INFO_LEN as u64)
        .ok_or(Errno::Efault)?;
    user::write_bytes(len_ptr, &(copied as u32).to_ne_bytes())?;
    Ok(0)
}
