use syscall::errno::Errno;

use super::super::{BpfProgInode, attr::Attr, uapi, user};
use super::attr;
use super::object::BtfObject;

const BTF_INFO_SIZE: usize = 32;
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

const PROG_INFO_SIZE: usize = 232;
const PROG_INFO_VISIBLE_END: usize = 228;
const PROG_TYPE_OFF: usize = 0;
const PROG_ID_OFF: usize = 4;
const PROG_XLATED_LEN_OFF: usize = 20;
const PROG_RUN_TIME_NS_OFF: usize = 192;
const PROG_RUN_CNT_OFF: usize = 200;
const PROG_VERIFIED_INSNS_OFF: usize = 216;

fn get_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(bytes[off..off + U32_SIZE].try_into().unwrap())
}

fn get_u64(bytes: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes(bytes[off..off + U64_SIZE].try_into().unwrap())
}

fn put_u32(bytes: &mut [u8], off: usize, value: u32) {
    bytes[off..off + U32_SIZE].copy_from_slice(&value.to_ne_bytes());
}

fn put_u64(bytes: &mut [u8], off: usize, value: u64) {
    bytes[off..off + U64_SIZE].copy_from_slice(&value.to_ne_bytes());
}

fn object_from_fd(fd: i32) -> Result<alloc::sync::Arc<vfs::File>, Errno> {
    let cur = sched::current().ok_or(Errno::Ebadfd)?;
    // SAFETY: the running task pins its descriptor table throughout this syscall.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadfd)?.clone();
    fdt.get(fd).map_err(|_| Errno::Ebadfd)
}

fn btf_info(object: &BtfObject, requested_len: u32, info_ptr: u64) -> Result<usize, Errno> {
    let requested = requested_len as usize;
    if requested > uapi::ATTR_MAX_USER_SIZE { return Err(Errno::E2big); }
    if requested > BTF_INFO_SIZE
        && !user::all_zero(
            info_ptr.checked_add(BTF_INFO_SIZE as u64).ok_or(Errno::Efault)?,
            requested - BTF_INFO_SIZE,
        )? {
        return Err(Errno::E2big);
    }

    let copied = core::cmp::min(requested, BTF_INFO_SIZE);
    let mut info = [0u8; BTF_INFO_SIZE];
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
    Ok(copied)
}

fn program_record(prog: &BpfProgInode, run_time_ns: u64, run_cnt: u64) -> [u8; PROG_INFO_SIZE] {
    let mut info = [0u8; PROG_INFO_SIZE];
    put_u32(&mut info, PROG_TYPE_OFF, prog.prog_type);
    put_u32(&mut info, PROG_ID_OFF, prog.id);
    put_u32(&mut info, PROG_XLATED_LEN_OFF, prog.insns.len() as u32);
    put_u64(&mut info, PROG_RUN_TIME_NS_OFF, run_time_ns);
    put_u64(&mut info, PROG_RUN_CNT_OFF, run_cnt);
    put_u32(&mut info, PROG_VERIFIED_INSNS_OFF,
        (prog.insns.len() / uapi::INSN_SIZE as usize) as u32);
    info
}

fn prog_info(prog: &BpfProgInode, requested_len: u32, info_ptr: u64) -> Result<usize, Errno> {
    let requested = requested_len as usize;
    if requested > uapi::ATTR_MAX_USER_SIZE { return Err(Errno::E2big); }
    if requested > PROG_INFO_VISIBLE_END
        && !user::all_zero(
            info_ptr.checked_add(PROG_INFO_VISIBLE_END as u64).ok_or(Errno::Efault)?,
            requested - PROG_INFO_VISIBLE_END,
        )? {
        return Err(Errno::E2big);
    }
    let copied = core::cmp::min(requested, PROG_INFO_SIZE);
    let mut _supplied = [0u8; PROG_INFO_SIZE];
    if copied != 0 { user::read_bytes(info_ptr, &mut _supplied[..copied])?; }
    let stats = prog.stats.snapshot();
    let info = program_record(prog, stats.run_time_ns, stats.run_cnt);
    if copied != 0 { user::write_bytes(info_ptr, &info[..copied])?; }
    Ok(copied)
}

/// Copy descriptor information using the object type's extensible record.
/// # C: O(requested info bytes + copied object bytes)
pub(crate) fn get_info_by_fd(a: &Attr, attr_ptr: u64) -> Result<i64, Errno> {
    let (fd, requested_len, info_ptr) = attr::object_info(a)?;
    let file = object_from_fd(fd)?;
    let inode = file.inode();
    let copied = if let Some(prog) = inode.private::<BpfProgInode>() {
        prog_info(prog, requested_len, info_ptr)?
    } else if let Some(object) = inode.private::<BtfObject>() {
        btf_info(object, requested_len, info_ptr)?
    } else { return Err(Errno::Einval); };

    let len_ptr = attr_ptr
        .checked_add(uapi::off::object_info::INFO_LEN as u64)
        .ok_or(Errno::Efault)?;
    user::write_bytes(len_ptr, &(copied as u32).to_ne_bytes())?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use super::*;
    use super::super::super::make_bpf_prog_inode;

    #[test]
    fn program_record_places_runtime_statistics_at_the_uapi_offsets() {
        let inode = make_bpf_prog_inode(uapi::prog_type::SOCKET_FILTER, vec![0; 16]);
        let prog = inode.private::<BpfProgInode>().unwrap();
        let info = program_record(prog, 0x1122_3344_5566_7788, 0x8877_6655_4433_2211);
        assert_eq!(get_u32(&info, PROG_TYPE_OFF), uapi::prog_type::SOCKET_FILTER);
        assert_eq!(get_u32(&info, PROG_ID_OFF), prog.id);
        assert_eq!(get_u32(&info, PROG_XLATED_LEN_OFF), 16);
        assert_eq!(get_u64(&info, PROG_RUN_TIME_NS_OFF), 0x1122_3344_5566_7788);
        assert_eq!(get_u64(&info, PROG_RUN_CNT_OFF), 0x8877_6655_4433_2211);
        assert_eq!(get_u32(&info, PROG_VERIFIED_INSNS_OFF), 2);
    }

    #[test]
    fn program_info_copy_reads_the_program_owned_run_count() {
        let inode = make_bpf_prog_inode(
            uapi::prog_type::SOCKET_FILTER,
            vec![0x95, 0, 0, 0, 0, 0, 0, 0],
        );
        let prog = inode.private::<BpfProgInode>().unwrap();
        crate::bpf::prog::stats::hold();
        let answer = crate::bpf_interp::run_program_with_state(
            prog, &[], &[], &[], &mut crate::bpf_interp::HelperState::default(),
        );
        crate::bpf::prog::stats::release();
        assert_eq!(answer, Some(0));

        let mut info = [0u8; PROG_INFO_SIZE];
        assert_eq!(prog_info(prog, PROG_INFO_SIZE as u32, info.as_mut_ptr() as u64),
            Ok(PROG_INFO_SIZE));
        assert_eq!(get_u64(&info, PROG_RUN_CNT_OFF), 1);
    }

    #[test]
    fn program_info_rejects_nonzero_bytes_after_the_visible_record() {
        let inode = make_bpf_prog_inode(uapi::prog_type::SOCKET_FILTER, vec![0; 8]);
        let prog = inode.private::<BpfProgInode>().unwrap();
        let mut info = [0u8; PROG_INFO_SIZE + 1];
        info[PROG_INFO_VISIBLE_END] = 1;
        assert_eq!(prog_info(prog, info.len() as u32, info.as_mut_ptr() as u64),
            Err(Errno::E2big));
    }
}
