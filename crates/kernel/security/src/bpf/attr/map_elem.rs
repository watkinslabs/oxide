// Map element-operation access mode and flag validation.

use syscall::errno::Errno;

use super::super::uapi;

/// Access mode the fd must carry for an element op, per
/// `map_get_sys_perms()`: a frozen map loses `FMODE_CAN_WRITE`, and a
/// map created `BPF_F_RDONLY` / `BPF_F_WRONLY` never had the other.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Access { Read, Write }

/// `map_get_sys_perms()` + `bpf_get_file_flag()` combined. # C: O(1)
pub fn map_access_ok(map_flags: u32, frozen: bool, want: Access) -> Result<(), Errno> {
    use uapi::map_flags as f;
    let can_read = map_flags & f::WRONLY == 0;
    let can_write = map_flags & f::RDONLY == 0 && !frozen;
    let ok = match want { Access::Read => can_read, Access::Write => can_write };
    if ok { Ok(()) } else { Err(Errno::Eperm) }
}

/// `bpf_map_check_op_flags()` for a plain HASH map: it carries no
/// `BPF_SPIN_LOCK` btf record and is not a per-cpu map, so `BPF_F_LOCK`,
/// `BPF_F_CPU`, `BPF_F_ALL_CPUS` and any high half are all `-EINVAL`.
/// `allowed` is the per-command mask (`BPF_F_LOCK|BPF_F_CPU` for lookup,
/// `~0` for update). # C: O(1)
pub fn check_op_flags(flags: u64, allowed: u64) -> Result<(), Errno> {
    use uapi::elem_flags as e;
    if (flags as u32) as u64 & !allowed != 0 { return Err(Errno::Einval); }
    if flags & e::F_LOCK != 0 { return Err(Errno::Einval); }
    if flags & e::F_CPU == 0 && flags >> 32 != 0 { return Err(Errno::Einval); }
    if flags & (e::F_CPU | e::F_ALL_CPUS) != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// `htab_map_update_elem()`'s own flag gate: anything above
/// `BPF_EXIST` (ignoring `BPF_F_LOCK`) is `-EINVAL`. # C: O(1)
pub fn check_update_flags(flags: u64) -> Result<(), Errno> {
    use uapi::elem_flags as e;
    if flags & !e::F_LOCK > e::EXIST { return Err(Errno::Einval); }
    Ok(())
}

/// Presence gate on a map-element update: BPF_NOEXIST on a present key
/// is EEXIST; BPF_EXIST on an absent key is ENOENT. # C: O(1)
pub fn update_presence_verdict(flags: u64, present: bool) -> Result<(), Errno> {
    use uapi::elem_flags as e;
    let f = flags & !e::F_LOCK;
    if present && f == e::NOEXIST { return Err(Errno::Eexist); }
    if !present && f == e::EXIST { return Err(Errno::Enoent); }
    Ok(())
}
