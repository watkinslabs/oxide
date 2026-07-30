// `BPF_MAP_CREATE` + the element/freeze commands.
//
// Linux: kernel/bpf/syscall.c `map_create()`, `map_lookup_elem()`,
// `map_update_elem()`, `map_delete_elem()`, `map_get_next_key()`,
// `map_lookup_and_delete_elem()`, `map_freeze()`; kernel/bpf/hashtab.c
// for the BPF_MAP_TYPE_HASH element semantics. Every errno decision
// lives in `attr.rs`; this file resolves fds and moves bytes.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::InodeRef;

use super::attr::{self, Access, Attr, Caps};
use super::uapi;
use super::user;
use super::{BpfMapInode, install_fd, make_bpf_map_inode, next_map_id};

#[path = "map/storage.rs"]
mod storage;
pub(crate) use storage::MapStorage;

/// `map_create()`.
/// # C: O(max_entries × (key_size + value_size)) for preallocated maps
pub(super) fn create(a: &Attr, caps: Caps) -> Result<i64, Errno> {
    let m = attr::map_create_check(a, caps, attr::unpriv_bpf_disabled())?;
    let inode = allocate(
        m.map_type, m.key_size, m.value_size, m.max_entries, m.map_flags,
    )?;
    install_fd(inode, "bpf-map")
}

/// Allocate one validated map inode and its backing storage.
/// # C: O(max_entries × (key_size + value_size)) for preallocated maps
pub(crate) fn allocate(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
) -> Result<InodeRef, Errno> {
    let storage = MapStorage::allocate(
        map_type, key_size, value_size, max_entries, map_flags,
    )?;
    Ok(make_bpf_map_inode(BpfMapInode {
        id: next_map_id(),
        map_type,
        storage,
        max_entries,
        key_size,
        value_size,
        map_flags,
    }))
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub(super) enum MapOp { Lookup, Update, Delete, LookupAndDelete }

impl MapOp {
    /// `<CMD>_LAST_FIELD` — the `CHECK_ATTR` boundary differs per command.
    fn last_end(self) -> usize {
        use uapi::off::map_elem as o;
        match self {
            MapOp::Delete => o::KEY_LAST_END,
            _ => o::FLAGS_LAST_END,
        }
    }
    /// `map_lookup_and_delete_elem()` demands FMODE_CAN_READ **and**
    /// FMODE_CAN_WRITE; lookup wants read, update/delete want write.
    fn accesses(self) -> &'static [Access] {
        match self {
            MapOp::Lookup => &[Access::Read],
            MapOp::LookupAndDelete => &[Access::Read, Access::Write],
            _ => &[Access::Write],
        }
    }
    /// The `allowed_flags` argument `bpf_map_check_op_flags()` is called
    /// with: `BPF_F_LOCK|BPF_F_CPU` for lookup, `~0` for update.
    /// `map_lookup_and_delete_elem()` open-codes `flags & ~BPF_F_LOCK`.
    fn allowed_flags(self) -> u64 {
        use uapi::elem_flags as e;
        match self {
            MapOp::Lookup => e::F_LOCK | e::F_CPU,
            MapOp::LookupAndDelete => e::F_LOCK,
            _ => !0,
        }
    }
}

/// Resolve `attr.map_fd` to its map object. `__bpf_map_get()` returns
/// `-EBADF` for a closed fd and `-EINVAL` for an fd that is not a map.
/// # C: O(1)
pub(super) fn map_from_fd(fd: u32) -> Result<InodeRef, Errno> {
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off on the syscall path; sole reader of the fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let file = fdt.get(fd as i32).map_err(|_| Errno::Ebadf)?;
    let inode = alloc::sync::Arc::clone(file.inode());
    if inode.private::<BpfMapInode>().is_none() { return Err(Errno::Einval); }
    Ok(inode)
}

/// `map_lookup_elem()` / `map_update_elem()` / `map_delete_elem()` /
/// `map_lookup_and_delete_elem()`. No capability is consulted: Linux
/// gates element ops on the descriptor's FMODE alone, so a privileged
/// loader can hand a map fd to an unprivileged consumer.
/// # C: O(N_entries + key_size + value_size)
pub(super) fn elem(a: &Attr, op: MapOp) -> Result<i64, Errno> {
    use uapi::off::map_elem as o;
    attr::check_attr(a, op.last_end())?;
    let flags = a.u64_at(o::FLAGS);
    if op == MapOp::LookupAndDelete && flags & !uapi::elem_flags::F_LOCK != 0 {
        return Err(Errno::Einval);
    }
    let inode = map_from_fd(a.u32_at(o::MAP_FD))?;
    let m = inode.private::<BpfMapInode>().ok_or(Errno::Einval)?;
    let _writer = if op.accesses().contains(&Access::Write) {
        Some(m.storage.begin_write()?)
    } else {
        None
    };
    let frozen = m.storage.frozen();
    for want in op.accesses() { attr::map_access_ok(m.map_flags, frozen, *want)?; }
    attr::check_op_flags(flags, op.allowed_flags())?;

    let key = user::read_vec(a.u64_at(o::KEY), m.key_size as usize)?;
    let value_ptr = a.u64_at(o::VALUE);
    match op {
        MapOp::Lookup => lookup_to_user(m, &key, value_ptr),
        MapOp::LookupAndDelete => lookup_delete_to_user(m, &key, value_ptr),
        MapOp::Update => {
            let val = user::read_vec(value_ptr, m.value_size as usize)?;
            // `htab_map_update_elem()` runs its own flag gate after the
            // key and value copies, so a bad pointer is EFAULT first.
            attr::check_update_flags(flags)?;
            update_entry(m, key, val, flags)
        }
        MapOp::Delete => {
            if m.map_type == uapi::map_type::ARRAY { return Err(Errno::Einval); }
            match remove_entry(m, &key, false)? {
                Some(_) => Ok(0),
                None => Err(Errno::Enoent),
            }
        }
    }
}

fn lookup_to_user(m: &BpfMapInode, key: &[u8], value_ptr: u64) -> Result<i64, Errno> {
    let value = m.lookup_value(key).ok_or(Errno::Enoent)?;
    user::write_bytes(value_ptr, &value.bytes.lock())?;
    Ok(0)
}

fn lookup_delete_to_user(
    m: &BpfMapInode,
    key: &[u8],
    value_ptr: u64,
) -> Result<i64, Errno> {
    if m.map_type == uapi::map_type::ARRAY { return Err(Errno::Einval); }
    let value = remove_entry(m, key, true)?.ok_or(Errno::Enoent)?;
    user::write_bytes(value_ptr, &value)?;
    Ok(0)
}

fn remove_entry(
    m: &BpfMapInode,
    key: &[u8],
    snapshot: bool,
) -> Result<Option<Vec<u8>>, Errno> {
    m.storage.remove(m.map_type, key, snapshot)
}

fn update_entry(m: &BpfMapInode, key: Vec<u8>, val: Vec<u8>, flags: u64) -> Result<i64, Errno> {
    m.storage.update(m.map_type, key, val, flags)
}

/// `map_freeze()`. Re-freezing an already-frozen map is `-EBUSY`, and
/// the caller needs write access (a read-only map fd cannot freeze).
/// # C: O(1)
pub(super) fn freeze(a: &Attr) -> Result<i64, Errno> {
    use uapi::off::map_elem as o;
    attr::check_attr(a, o::MAP_FD_LAST_END)?;
    let inode = map_from_fd(a.u32_at(o::MAP_FD))?;
    let m = inode.private::<BpfMapInode>().ok_or(Errno::Einval)?;
    // `map_get_sys_perms()` is evaluated before the frozen re-check, so
    // a WRONLY-less fd is EPERM and only then a second freeze is EBUSY.
    attr::map_access_ok(m.map_flags, false, Access::Write)?;
    m.storage.freeze()?;
    Ok(0)
}

/// `map_get_next_key()`: a NULL or absent `attr.key` yields the first
/// key in iteration order, otherwise the successor; `-ENOENT` past the
/// end. `attr.next_key` aliases `attr.value` in the union.
/// # C: O(N_entries + key_size)
pub(super) fn get_next_key(a: &Attr) -> Result<i64, Errno> {
    use uapi::off::map_elem as o;
    attr::check_attr(a, o::NEXT_KEY_LAST_END)?;
    let inode = map_from_fd(a.u32_at(o::MAP_FD))?;
    let m = inode.private::<BpfMapInode>().ok_or(Errno::Einval)?;
    attr::map_access_ok(m.map_flags, m.storage.frozen(), Access::Read)?;
    let next_key_ptr = a.u64_at(o::NEXT_KEY);
    user::range_ok(next_key_ptr, m.key_size as usize)?;
    let cur_key = a.u64_at(o::KEY);
    let key_in: Option<Vec<u8>> = if cur_key == 0 { None }
        else { Some(user::read_vec(cur_key, m.key_size as usize)?) };

    let chosen = m.storage.next_key(key_in.as_deref(), m.max_entries)?;
    let next = chosen.ok_or(Errno::Enoent)?;
    user::write_bytes(next_key_ptr, &next)?;
    Ok(0)
}

#[cfg(test)]
#[path = "map_tests.rs"]
mod tests;
