// `BPF_MAP_CREATE` + the element/freeze commands.
//
// Linux: kernel/bpf/syscall.c `map_create()`, `map_lookup_elem()`,
// `map_update_elem()`, `map_delete_elem()`, `map_get_next_key()`,
// `map_lookup_and_delete_elem()`, `map_freeze()`; kernel/bpf/hashtab.c
// for the BPF_MAP_TYPE_HASH element semantics. Every errno decision
// lives in `attr.rs`; this file resolves fds and moves bytes.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use sync::Spinlock;
use syscall::errno::Errno;
use vfs::InodeRef;

use super::attr::{self, Access, Attr, Caps};
use super::uapi;
use super::user;
use super::{BpfMapInode, install_fd, make_bpf_map_inode};

/// `map_create()`. # C: O(1)
pub(super) fn create(a: &Attr, caps: Caps) -> Result<i64, Errno> {
    let m = attr::map_create_check(a, caps, attr::unpriv_bpf_disabled())?;
    let inode: InodeRef = make_bpf_map_inode(BpfMapInode {
        entries: Spinlock::new(BTreeMap::new()),
        max_entries: m.max_entries,
        key_size: m.key_size,
        value_size: m.value_size,
        map_flags: m.map_flags,
        frozen: AtomicBool::new(false),
    });
    install_fd(inode, "bpf-map")
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
fn map_from_fd(fd: u32) -> Result<InodeRef, Errno> {
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
/// # C: O(log N_entries)
pub(super) fn elem(a: &Attr, op: MapOp) -> Result<i64, Errno> {
    use uapi::off::map_elem as o;
    attr::check_attr(a, op.last_end())?;
    let inode = map_from_fd(a.u32_at(o::MAP_FD))?;
    let m = inode.private::<BpfMapInode>().ok_or(Errno::Einval)?;
    let frozen = m.frozen.load(Ordering::Acquire);
    for want in op.accesses() { attr::map_access_ok(m.map_flags, frozen, *want)?; }
    let flags = a.u64_at(o::FLAGS);
    attr::check_op_flags(flags, op.allowed_flags())?;

    let key = user::read_vec(a.u64_at(o::KEY), m.key_size as usize)?;
    let value_ptr = a.u64_at(o::VALUE);
    match op {
        MapOp::Lookup => {
            user::range_ok(value_ptr, m.value_size as usize)?;
            let value = m.entries.lock().get(&key).cloned().ok_or(Errno::Enoent)?;
            user::write_bytes(value_ptr, &value)?;
            Ok(0)
        }
        MapOp::LookupAndDelete => {
            user::range_ok(value_ptr, m.value_size as usize)?;
            let value = m.entries.lock().remove(&key).ok_or(Errno::Enoent)?;
            user::write_bytes(value_ptr, &value)?;
            Ok(0)
        }
        MapOp::Update => {
            let val = user::read_vec(value_ptr, m.value_size as usize)?;
            // `htab_map_update_elem()` runs its own flag gate after the
            // key and value copies, so a bad pointer is EFAULT first.
            attr::check_update_flags(flags)?;
            let mut entries = m.entries.lock();
            let present = entries.contains_key(&key);
            attr::update_presence_verdict(flags, present)?;
            // `htab_map_update_elem()` returns -E2BIG once the table is
            // at max_entries and the key is new.
            if !present && entries.len() >= m.max_entries as usize { return Err(Errno::E2big); }
            entries.insert(key, val);
            Ok(0)
        }
        MapOp::Delete => {
            match m.entries.lock().remove(&key) { Some(_) => Ok(0), None => Err(Errno::Enoent) }
        }
    }
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
    if m.frozen.swap(true, Ordering::AcqRel) { return Err(Errno::Ebusy); }
    Ok(0)
}

/// `map_get_next_key()`: a NULL or absent `attr.key` yields the first
/// key in iteration order, otherwise the successor; `-ENOENT` past the
/// end. `attr.next_key` aliases `attr.value` in the union.
/// # C: O(log N_entries)
pub(super) fn get_next_key(a: &Attr) -> Result<i64, Errno> {
    use uapi::off::map_elem as o;
    attr::check_attr(a, o::NEXT_KEY_LAST_END)?;
    let inode = map_from_fd(a.u32_at(o::MAP_FD))?;
    let m = inode.private::<BpfMapInode>().ok_or(Errno::Einval)?;
    attr::map_access_ok(m.map_flags, m.frozen.load(Ordering::Acquire), Access::Read)?;
    let next_key_ptr = a.u64_at(o::NEXT_KEY);
    user::range_ok(next_key_ptr, m.key_size as usize)?;
    let cur_key = a.u64_at(o::KEY);
    let key_in: Option<Vec<u8>> = if cur_key == 0 { None }
        else { Some(user::read_vec(cur_key, m.key_size as usize)?) };

    let entries = m.entries.lock();
    let chosen: Option<Vec<u8>> = match key_in {
        None => entries.keys().next().cloned(),
        Some(k) => entries.range(k.clone()..).find(|(kk, _)| **kk > k).map(|(kk, _)| kk.clone()),
    };
    drop(entries);
    let next = chosen.ok_or(Errno::Enoent)?;
    user::write_bytes(next_key_ptr, &next)?;
    Ok(0)
}
