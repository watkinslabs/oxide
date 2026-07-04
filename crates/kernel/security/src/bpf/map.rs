extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use sync::Spinlock;
use syscall::errno::Errno;
use vfs::InodeRef;

use super::{BpfMapInode, install_fd, make_bpf_map_inode};

/// `bpf_attr` MAP_CREATE prefix:
/// { u32 map_type; u32 key_size; u32 value_size; u32 max_entries; u32 map_flags }.
#[derive(Copy, Clone)]
struct BpfMapCreateAttr {
    map_type:    u32,
    key_size:    u32,
    value_size:  u32,
    max_entries: u32,
    _map_flags:  u32,
}

const BPF_ATTR_MAP_CREATE_SIZE: u64 = 20;
const BPF_MAP_TYPE_HASH: u32 = 1;

pub(super) fn handle_map_create(attr_ptr: u64, attr_size: u64) -> i64 {
    use hal::USER_VA_END;
    if attr_ptr == 0 || attr_size < BPF_ATTR_MAP_CREATE_SIZE {
        return -(Errno::Einval.as_i32() as i64);
    }
    if attr_ptr.checked_add(BPF_ATTR_MAP_CREATE_SIZE).map_or(true, |e| e > USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: attr_ptr range validated < USER_VA_END; 20 B bounded read.
    let attr = unsafe {
        BpfMapCreateAttr {
            map_type: core::ptr::read_volatile(attr_ptr as *const u32),
            key_size: core::ptr::read_volatile((attr_ptr + 4) as *const u32),
            value_size: core::ptr::read_volatile((attr_ptr + 8) as *const u32),
            max_entries: core::ptr::read_volatile((attr_ptr + 12) as *const u32),
            _map_flags: core::ptr::read_volatile((attr_ptr + 16) as *const u32),
        }
    };
    if attr.map_type != BPF_MAP_TYPE_HASH
        || attr.key_size == 0
        || attr.value_size == 0
        || attr.max_entries == 0
    {
        return -(Errno::Einval.as_i32() as i64);
    }
    let inode: InodeRef = make_bpf_map_inode(BpfMapInode {
        entries: Spinlock::new(BTreeMap::new()),
        max_entries: attr.max_entries,
        key_size: attr.key_size,
        value_size: attr.value_size,
        frozen: AtomicBool::new(false),
    });
    install_fd(inode, "bpf-map")
}

/// `bpf_attr` map-ops variant per Linux `linux/bpf.h`. 32 bytes
/// total: { u32 map_fd; u32 _pad; u64 key; u64 value_or_nextkey;
/// u64 flags }.
#[derive(Copy, Clone, Debug)]
struct BpfMapAttr {
    map_fd: u32,
    key:    u64,
    value:  u64,
    _flags: u64,
}

#[derive(Copy, Clone)]
pub(super) enum MapOp {
    Lookup,
    Update,
    Delete,
}

const BPF_ATTR_MAP_OPS_SIZE: u64 = 32;

pub(super) fn handle_map_op(attr_ptr: u64, attr_size: u64, op: MapOp) -> i64 {
    use hal::USER_VA_END;
    if attr_ptr == 0 || attr_size < BPF_ATTR_MAP_OPS_SIZE {
        return -(Errno::Einval.as_i32() as i64);
    }
    if attr_ptr.checked_add(BPF_ATTR_MAP_OPS_SIZE).map_or(true, |e| e > USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: attr_ptr range validated < USER_VA_END; user page mapped under caller's AS; 32 B bounded read.
    let attr = unsafe {
        BpfMapAttr {
            map_fd: core::ptr::read_volatile(attr_ptr as *const u32),
            key: core::ptr::read_volatile((attr_ptr + 8) as *const u64),
            value: core::ptr::read_volatile((attr_ptr + 16) as *const u64),
            _flags: core::ptr::read_volatile((attr_ptr + 24) as *const u64),
        }
    };
    let cur = match sched::current() {
        Some(c) => c,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(attr.map_fd as i32) {
        Ok(f) => f,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = file.inode();
    let map = match inode.private::<BpfMapInode>() {
        Some(m) => m,
        None => return -(Errno::Einval.as_i32() as i64),
    };

    if attr.key == 0 || attr.key >= USER_VA_END
        || attr
            .key
            .checked_add(map.key_size as u64)
            .map_or(true, |e| e > USER_VA_END)
    {
        return -(Errno::Efault.as_i32() as i64);
    }
    let mut key_buf: Vec<u8> = alloc::vec![0u8; map.key_size as usize];
    for i in 0..map.key_size {
        // SAFETY: attr.key + key_size validated < USER_VA_END above; per-byte volatile read.
        key_buf[i as usize] =
            unsafe { core::ptr::read_volatile((attr.key + i as u64) as *const u8) };
    }

    match op {
        MapOp::Lookup => {
            if attr.value == 0 || attr.value >= USER_VA_END
                || attr
                    .value
                    .checked_add(map.value_size as u64)
                    .map_or(true, |e| e > USER_VA_END)
            {
                return -(Errno::Efault.as_i32() as i64);
            }
            let entries = map.entries.lock();
            let value = match entries.get(&key_buf) {
                Some(v) => v.clone(),
                None => return -(Errno::Enoent.as_i32() as i64),
            };
            drop(entries);
            let n = value.len().min(map.value_size as usize);
            for (i, byte) in value.iter().take(n).copied().enumerate() {
                // SAFETY: attr.value + value_size validated < USER_VA_END above; per-byte volatile write.
                unsafe {
                    core::ptr::write_volatile((attr.value + i as u64) as *mut u8, byte);
                }
            }
            0
        }
        MapOp::Update => {
            if map.frozen.load(Ordering::Acquire) {
                return -(Errno::Eperm.as_i32() as i64);
            }
            if attr.value == 0 || attr.value >= USER_VA_END
                || attr
                    .value
                    .checked_add(map.value_size as u64)
                    .map_or(true, |e| e > USER_VA_END)
            {
                return -(Errno::Efault.as_i32() as i64);
            }
            let mut val_buf: Vec<u8> = alloc::vec![0u8; map.value_size as usize];
            for i in 0..map.value_size {
                // SAFETY: attr.value + value_size validated < USER_VA_END above; per-byte volatile read.
                val_buf[i as usize] =
                    unsafe { core::ptr::read_volatile((attr.value + i as u64) as *const u8) };
            }
            let mut entries = map.entries.lock();
            if entries.len() >= map.max_entries as usize && !entries.contains_key(&key_buf) {
                return -(Errno::E2big.as_i32() as i64);
            }
            entries.insert(key_buf, val_buf);
            0
        }
        MapOp::Delete => {
            if map.frozen.load(Ordering::Acquire) {
                return -(Errno::Eperm.as_i32() as i64);
            }
            let mut entries = map.entries.lock();
            match entries.remove(&key_buf) {
                Some(_) => 0,
                None => -(Errno::Enoent.as_i32() as i64),
            }
        }
    }
}

pub(super) fn handle_map_freeze(attr_ptr: u64, attr_size: u64) -> i64 {
    use hal::USER_VA_END;
    if attr_ptr == 0 || attr_size < 4 {
        return -(Errno::Einval.as_i32() as i64);
    }
    if attr_ptr.checked_add(4).map_or(true, |e| e > USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: attr_ptr..attr_ptr+4 validated.
    let map_fd = unsafe { core::ptr::read_volatile(attr_ptr as *const u32) };
    let cur = match sched::current() {
        Some(c) => c,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task; preempt-off in this syscall path.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(map_fd as i32) {
        Ok(f) => f,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = file.inode();
    let map = match inode.private::<BpfMapInode>() {
        Some(m) => m,
        None => return -(Errno::Einval.as_i32() as i64),
    };
    map.frozen.store(true, Ordering::Release);
    0
}

/// Iterate map keys. Linux convention: `attr.key` is NULL or
/// non-existent → return first key in iteration order;
/// otherwise return the key strictly greater than `attr.key`
/// (BTreeMap sorted order). Writes into `attr.value` (which the
/// UAPI names `next_key`). -ENOENT when no successor exists.
/// # C: O(N_entries)
pub(super) fn handle_map_get_next_key(attr_ptr: u64, attr_size: u64) -> i64 {
    use hal::USER_VA_END;
    if attr_ptr == 0 || attr_size < BPF_ATTR_MAP_OPS_SIZE {
        return -(Errno::Einval.as_i32() as i64);
    }
    if attr_ptr.checked_add(BPF_ATTR_MAP_OPS_SIZE).map_or(true, |e| e > USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: attr_ptr range validated < USER_VA_END; 32-byte struct.
    let map_fd = unsafe { core::ptr::read_volatile(attr_ptr as *const u32) };
    // SAFETY: attr_ptr + 8/16 still within validated 32-byte range.
    let cur_key = unsafe { core::ptr::read_volatile((attr_ptr + 8) as *const u64) };
    // SAFETY: same struct bound; field 'value' UAPI-aliased to next_key.
    let next_key_ptr = unsafe { core::ptr::read_volatile((attr_ptr + 16) as *const u64) };

    let cur = match sched::current() {
        Some(c) => c,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task; preempt-off in this op path.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(map_fd as i32) {
        Ok(f) => f,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = file.inode();
    let map = match inode.private::<BpfMapInode>() {
        Some(m) => m,
        None => return -(Errno::Einval.as_i32() as i64),
    };
    if next_key_ptr == 0 || next_key_ptr >= USER_VA_END
        || next_key_ptr
            .checked_add(map.key_size as u64)
            .map_or(true, |e| e > USER_VA_END)
    {
        return -(Errno::Efault.as_i32() as i64);
    }

    let key_in: Option<Vec<u8>> = if cur_key != 0
        && cur_key < USER_VA_END
        && cur_key
            .checked_add(map.key_size as u64)
            .map_or(false, |e| e <= USER_VA_END)
    {
        let mut k = alloc::vec![0u8; map.key_size as usize];
        for i in 0..map.key_size {
            // SAFETY: cur_key range validated above; per-byte volatile read.
            k[i as usize] =
                unsafe { core::ptr::read_volatile((cur_key + i as u64) as *const u8) };
        }
        Some(k)
    } else {
        None
    };

    let entries = map.entries.lock();
    let chosen: Option<Vec<u8>> = match key_in {
        None => entries.keys().next().cloned(),
        Some(k) => entries
            .range(k.clone()..)
            .find(|(kk, _)| **kk > k)
            .map(|(kk, _)| kk.clone()),
    };
    drop(entries);
    let next = match chosen {
        Some(k) => k,
        None => return -(Errno::Enoent.as_i32() as i64),
    };
    for i in 0..map.key_size as usize {
        // SAFETY: next_key_ptr + key_size validated above; per-byte volatile write.
        unsafe {
            core::ptr::write_volatile(
                (next_key_ptr + i as u64) as *mut u8,
                *next.get(i).unwrap_or(&0),
            );
        }
    }
    0
}
