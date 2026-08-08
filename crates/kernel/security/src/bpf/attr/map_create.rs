// `BPF_MAP_CREATE` field and flag validation, per map type.

use syscall::errno::Errno;

use super::super::uapi;
use super::Caps;
use super::check_attr;
use super::Attr;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MapCreate {
    pub map_type: u32, pub key_size: u32, pub value_size: u32,
    pub max_entries: u32, pub map_flags: u32,
}

/// `bpf_get_file_flag()` — RDONLY and WRONLY together is `-EINVAL`.
/// # C: O(1)
pub fn get_file_flag(map_flags: u32) -> Result<(), Errno> {
    use uapi::map_flags as f;
    if map_flags & f::RDONLY != 0 && map_flags & f::WRONLY != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// `map_create_alloc()` ordering, verbatim: `CHECK_ATTR` → `map_extra`
/// → `numa_node` → map-type lookup → `map_alloc_check` → the
/// `unprivileged_bpf_disabled` EPERM gate → `bpf_get_file_flag`.
/// EINVAL for a bad attr therefore *precedes* EPERM for a caller
/// without CAP_BPF. # C: O(ATTR_SIZE)
pub fn map_create_check(a: &Attr, caps: Caps, unpriv_disabled: bool) -> Result<MapCreate, Errno> {
    use uapi::off::map_create as o;
    check_attr(a, o::LAST_END)?;
    let m = MapCreate {
        map_type: a.u32_at(o::MAP_TYPE), key_size: a.u32_at(o::KEY_SIZE),
        value_size: a.u32_at(o::VALUE_SIZE), max_entries: a.u32_at(o::MAX_ENTRIES),
        map_flags: a.u32_at(o::MAP_FLAGS),
    };
    // `map_extra` is only meaningful for BLOOM_FILTER / ARENA / RHASH.
    if a.u64_at(o::MAP_EXTRA) != 0 { return Err(Errno::Einval); }
    // `bpf_map_attr_numa_node()`: honoured only under BPF_F_NUMA_NODE.
    if m.map_flags & uapi::map_flags::NUMA_NODE != 0
        && a.u32_at(o::NUMA_NODE) != uapi::NUMA_NO_NODE && a.u32_at(o::NUMA_NODE) != 0 {
        return Err(Errno::Einval);
    }
    if m.map_type >= uapi::map_type::MAX { return Err(Errno::Einval); }
    match m.map_type {
        uapi::map_type::HASH => htab_map_alloc_check(&m, caps)?,
        uapi::map_type::ARRAY => array_map_alloc_check(&m)?,
        uapi::map_type::LPM_TRIE => lpm_map_alloc_check(&m)?,
        _ => return Err(Errno::Einval),
    }
    if unpriv_disabled && !caps.bpf_capable() { return Err(Errno::Eperm); }
    get_file_flag(m.map_flags)?;
    Ok(m)
}

/// Per-command create-flag/field validation for a `BPF_MAP_TYPE_HASH` map.
/// # C: O(1)
fn htab_map_alloc_check(m: &MapCreate, caps: Caps) -> Result<(), Errno> {
    use uapi::map_flags as f;
    if m.map_flags & f::ZERO_SEED != 0 && !caps.sys_admin { return Err(Errno::Eperm); }
    if m.map_flags & !f::HTAB_CREATE_MASK != 0 { return Err(Errno::Einval); }
    // Requesting both read-only-from-prog and write-only-from-prog together
    // is contradictory.
    if m.map_flags & (f::RDONLY_PROG | f::WRONLY_PROG) == (f::RDONLY_PROG | f::WRONLY_PROG) {
        return Err(Errno::Einval);
    }
    // BPF_F_NO_COMMON_LRU is an LRU-only flag; plain HASH rejects it.
    if m.map_flags & f::NO_COMMON_LRU != 0 { return Err(Errno::Einval); }
    if m.max_entries == 0 || m.key_size == 0 || m.value_size == 0 { return Err(Errno::Einval); }
    if m.key_size as u64 + m.value_size as u64 >= HTAB_ELEM_SIZE_LIMIT { return Err(Errno::E2big); }
    Ok(())
}

/// Per-command create-flag/field validation for a `BPF_MAP_TYPE_ARRAY` map:
/// key size is fixed at 4 bytes (the index), value/entry count non-zero.
/// # C: O(1)
fn array_map_alloc_check(m: &MapCreate) -> Result<(), Errno> {
    use uapi::map_flags as f;
    if m.map_flags & !f::ARRAY_CREATE_MASK != 0
        || m.key_size != 4 || m.value_size == 0 || m.max_entries == 0 {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// Per-command create-flag/field validation for a `BPF_MAP_TYPE_LPM_TRIE`
/// map: NO_PREALLOC is mandatory (an LPM trie cannot be preallocated), key
/// size covers a prefixlen field plus 1-256 bytes of matched data. # C: O(1)
fn lpm_map_alloc_check(m: &MapCreate) -> Result<(), Errno> {
    use uapi::map_flags as f;
    if m.map_flags & !f::LPM_CREATE_MASK != 0
        || m.map_flags & f::NO_PREALLOC == 0
        || !(5..=260).contains(&m.key_size)
        || m.value_size == 0 || m.max_entries == 0 {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// `KMALLOC_MAX_SIZE - sizeof(struct htab_elem)` rounded to the power of
/// two Linux uses on x86_64 (`KMALLOC_MAX_SIZE` = 4 MiB).
const HTAB_ELEM_SIZE_LIMIT: u64 = (4 << 20) - 64;
