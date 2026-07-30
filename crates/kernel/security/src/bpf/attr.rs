// `union bpf_attr` extensible-struct protocol + the per-command
// validation/capability ladders for `bpf(2)`.
//
// No target gate anywhere in this file: every rule below is exercised
// by hosted `cargo test -p security` (see `attr/tests.rs`). Slot-file
// modules under `crates/kernel/syscalls/src/` are
// `#[cfg(target_os = "oxide-kernel")]` and silently compile their
// tests out, so decision logic must live here, not there.
//
// Linux source of truth (linux-master v7.2.0-rc4):
//   kernel/bpf/syscall.c  `__sys_bpf()`, `bpf_check_uarg_tail_zero()`,
//                         `CHECK_ATTR()`, `map_create_alloc()`,
//                         `bpf_prog_load()`, `bpf_prog_attach()`,
//                         `bpf_get_file_flag()`, `map_get_sys_perms()`
//   kernel/bpf/hashtab.c  `htab_map_alloc_check()`, `check_flags()`
//   include/linux/bpf.h   `bpf_map_check_op_flags()`,
//                         `bpf_map_flags_access_ok()`
//   include/linux/capability.h `bpf_capable()`, `perfmon_capable()`

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::errno::Errno;

use super::uapi;

/// Zero-filled staging copy of `union bpf_attr`. `__sys_bpf()` memsets
/// its on-stack union then copies only `min(size, sizeof(attr))` bytes,
/// so short attrs read as zeros rather than as EINVAL.
#[derive(Copy, Clone)]
pub struct Attr { pub bytes: [u8; uapi::ATTR_SIZE] }

impl Attr {
    pub const fn zeroed() -> Self { Attr { bytes: [0u8; uapi::ATTR_SIZE] } }
    /// # C: O(1)
    pub fn u32_at(&self, off: usize) -> u32 {
        u32::from_ne_bytes([self.bytes[off], self.bytes[off + 1], self.bytes[off + 2], self.bytes[off + 3]])
    }
    /// # C: O(1)
    pub fn u64_at(&self, off: usize) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.bytes[off..off + 8]);
        u64::from_ne_bytes(b)
    }
    /// # C: O(ATTR_SIZE - from)
    pub fn tail_is_zero(&self, from: usize) -> bool {
        from >= uapi::ATTR_SIZE || self.bytes[from..].iter().all(|b| *b == 0)
    }
}

/// `sysctl_unprivileged_bpf_disabled` (kernel/bpf/syscall.c). Linux's
/// build-time default is `IS_BUILTIN(CONFIG_BPF_UNPRIV_DEFAULT_OFF) ? 2 : 0`;
/// every distro this kernel targets ships `=y`, so 2 (locked-off) is the
/// matching default. Non-zero means MAP_CREATE and PROG_LOAD demand
/// `bpf_capable()`; element ops on an already-open map fd are never gated.
static UNPRIV_BPF_DISABLED: AtomicU32 = AtomicU32::new(2);

/// # C: O(1)
pub fn unpriv_bpf_disabled() -> bool { UNPRIV_BPF_DISABLED.load(Ordering::Relaxed) != 0 }

/// # C: O(1)
pub fn set_unpriv_bpf_disabled(v: u32) { UNPRIV_BPF_DISABLED.store(v, Ordering::Relaxed); }

/// Effective capability snapshot for one `bpf(2)` call.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Caps { pub bpf: bool, pub sys_admin: bool, pub net_admin: bool, pub perfmon: bool }

impl Caps {
    /// `bpf_capable()` — include/linux/capability.h. # C: O(1)
    pub fn bpf_capable(&self) -> bool { self.bpf || self.sys_admin }
    /// `perfmon_capable()` — include/linux/capability.h. # C: O(1)
    pub fn perfmon_capable(&self) -> bool { self.perfmon || self.sys_admin }
    /// `bpf_token_capable(NULL, CAP_NET_ADMIN)` — kernel/bpf/token.c
    /// falls back to `capable(cap) || capable(CAP_SYS_ADMIN)`. # C: O(1)
    pub fn net_admin_capable(&self) -> bool { self.net_admin || self.sys_admin }
}

/// `bpf_check_uarg_tail_zero()` size arithmetic. Returns
/// `(copy_len, tail_len)`: copy `copy_len` bytes into a zeroed [`Attr`],
/// and require the `tail_len` bytes past `ATTR_SIZE` to be all zero.
/// `-E2BIG` for a "silly large" size, exactly as Linux does *before*
/// any capability or per-command check. # C: O(1)
pub fn size_protocol(size: u32) -> Result<(usize, usize), Errno> {
    let actual = size as usize;
    if actual > uapi::ATTR_MAX_USER_SIZE { return Err(Errno::E2big); }
    let copy = if actual < uapi::ATTR_SIZE { actual } else { uapi::ATTR_SIZE };
    Ok((copy, actual - copy))
}

/// Verdict for the trailing bytes past `sizeof(union bpf_attr)`:
/// non-zero means userspace asked for a field this kernel does not
/// know → `-E2BIG`. # C: O(1)
pub fn tail_verdict(all_zero: bool) -> Result<(), Errno> {
    if all_zero { Ok(()) } else { Err(Errno::E2big) }
}

/// `CHECK_ATTR(CMD)` — every byte past the command's last field must
/// be zero, else `-EINVAL`. # C: O(ATTR_SIZE)
pub fn check_attr(a: &Attr, last_end: usize) -> Result<(), Errno> {
    if a.tail_is_zero(last_end) { Ok(()) } else { Err(Errno::Einval) }
}

/// `__sys_bpf()`'s `switch` reach: commands Linux dispatches vs the
/// `default: -EINVAL` arm. A command number at or above
/// `__MAX_BPF_CMD` is EINVAL on Linux too. # C: O(1)
pub fn cmd_is_known(cmd: u32) -> bool { cmd < uapi::cmd::MAX }

// ---------------------------------------------------------------- caps

/// `is_net_admin_prog_type()` — kernel/bpf/syscall.c. # C: O(1)
pub fn is_net_admin_prog_type(t: u32) -> bool {
    use uapi::prog_type as p;
    matches!(t, p::SCHED_CLS | p::SCHED_ACT | p::XDP | p::LWT_IN | p::LWT_OUT
        | p::LWT_XMIT | p::LWT_SEG6LOCAL | p::SK_SKB | p::SK_MSG | p::FLOW_DISSECTOR
        | p::CGROUP_DEVICE | p::CGROUP_SOCK | p::CGROUP_SOCK_ADDR | p::CGROUP_SOCKOPT
        | p::CGROUP_SYSCTL | p::SOCK_OPS | p::EXT | p::NETFILTER)
}

/// `is_perfmon_prog_type()` — kernel/bpf/syscall.c. # C: O(1)
pub fn is_perfmon_prog_type(t: u32) -> bool {
    use uapi::prog_type as p;
    matches!(t, p::KPROBE | p::TRACEPOINT | p::PERF_EVENT | p::RAW_TRACEPOINT
        | p::RAW_TRACEPOINT_WRITABLE | p::TRACING | p::LSM | p::STRUCT_OPS | p::EXT)
}

/// `find_prog_type()` — Linux indexes `bpf_prog_types[]`, which
/// `include/linux/bpf_types.h` populates only for prog types whose
/// `CONFIG_*` is built in; a type with no entry is `-EINVAL`.
///
/// The built-in set here is exactly the set that can be *executed*:
/// socket filters plus the cgroup device and network hooks.
/// `BPF_PROG_TYPE_LSM` is deliberately absent —
/// `security::bpf_lsm` holds a link registry whose `file_open` hook
/// executes no program and returns "allow" unconditionally, so
/// admitting an LSM load would hand userspace an fd standing for a MAC
/// guarantee that is not enforced. Linux built without `CONFIG_BPF_LSM`
/// answers those loads with the same EINVAL.
/// # C: O(1)
pub fn prog_type_supported(t: u32) -> bool {
    matches!(t, uapi::prog_type::SOCKET_FILTER | uapi::prog_type::CGROUP_DEVICE
        | uapi::prog_type::CGROUP_SKB | uapi::prog_type::CGROUP_SOCK_ADDR)
}

// ------------------------------------------------------------ MAP_CREATE

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

/// `htab_map_alloc_check()` — kernel/bpf/hashtab.c. # C: O(1)
fn htab_map_alloc_check(m: &MapCreate, caps: Caps) -> Result<(), Errno> {
    use uapi::map_flags as f;
    if m.map_flags & f::ZERO_SEED != 0 && !caps.sys_admin { return Err(Errno::Eperm); }
    if m.map_flags & !f::HTAB_CREATE_MASK != 0 { return Err(Errno::Einval); }
    // `bpf_map_flags_access_ok()`.
    if m.map_flags & (f::RDONLY_PROG | f::WRONLY_PROG) == (f::RDONLY_PROG | f::WRONLY_PROG) {
        return Err(Errno::Einval);
    }
    // BPF_F_NO_COMMON_LRU is an LRU-only flag; plain HASH rejects it.
    if m.map_flags & f::NO_COMMON_LRU != 0 { return Err(Errno::Einval); }
    if m.max_entries == 0 || m.key_size == 0 || m.value_size == 0 { return Err(Errno::Einval); }
    if m.key_size as u64 + m.value_size as u64 >= HTAB_ELEM_SIZE_LIMIT { return Err(Errno::E2big); }
    Ok(())
}

/// `array_map_alloc_check()` — kernel/bpf/arraymap.c. # C: O(1)
fn array_map_alloc_check(m: &MapCreate) -> Result<(), Errno> {
    use uapi::map_flags as f;
    if m.map_flags & !f::ARRAY_CREATE_MASK != 0
        || m.key_size != 4 || m.value_size == 0 || m.max_entries == 0 {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// `trie_map_alloc()` — kernel/bpf/lpm_trie.c. # C: O(1)
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

// ---------------------------------------------------------- map element

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

/// `check_flags()` — kernel/bpf/hashtab.c. BPF_NOEXIST on a present key
/// is EEXIST; BPF_EXIST on an absent key is ENOENT. # C: O(1)
pub fn update_presence_verdict(flags: u64, present: bool) -> Result<(), Errno> {
    use uapi::elem_flags as e;
    let f = flags & !e::F_LOCK;
    if present && f == e::NOEXIST { return Err(Errno::Eexist); }
    if !present && f == e::EXIST { return Err(Errno::Enoent); }
    Ok(())
}

// -------------------------------------------------------------- PROG_LOAD

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ProgLoad {
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub insns: u64,
    pub license: u64,
    pub expected_attach_type: u32,
}

/// `bpf_prog_load()`'s pre-copy ladder, in Linux's order:
/// `CHECK_ATTR` → `prog_flags` mask → `unprivileged_bpf_disabled` EPERM
/// → `insn_cnt` bounds (**E2BIG**, not EINVAL) → the "only SOCKET_FILTER
/// and CGROUP_SKB are loadable unprivileged" EPERM → CAP_NET_ADMIN
/// prog types → CAP_PERFMON prog types.
///
/// `find_prog_type()` deliberately is *not* here: Linux runs it after
/// copying insns and license, so a bad `insns` pointer is EFAULT even
/// for a prog type the kernel does not implement.
/// # C: O(ATTR_SIZE)
pub fn prog_load_check(a: &Attr, caps: Caps, unpriv_disabled: bool) -> Result<ProgLoad, Errno> {
    use uapi::off::prog_load as o;
    check_attr(a, o::LAST_END)?;
    let flags = a.u32_at(o::PROG_FLAGS);
    if flags & !uapi::prog_flags::LOAD_MASK != 0 { return Err(Errno::Einval); }
    let bpf_cap = caps.bpf_capable();
    if unpriv_disabled && !bpf_cap { return Err(Errno::Eperm); }
    let p = ProgLoad {
        prog_type: a.u32_at(o::PROG_TYPE), insn_cnt: a.u32_at(o::INSN_CNT),
        insns: a.u64_at(o::INSNS), license: a.u64_at(o::LICENSE),
        expected_attach_type: a.u32_at(o::EXPECTED_ATTACH_TYPE),
    };
    let ceiling = if bpf_cap { uapi::COMPLEXITY_LIMIT_INSNS } else { uapi::MAXINSNS };
    if p.insn_cnt == 0 || p.insn_cnt > ceiling { return Err(Errno::E2big); }
    if p.prog_type != uapi::prog_type::SOCKET_FILTER
        && p.prog_type != uapi::prog_type::CGROUP_SKB && !bpf_cap { return Err(Errno::Eperm); }
    if is_net_admin_prog_type(p.prog_type) && !caps.net_admin_capable() { return Err(Errno::Eperm); }
    if is_perfmon_prog_type(p.prog_type) && !caps.perfmon_capable() { return Err(Errno::Eperm); }
    Ok(p)
}

/// `bpf_prog_load_check_attach()` for the implemented program types.
/// # C: O(1)
pub fn expected_attach_type_check(prog_type: u32, attach_type: u32) -> Result<(), Errno> {
    use uapi::attach_type as a;
    use uapi::prog_type as p;
    let valid = match prog_type {
        p::CGROUP_SKB => matches!(attach_type, a::CGROUP_INET_INGRESS | a::CGROUP_INET_EGRESS),
        p::CGROUP_SOCK_ADDR => matches!(attach_type,
            a::CGROUP_INET4_BIND | a::CGROUP_INET6_BIND
                | a::CGROUP_INET4_CONNECT | a::CGROUP_INET6_CONNECT),
        _ => true,
    };
    if valid { Ok(()) } else { Err(Errno::Einval) }
}

// ------------------------------------------------------------ PROG_ATTACH

/// `attach_type_to_prog_type()` — kernel/bpf/syscall.c. Returns
/// `BPF_PROG_TYPE_UNSPEC` for an attach type Linux does not map, which
/// `bpf_prog_attach()` turns into `-EINVAL`. # C: O(1)
pub fn attach_type_to_prog_type(attach_type: u32) -> u32 {
    use uapi::attach_type as at;
    use uapi::prog_type as p;
    match attach_type {
        at::CGROUP_INET_INGRESS | at::CGROUP_INET_EGRESS => p::CGROUP_SKB,
        at::CGROUP_INET4_BIND | at::CGROUP_INET6_BIND
            | at::CGROUP_INET4_CONNECT | at::CGROUP_INET6_CONNECT => p::CGROUP_SOCK_ADDR,
        at::CGROUP_DEVICE => p::CGROUP_DEVICE,
        at::LSM_MAC => p::LSM,
        _ => p::UNSPEC,
    }
}

/// `bpf_prog_attach()` / `bpf_prog_detach()`.
///
/// Linux resolves the attach type, then hands the request to a
/// per-subsystem attacher. Implemented cgroup types reach the hierarchy-owned
/// attachment engine; other mapped types retain their unavailable verdict.
///
/// Returns the resolved prog type so the caller can run Linux's
/// `bpf_prog_get_type(attr->attach_bpf_fd, ptype)` step — a bad fd is
/// EBADF, which precedes the attacher's EINVAL.
/// # C: O(ATTR_SIZE)
pub fn prog_attach_check(a: &Attr) -> Result<u32, Errno> {
    use uapi::off::prog_attach as o;
    check_attr(a, o::LAST_END)?;
    let ptype = attach_type_to_prog_type(a.u32_at(o::ATTACH_TYPE));
    if ptype == uapi::prog_type::UNSPEC { return Err(Errno::Einval); }
    // `bpf_mprog_supported()` is false and `is_cgroup_prog_type()` true
    // for every type reachable here, so `attach_flags` outside
    // BPF_F_ATTACH_MASK_BASE|MPROG is EINVAL.
    if a.u32_at(o::ATTACH_FLAGS) & !uapi::attach_flags::CGROUP_MASK != 0 {
        return Err(Errno::Einval);
    }
    Ok(ptype)
}

/// Verdict for attach types that have no matching runtime engine. Linux
/// dispatches to a per-subsystem attacher (`cgroup_bpf_prog_attach`,
/// `sock_map_get_from_fd`, `tcx_prog_attach`, …); an unavailable subsystem
/// returns the same `-EINVAL` as its `CONFIG_*=n` stub. # C: O(1)
pub fn prog_attach_verdict(_ptype: u32) -> Errno { Errno::Einval }

// ------------------------------------------------------------- PROG_QUERY

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ProgQuery {
    pub target_fd: u32,
    pub attach_type: u32,
    pub query_flags: u32,
    pub prog_ids: u64,
    pub prog_cnt: u32,
    pub prog_attach_flags: u64,
}

/// `bpf_prog_query()`: CAP_NET_ADMIN precedes CHECK_ATTR, then query flags and
/// attach-type dispatch. # C: O(ATTR_SIZE)
pub fn prog_query_check(a: &Attr, caps: Caps) -> Result<ProgQuery, Errno> {
    use uapi::off::prog_query as o;
    if !caps.net_admin_capable() { return Err(Errno::Eperm); }
    check_attr(a, o::LAST_END)?;
    let query_flags = a.u32_at(o::QUERY_FLAGS);
    if query_flags & !uapi::query_flags::EFFECTIVE != 0 { return Err(Errno::Einval); }
    let attach_type = a.u32_at(o::ATTACH_TYPE);
    if !matches!(attach_type,
        uapi::attach_type::CGROUP_DEVICE
            | uapi::attach_type::CGROUP_INET_INGRESS
            | uapi::attach_type::CGROUP_INET_EGRESS
            | uapi::attach_type::CGROUP_INET4_BIND
            | uapi::attach_type::CGROUP_INET6_BIND
            | uapi::attach_type::CGROUP_INET4_CONNECT
            | uapi::attach_type::CGROUP_INET6_CONNECT) {
        return Err(Errno::Einval);
    }
    let prog_attach_flags = a.u64_at(o::PROG_ATTACH_FLAGS);
    Ok(ProgQuery {
        target_fd: a.u32_at(o::TARGET_FD),
        attach_type,
        query_flags,
        prog_ids: a.u64_at(o::PROG_IDS),
        prog_cnt: a.u32_at(o::PROG_CNT),
        prog_attach_flags,
    })
}

/// `bpf_prog_get_fd_by_id()`: CHECK_ATTR precedes CAP_SYS_ADMIN.
/// # C: O(ATTR_SIZE)
pub fn prog_get_fd_by_id_check(a: &Attr, caps: Caps) -> Result<u32, Errno> {
    use uapi::off::prog_get_fd_by_id as o;
    check_attr(a, o::LAST_END)?;
    if !caps.sys_admin { return Err(Errno::Eperm); }
    Ok(a.u32_at(o::PROG_ID))
}

// ---------------------------------------------------------- PROG_BIND_MAP

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ProgBindMap { pub prog_fd: u32, pub map_fd: u32 }

/// Validate and decode one program-map lifetime binding. # C: O(ATTR_SIZE)
pub fn prog_bind_map_check(a: &Attr) -> Result<ProgBindMap, Errno> {
    use uapi::off::prog_bind_map as o;
    check_attr(a, o::LAST_END)?;
    if a.u32_at(o::FLAGS) != 0 { return Err(Errno::Einval); }
    Ok(ProgBindMap { prog_fd: a.u32_at(o::PROG_FD), map_fd: a.u32_at(o::MAP_FD) })
}

// ------------------------------------------------------------ LINK_CREATE

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LinkCreate {
    pub prog_fd: u32, pub target_fd: u32, pub attach_type: u32, pub flags: u32,
    pub target_btf_id: u32, pub relative_fd: u32, pub expected_revision: u64,
}

/// `link_create()` first-stage `CHECK_ATTR` and union decode. Program lookup
/// and program-type dispatch follow this stage on Linux. # C: O(ATTR_SIZE)
pub fn link_create_check(a: &Attr) -> Result<LinkCreate, Errno> {
    use uapi::off::link_create as o;
    check_attr(a, o::LAST_END)?;
    Ok(LinkCreate {
        prog_fd: a.u32_at(o::PROG_FD), target_fd: a.u32_at(o::TARGET_FD),
        attach_type: a.u32_at(o::ATTACH_TYPE), flags: a.u32_at(o::FLAGS),
        target_btf_id: a.u32_at(o::TARGET_BTF_ID),
        relative_fd: a.u32_at(o::CGROUP_RELATIVE_FD),
        expected_revision: a.u64_at(o::CGROUP_EXPECTED_REVISION),
    })
}

/// `cgroup_bpf_link_attach()` flag gate, before target-fd lookup. # C: O(1)
pub fn cgroup_link_flags_check(flags: u32) -> Result<(), Errno> {
    if flags & !uapi::attach_flags::CGROUP_LINK_MASK != 0 { Err(Errno::Einval) }
    else { Ok(()) }
}

#[cfg(test)]
mod tests;
