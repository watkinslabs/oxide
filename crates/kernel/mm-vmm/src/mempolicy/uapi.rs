// NUMA memory-policy UAPI (`include/uapi/linux/mempolicy.h`,
// linux-master v7.2.0-rc4). Numbers only — the admission ladders live in
// `policy.rs`, the bitmap conventions in `nodemask.rs`.

/// `enum { MPOL_DEFAULT, ... }` (`include/uapi/linux/mempolicy.h:19`).
pub const MPOL_DEFAULT: u16 = 0;
pub const MPOL_PREFERRED: u16 = 1;
pub const MPOL_BIND: u16 = 2;
pub const MPOL_INTERLEAVE: u16 = 3;
pub const MPOL_LOCAL: u16 = 4;
pub const MPOL_PREFERRED_MANY: u16 = 5;
pub const MPOL_WEIGHTED_INTERLEAVE: u16 = 6;
/// Always last member of the enum — `sanitize_mpol_flags` rejects `>=` this.
pub const MPOL_MAX: u16 = 7;

/// Optional mode flags packed into the mode word by set_mempolicy/mbind
/// (`include/uapi/linux/mempolicy.h:31`).
pub const MPOL_F_STATIC_NODES: u16 = 1 << 15;
pub const MPOL_F_RELATIVE_NODES: u16 = 1 << 14;
pub const MPOL_F_NUMA_BALANCING: u16 = 1 << 13;
/// `MPOL_MODE_FLAGS` (`include/uapi/linux/mempolicy.h:39`).
pub const MPOL_MODE_FLAGS: u16 =
    MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES | MPOL_F_NUMA_BALANCING;
/// `MPOL_USER_NODEMASK_FLAGS` (`:43`) — the two flags that make the kernel
/// keep the RAW user nodemask alongside the effective one, so `get_mempolicy`
/// reports back exactly what was passed in.
pub const MPOL_USER_NODEMASK_FLAGS: u16 = MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES;

/// Internal flags sharing the policy flags word (`:67`). Never OR'ed into a
/// mode argument by userspace; `do_get_mempolicy` masks them off with
/// `MPOL_MODE_FLAGS` before exposing `pol->flags`.
pub const MPOL_F_SHARED: u16 = 1 << 0;
pub const MPOL_F_MOF: u16 = 1 << 3;
pub const MPOL_F_MORON: u16 = 1 << 4;

/// `get_mempolicy` flags (`:46`).
pub const MPOL_F_NODE: u64 = 1 << 0;
pub const MPOL_F_ADDR: u64 = 1 << 1;
pub const MPOL_F_MEMS_ALLOWED: u64 = 1 << 2;
pub const MPOL_F_GET_VALID: u64 = MPOL_F_NODE | MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED;

/// `mbind`/`move_pages` flags (`:51`).
pub const MPOL_MF_STRICT: u64 = 1 << 0;
pub const MPOL_MF_MOVE: u64 = 1 << 1;
pub const MPOL_MF_MOVE_ALL: u64 = 1 << 2;
pub const MPOL_MF_LAZY: u64 = 1 << 3;
/// `MPOL_MF_VALID` (`:58`) — MPOL_MF_LAZY is deliberately NOT in it.
pub const MPOL_MF_VALID: u64 = MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_MOVE_ALL;
/// `move_pages` accepts only the two MOVE bits (`mm/migrate.c:2601`).
pub const MPOL_MF_MOVE_VALID: u64 = MPOL_MF_MOVE | MPOL_MF_MOVE_ALL;

/// `NUMA_NO_NODE` (`include/linux/numa.h`).
pub const NUMA_NO_NODE: i32 = -1;

/// `MAX_NUMNODES` = `1 << CONFIG_NODES_SHIFT`. oxide pins NODES_SHIFT=6, the
/// upstream x86_64 default (`arch/x86/Kconfig:1546`), so a nodemask is exactly
/// one `unsigned long` and `MAX_NUMNODES % BITS_PER_LONG == 0` — the condition
/// `get_nodes`' overflow-word masking depends on.
pub const MAX_NUMNODES: u64 = 64;

/// `nr_node_ids` — nodes actually possible on this machine. oxide's PMM is
/// single-node UMA, so 1. `kernel_get_mempolicy` compares `maxnode` against
/// this, and `copy_nodes_to_user` clamps its copy length to it.
pub const NR_NODE_IDS: u64 = 1;

/// The one node id that exists. `node_states[N_MEMORY]` == { NODE_ID_LOCAL }.
pub const NODE_ID_LOCAL: u16 = 0;

/// `BITS_PER_LONG`.
pub const BITS_PER_LONG: u64 = 64;
/// `PAGE_SIZE * BITS_PER_BYTE` — `get_nodes`' hard ceiling on `maxnode - 1`
/// (`mm/mempolicy.c:1665`).
pub const MAX_NODEMASK_BITS: u64 = 4096 * 8;
/// `PAGE_SIZE` — `copy_nodes_to_user`'s ceiling on the byte count it will
/// zero-fill past `nr_node_ids` (`mm/mempolicy.c:1704`).
pub const NODEMASK_COPY_MAX_BYTES: u64 = 4096;
