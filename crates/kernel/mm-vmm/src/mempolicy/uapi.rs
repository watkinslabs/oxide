// NUMA memory-policy UAPI: mode/flag numbers as exposed by set_mempolicy(2),
// mbind(2), get_mempolicy(2). Numbers only — the admission ladders live in
// `policy.rs`, the bitmap conventions in `nodemask.rs`.

/// Policy mode enum values, as returned/accepted by the mempolicy syscalls.
pub const MPOL_DEFAULT: u16 = 0;
pub const MPOL_PREFERRED: u16 = 1;
pub const MPOL_BIND: u16 = 2;
pub const MPOL_INTERLEAVE: u16 = 3;
pub const MPOL_LOCAL: u16 = 4;
pub const MPOL_PREFERRED_MANY: u16 = 5;
pub const MPOL_WEIGHTED_INTERLEAVE: u16 = 6;
/// Always last member of the enum — `sanitize_mpol_flags` rejects `>=` this.
pub const MPOL_MAX: u16 = 7;

/// Optional mode flags packed into the mode word by set_mempolicy/mbind.
pub const MPOL_F_STATIC_NODES: u16 = 1 << 15;
pub const MPOL_F_RELATIVE_NODES: u16 = 1 << 14;
pub const MPOL_F_NUMA_BALANCING: u16 = 1 << 13;
/// Mask of the mode flags a caller may OR into the mode word.
pub const MPOL_MODE_FLAGS: u16 =
    MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES | MPOL_F_NUMA_BALANCING;
/// The two flags that make the kernel keep the RAW user nodemask alongside
/// the effective one, so `get_mempolicy` reports back exactly what was
/// passed in.
pub const MPOL_USER_NODEMASK_FLAGS: u16 = MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES;

/// Internal flags sharing the policy flags word. Never OR'ed into a mode
/// argument by userspace; masked off with `MPOL_MODE_FLAGS` before a policy's
/// flags are exposed back to userspace.
pub const MPOL_F_SHARED: u16 = 1 << 0;
pub const MPOL_F_MOF: u16 = 1 << 3;
pub const MPOL_F_MORON: u16 = 1 << 4;

/// `get_mempolicy(2)` flags argument bits.
pub const MPOL_F_NODE: u64 = 1 << 0;
pub const MPOL_F_ADDR: u64 = 1 << 1;
pub const MPOL_F_MEMS_ALLOWED: u64 = 1 << 2;
pub const MPOL_F_GET_VALID: u64 = MPOL_F_NODE | MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED;

/// `mbind(2)`/`move_pages(2)` flags argument bits.
pub const MPOL_MF_STRICT: u64 = 1 << 0;
pub const MPOL_MF_MOVE: u64 = 1 << 1;
pub const MPOL_MF_MOVE_ALL: u64 = 1 << 2;
pub const MPOL_MF_LAZY: u64 = 1 << 3;
/// Full valid `mbind` flag set — MPOL_MF_LAZY is deliberately NOT in it (it
/// is accepted historically but no longer acted on).
pub const MPOL_MF_VALID: u64 = MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_MOVE_ALL;
/// `move_pages` accepts only the two MOVE bits, not STRICT.
pub const MPOL_MF_MOVE_VALID: u64 = MPOL_MF_MOVE | MPOL_MF_MOVE_ALL;

/// Sentinel meaning "no specific node" / "not yet assigned a node".
pub const NUMA_NO_NODE: i32 = -1;

/// Max representable NUMA node count, fixed at the standard x86_64 default so
/// a nodemask is exactly one `unsigned long` and `MAX_NUMNODES % BITS_PER_LONG
/// == 0` — the condition the overflow-word masking in `get_nodes`-equivalent
/// code depends on.
pub const MAX_NUMNODES: u64 = 64;

/// Nodes actually possible on this machine. oxide's PMM is single-node UMA,
/// so 1. `get_mempolicy` compares the caller's `maxnode` against this, and
/// the nodemask-to-user copy clamps its length to it.
pub const NR_NODE_IDS: u64 = 1;

/// The one node id that exists on a single-node UMA machine.
pub const NODE_ID_LOCAL: u16 = 0;

/// Bits in a native word — a nodemask is a bitmap of these.
pub const BITS_PER_LONG: u64 = 64;
/// `PAGE_SIZE * BITS_PER_BYTE` — hard ceiling on the caller's `maxnode - 1`
/// when reading a user nodemask.
pub const MAX_NODEMASK_BITS: u64 = 4096 * 8;
/// `PAGE_SIZE` — ceiling on the byte count zero-filled past `nr_node_ids`
/// when copying a nodemask back to userspace.
pub const NODEMASK_COPY_MAX_BYTES: u64 = 4096;
