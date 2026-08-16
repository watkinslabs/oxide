// Generic-netlink family registry: the name -> id map every client resolves
// through `nlctrl` before it can address a family at all.
//
// Two id spaces are kept here. Family ids run `GENL_START_ALLOC..=GENL_MAX_ID`
// with three static reservations; multicast-group ids are a single flat space
// shared by ALL families (a socket subscribes to a group NUMBER, not to a
// family), pre-reserving 0, NET_DM's 1, and the three static family ids.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use sync::{Socket as SockLockClass, Spinlock};

use super::uapi::*;

/// Context a command handler needs about the request it is serving, gathered
/// by the transport so a handler never reaches for the current task.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GenlCtx {
    /// Network namespace the sending socket is in.
    pub net_ns: u64,
    /// Netlink port the request came from, and that a reply is addressed to.
    pub portid: u32,
    /// Family id serving the request.
    pub family_id: u16,
    /// Capability answers the permission ladder already consumed, so a
    /// handler with a per-object check does not have to re-resolve them.
    pub init_ns_net_admin: bool,
    pub sock_ns_net_admin: bool,
}

/// A command handler. Returns the full reply — a message, an `NLMSG_ERROR`,
/// or nothing.
pub type GenlDoit = fn(&crate::Nlmsghdr, &[u8], GenlCtx) -> Vec<u8>;

/// One command a family accepts, with its permission and capability flags.
///
/// A family whose handlers live outside this crate supplies them here, the
/// way a generic-netlink family supplies its own `doit`. Without that the
/// dispatcher would need to know every family by name, which is a second
/// registry beside this one.
#[derive(Clone, Debug)]
pub struct GenlOp {
    pub cmd:   u8,
    /// `GENL_CMD_CAP_*` | `GENL_*ADMIN_PERM` bits.
    pub flags: u32,
    /// Attribute validation policy reported by `CTRL_CMD_GETPOLICY`.
    pub policy: &'static [PolicyEntry],
    /// Handler for a non-dump request.
    pub doit: Option<GenlDoit>,
    /// Handler for a dump request.
    pub dumpit: Option<GenlDoit>,
}

/// Two ops are the same command when they agree on the number, the flags and
/// the policy, and on whether the family serves it itself. Handler ADDRESSES
/// are deliberately not compared: a function's address is not stable across
/// codegen units, so comparing them would make equality depend on the build.
impl PartialEq for GenlOp {
    fn eq(&self, other: &Self) -> bool {
        self.cmd == other.cmd && self.flags == other.flags && self.policy == other.policy
            && self.doit.is_some() == other.doit.is_some()
            && self.dumpit.is_some() == other.dumpit.is_some()
    }
}
impl Eq for GenlOp {}

impl GenlOp {
    /// A command with no handler of its own — served by the controller, or by
    /// nothing yet.
    pub const EMPTY: GenlOp =
        GenlOp { cmd: 0, flags: 0, policy: &[], doit: None, dumpit: None };

    /// A command served by handlers this family supplies. # C: O(1)
    pub const fn with_handlers(cmd: u8, flags: u32, policy: &'static [PolicyEntry],
                               doit: Option<GenlDoit>, dumpit: Option<GenlDoit>) -> Self {
        Self { cmd, flags, policy, doit, dumpit }
    }
}

/// One attribute's validation rule inside an op policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyEntry {
    pub attr:     u16,
    pub kind:     u32,
    pub min_len:  u32,
    pub max_len:  u32,
}

/// One registered multicast group. `id` is the flat group-space number a
/// socket passes to `NETLINK_ADD_MEMBERSHIP`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenlMcastGroup {
    pub name: String,
    pub id:   u32,
}

/// A registered generic-netlink family.
#[derive(Clone, Debug)]
pub struct GenlFamily {
    pub id:      u16,
    pub name:    String,
    pub version: u8,
    pub hdrsize: u8,
    pub maxattr: u16,
    pub ops:     Vec<GenlOp>,
    pub mcgrps:  Vec<GenlMcastGroup>,
    /// First multicast-group id owned by this family; group INDEX `i` in
    /// `genlmsg_multicast_*` is group id `mcgrp_offset + i`.
    pub mcgrp_offset: u32,
    /// Reachable from every network namespace, not just the initial one.
    pub netnsok: bool,
    /// First command validated against the strict genetlink header rules.
    pub resv_start_op: u8,
}

impl GenlFamily {
    /// Command entry for `cmd`, if the family accepts it. # C: O(N ops)
    pub fn op(&self, cmd: u8) -> Option<&GenlOp> { self.ops.iter().find(|o| o.cmd == cmd) }
    /// Group id for a family-relative group INDEX. # C: O(1)
    pub fn group_id(&self, index: usize) -> Option<u32> {
        (index < self.mcgrps.len()).then(|| self.mcgrp_offset + index as u32)
    }
}

/// What a caller asks `register_family` to create.
pub struct GenlFamilySpec {
    pub name:    &'static str,
    pub version: u8,
    pub hdrsize: u8,
    pub maxattr: u16,
    pub ops:     Vec<GenlOp>,
    pub mcgrps:  Vec<&'static str>,
    pub netnsok: bool,
    pub resv_start_op: u8,
}

/// Registration failure, in Linux's errno vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenlRegError {
    /// Family name already registered.
    Eexist,
    /// Op table, group name, or family name violates the registration contract.
    Einval,
    /// Family-id or multicast-group-id space exhausted.
    Enospc,
    /// No such family.
    Enoent,
}

struct Registry {
    families:  Vec<GenlFamily>,
    /// Allocated multicast-group ids, one bit per id.
    group_ids: Vec<u32>,
    /// Cyclic family-id allocation cursor.
    next_id:   u16,
}

const GROUP_ID_BITS: u32 = 32;

impl Registry {
    const fn new() -> Self {
        Self { families: Vec::new(), group_ids: Vec::new(), next_id: GENL_START_ALLOC }
    }

    fn group_taken(&self, id: u32) -> bool {
        // Ids 0, NET_DM's 1, and the three static family ids are permanently
        // reserved so those families can keep id == group id.
        if id == 0 || id == GENL_GRP_ID_NET_DM { return true; }
        if id == GENL_ID_CTRL as u32 || id == GENL_ID_VFS_DQUOT as u32
            || id == GENL_ID_PMCRAID as u32 { return true; }
        let (w, b) = ((id / GROUP_ID_BITS) as usize, id % GROUP_ID_BITS);
        self.group_ids.get(w).is_some_and(|word| word & (1u32 << b) != 0)
    }

    fn group_set(&mut self, id: u32) {
        let (w, b) = ((id / GROUP_ID_BITS) as usize, id % GROUP_ID_BITS);
        if self.group_ids.len() <= w { self.group_ids.resize(w + 1, 0); }
        self.group_ids[w] |= 1u32 << b;
    }

    fn group_clear(&mut self, id: u32) {
        let (w, b) = ((id / GROUP_ID_BITS) as usize, id % GROUP_ID_BITS);
        if let Some(word) = self.group_ids.get_mut(w) { *word &= !(1u32 << b); }
    }

    /// Highest allocated group id + 1 — the socket-visible group count.
    fn ngroups(&self) -> u32 {
        self.families.iter()
            .map(|f| f.mcgrp_offset + f.mcgrps.len() as u32)
            .max().unwrap_or(0)
    }

    /// Reserve `n` CONTIGUOUS free group ids and return the first.
    fn allocate_groups(&mut self, n: usize) -> Result<u32, GenlRegError> {
        if n == 0 { return Ok(0); }
        let mut start = GENL_GRP_ID_MIN;
        // Group ids are unbounded in netlink; a scan that has to walk past
        // every family's reservation still terminates on the first free run.
        let limit = GENL_GRP_ID_MIN + (self.ngroups() + n as u32) * 2 + GROUP_ID_BITS;
        while start < limit {
            let fits = (0..n as u32).all(|i| !self.group_taken(start + i));
            if fits {
                for i in 0..n as u32 { self.group_set(start + i); }
                return Ok(start);
            }
            start += 1;
        }
        Err(GenlRegError::Enospc)
    }

    /// Cyclic family-id allocation over `GENL_START_ALLOC..=GENL_MAX_ID`.
    fn allocate_id(&mut self) -> Result<u16, GenlRegError> {
        let span = GENL_MAX_ID - GENL_START_ALLOC + 1;
        for _ in 0..span {
            let id = self.next_id;
            self.next_id = if id >= GENL_MAX_ID { GENL_START_ALLOC } else { id + 1 };
            if !self.families.iter().any(|f| f.id == id) { return Ok(id); }
        }
        Err(GenlRegError::Enospc)
    }
}

static REGISTRY: Spinlock<Registry, SockLockClass> = Spinlock::new(Registry::new());

/// Statically reserved family id for a name, if it has one. # C: O(1)
fn reserved_id(name: &str) -> Option<u16> {
    match name {
        CTRL_FAMILY_NAME => Some(GENL_ID_CTRL),
        "VFS_DQUOT"      => Some(GENL_ID_VFS_DQUOT),
        "pmcraid"        => Some(GENL_ID_PMCRAID),
        _                => None,
    }
}

/// Statically reserved FIRST multicast-group id for a family, if it has one.
/// # C: O(1)
fn reserved_group(name: &str, id: u16) -> Option<u32> {
    if let Some(reserved) = reserved_id(name) { if reserved == id { return Some(id as u32); } }
    if name == "NET_DM" { return Some(GENL_GRP_ID_NET_DM); }
    None
}

fn validate(spec: &GenlFamilySpec) -> Result<(), GenlRegError> {
    if spec.name.is_empty() || spec.name.len() >= GENL_NAMSIZ { return Err(GenlRegError::Einval); }
    for grp in &spec.mcgrps {
        if grp.is_empty() || grp.len() >= GENL_NAMSIZ { return Err(GenlRegError::Einval); }
    }
    // Every op must declare at least one of doit / dumpit; a family reserving
    // more than one group cannot use a static single-group reservation.
    for op in &spec.ops {
        if op.flags & (op_flags::GENL_CMD_CAP_DO | op_flags::GENL_CMD_CAP_DUMP) == 0 {
            return Err(GenlRegError::Einval);
        }
    }
    if reserved_group(spec.name, reserved_id(spec.name).unwrap_or(0)).is_some()
        && spec.mcgrps.len() > 1
    { return Err(GenlRegError::Einval); }
    Ok(())
}

/// Register a family: allocate its id and group ids, then announce it on the
/// `nlctrl` notify group. # C: O(N families + N groups)
pub fn register_family(spec: GenlFamilySpec) -> Result<u16, GenlRegError> {
    validate(&spec)?;
    let family = {
        let mut g = REGISTRY.lock();
        if g.families.iter().any(|f| f.name == spec.name) { return Err(GenlRegError::Eexist); }
        let id = match reserved_id(spec.name) {
            Some(id) if !g.families.iter().any(|f| f.id == id) => id,
            Some(_) => return Err(GenlRegError::Eexist),
            None    => g.allocate_id()?,
        };
        let mcgrp_offset = match reserved_group(spec.name, id) {
            Some(first) => first,
            None        => g.allocate_groups(spec.mcgrps.len())?,
        };
        let family = GenlFamily {
            id,
            name: String::from(spec.name),
            version: spec.version,
            hdrsize: spec.hdrsize,
            maxattr: spec.maxattr,
            ops: spec.ops,
            mcgrps: spec.mcgrps.iter().enumerate()
                .map(|(i, name)| GenlMcastGroup {
                    name: String::from(*name), id: mcgrp_offset + i as u32,
                }).collect(),
            mcgrp_offset,
            netnsok: spec.netnsok,
            resv_start_op: spec.resv_start_op,
        };
        g.families.push(family.clone());
        family
    };
    super::ctrl::announce_new_family(&family);
    Ok(family.id)
}

/// Unregister a family, releasing its group ids and announcing the removal.
/// # C: O(N families)
pub fn unregister_family(id: u16) -> Result<(), GenlRegError> {
    let family = {
        let mut g = REGISTRY.lock();
        let Some(pos) = g.families.iter().position(|f| f.id == id) else {
            return Err(GenlRegError::Enoent);
        };
        let family = g.families.remove(pos);
        if reserved_group(&family.name, family.id).is_none() {
            for grp in &family.mcgrps { g.group_clear(grp.id); }
        }
        family
    };
    super::ctrl::announce_del_family(&family);
    Ok(())
}

/// Family registered under `name`. # C: O(N families)
pub fn find_by_name(name: &str) -> Option<GenlFamily> {
    REGISTRY.lock().families.iter().find(|f| f.name == name).cloned()
}

/// Family registered under `id`. # C: O(N families)
pub fn find_by_id(id: u16) -> Option<GenlFamily> {
    REGISTRY.lock().families.iter().find(|f| f.id == id).cloned()
}

/// Every registered family, in registration order. # C: O(N families)
pub fn snapshot_families() -> Vec<GenlFamily> { REGISTRY.lock().families.clone() }

/// Multicast-group count a NETLINK_GENERIC socket may subscribe within — the
/// highest allocated group id plus one, floored at netlink's per-protocol
/// minimum. # C: O(N families)
pub fn mcast_ngroups() -> u32 {
    REGISTRY.lock().ngroups().max(crate::groups::NETLINK_MIN_NGROUPS)
}
