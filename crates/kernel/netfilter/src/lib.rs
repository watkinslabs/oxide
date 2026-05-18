// Netfilter / nftables substrate per Linux `linux/netfilter/nfnetlink.h`
// + `linux/netfilter/nf_tables.h`. v1 surface = NFNL message dispatch
// + in-memory storage so `nft list ruleset`, `nft add table`, etc.
// round-trip without lying. Packet-path enforcement (NF_INET_LOCAL_IN
// hook execution against the rule set) is a separate follow-up.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;

use sync::{Spinlock, Socket as SockLockClass};

use ::netlink::{flags, msg, nlmsg_align, Nlmsghdr};

/// 4-byte `struct nfgenmsg` per `linux/netfilter/nfnetlink.h`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Nfgenmsg {
    pub nfgen_family: u8,
    pub version:      u8,
    pub res_id:       u16, // big-endian on wire
}

impl Nfgenmsg {
    pub const SIZE: usize = 4;

    /// # C: O(1)
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE { return None; }
        Some(Self {
            nfgen_family: buf[0],
            version:      buf[1],
            res_id:       u16::from_be_bytes([buf[2], buf[3]]),
        })
    }
    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.nfgen_family;
        buf[1] = self.version;
        buf[2..4].copy_from_slice(&self.res_id.to_be_bytes());
    }
}

/// NFNL subsystem ids per Linux. Encoded in the high byte of
/// `nlmsghdr.nlmsg_type`; low byte holds the per-subsys command.
pub mod subsys {
    pub const NFNL_SUBSYS_NONE:        u8 = 0;
    pub const NFNL_SUBSYS_CTNETLINK:   u8 = 1;
    pub const NFNL_SUBSYS_QUEUE:       u8 = 3;
    pub const NFNL_SUBSYS_ULOG:        u8 = 4;
    pub const NFNL_SUBSYS_OSF:         u8 = 5;
    pub const NFNL_SUBSYS_IPSET:       u8 = 6;
    pub const NFNL_SUBSYS_ACCT:        u8 = 7;
    pub const NFNL_SUBSYS_CTNETLINK_TIMEOUT: u8 = 8;
    pub const NFNL_SUBSYS_CTHELPER:    u8 = 9;
    pub const NFNL_SUBSYS_NFTABLES:    u8 = 10;
    pub const NFNL_SUBSYS_NFT_COMPAT:  u8 = 11;
    pub const NFNL_SUBSYS_HOOK:        u8 = 12;
}

/// nf_tables (NFNL_SUBSYS_NFTABLES) command ids per Linux
/// `linux/netfilter/nf_tables.h::nft_msg_types`.
pub mod nft_msg {
    pub const NFT_MSG_NEWTABLE:    u8 = 0;
    pub const NFT_MSG_GETTABLE:    u8 = 1;
    pub const NFT_MSG_DELTABLE:    u8 = 2;
    pub const NFT_MSG_NEWCHAIN:    u8 = 3;
    pub const NFT_MSG_GETCHAIN:    u8 = 4;
    pub const NFT_MSG_DELCHAIN:    u8 = 5;
    pub const NFT_MSG_NEWRULE:     u8 = 6;
    pub const NFT_MSG_GETRULE:     u8 = 7;
    pub const NFT_MSG_DELRULE:     u8 = 8;
    pub const NFT_MSG_NEWSET:      u8 = 9;
    pub const NFT_MSG_GETSET:      u8 = 10;
    pub const NFT_MSG_DELSET:      u8 = 11;
    pub const NFT_MSG_NEWGEN:      u8 = 15;
    pub const NFT_MSG_GETGEN:      u8 = 16;
    pub const NFT_MSG_NEWOBJ:      u8 = 18;
    pub const NFT_MSG_GETOBJ:      u8 = 19;
    pub const NFT_MSG_DELOBJ:      u8 = 20;
}

/// nft object attribute ids per Linux `nf_tables.h::nft_object_attributes`.
pub mod nfta_obj {
    pub const NFTA_OBJ_TABLE:  u16 = 1;
    pub const NFTA_OBJ_NAME:   u16 = 2;
    pub const NFTA_OBJ_TYPE:   u16 = 3;  // counter / quota / limit / ...
    pub const NFTA_OBJ_DATA:   u16 = 4;
    pub const NFTA_OBJ_USE:    u16 = 5;
    pub const NFTA_OBJ_HANDLE: u16 = 6;
}

/// nft generation attribute ids (NEWGEN replies).
pub mod nfta_gen {
    pub const NFTA_GEN_ID:    u16 = 1;
    pub const NFTA_GEN_PROC_PID:  u16 = 2;
    pub const NFTA_GEN_PROC_NAME: u16 = 3;
}

/// nft table attribute ids.
pub mod nfta_table {
    pub const NFTA_TABLE_NAME:   u16 = 1;
    pub const NFTA_TABLE_FLAGS:  u16 = 2;
    pub const NFTA_TABLE_USE:    u16 = 3;
}

/// nft set attribute ids per Linux `nf_tables.h::nft_set_attributes`.
pub mod nfta_set {
    pub const NFTA_SET_TABLE:        u16 = 1;
    pub const NFTA_SET_NAME:         u16 = 2;
    pub const NFTA_SET_FLAGS:        u16 = 3;
    pub const NFTA_SET_KEY_TYPE:     u16 = 4;
    pub const NFTA_SET_KEY_LEN:      u16 = 5;
    pub const NFTA_SET_DATA_TYPE:    u16 = 6;
    pub const NFTA_SET_DATA_LEN:     u16 = 7;
    pub const NFTA_SET_POLICY:       u16 = 8;
    pub const NFTA_SET_DESC:         u16 = 9;
    pub const NFTA_SET_ID:           u16 = 10;
    pub const NFTA_SET_TIMEOUT:      u16 = 11;
    pub const NFTA_SET_USERDATA:     u16 = 13;
}

/// nft rule attribute ids per Linux `nf_tables.h::nft_rule_attributes`.
pub mod nfta_rule {
    pub const NFTA_RULE_TABLE:        u16 = 1;
    pub const NFTA_RULE_CHAIN:        u16 = 2;
    pub const NFTA_RULE_HANDLE:       u16 = 3;
    pub const NFTA_RULE_EXPRESSIONS:  u16 = 4;
    pub const NFTA_RULE_COMPAT:       u16 = 5;
    pub const NFTA_RULE_POSITION:     u16 = 6;
    pub const NFTA_RULE_USERDATA:     u16 = 7;
    pub const NFTA_RULE_ID:           u16 = 9;
}

/// nft chain attribute ids per Linux `nf_tables.h::nft_chain_attributes`.
pub mod nfta_chain {
    pub const NFTA_CHAIN_TABLE:  u16 = 1;
    pub const NFTA_CHAIN_HANDLE: u16 = 2;
    pub const NFTA_CHAIN_NAME:   u16 = 3;
    pub const NFTA_CHAIN_HOOK:   u16 = 4;
    pub const NFTA_CHAIN_POLICY: u16 = 5;
    pub const NFTA_CHAIN_USE:    u16 = 6;
    pub const NFTA_CHAIN_TYPE:   u16 = 7;
    pub const NFTA_CHAIN_COUNTERS: u16 = 8;
    pub const NFTA_CHAIN_FLAGS:  u16 = 9;
    pub const NFTA_CHAIN_ID:     u16 = 11;
}

// ---- In-memory storage --------------------------------------------------

#[derive(Clone, Debug)]
pub struct NftTable {
    pub family: u8,
    pub name:   String,
    pub flags:  u32,
}

#[derive(Clone, Debug)]
pub struct NftChain {
    pub table_family: u8,
    pub table_name:   String,
    pub name:         String,
    /// Some(hook_id) iff this is a base chain (registered to a
    /// netfilter hook); None for regular chains (only callable
    /// via jump/goto from another rule).
    pub hook:         Option<u32>,
    /// Hook priority. Linux uses signed i32 (NF_IP_PRI_FILTER = 0,
    /// NF_IP_PRI_MANGLE = -150, etc.). We sort ascending on eval.
    pub priority:     i32,
    /// Default verdict when no rule in this chain matches.
    /// NF_DROP = 0, NF_ACCEPT = 1. v1 stores as u32.
    pub policy:       u32,
}

/// Netfilter verdict per `linux/netfilter.h`. Returned by every
/// hook handler; the net-stack callsite decides whether to deliver
/// the packet based on this.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// `NF_DROP` — discard the packet.
    Drop,
    /// `NF_ACCEPT` — pass the packet through to the next layer.
    Accept,
    /// `NF_STOLEN` — handler took ownership (e.g. nf_queue). Net
    /// stack must not deliver or free; the hook will dispose.
    Stolen,
    /// `NF_QUEUE` — userspace queue handler (number embedded).
    Queue(u16),
    /// `NF_REPEAT` — re-run the same hook; v1 treats as Accept.
    Repeat,
}

impl Verdict {
    /// Linux returns NF_DROP=0 / NF_ACCEPT=1 / NF_STOLEN=2 /
    /// NF_QUEUE=3 / NF_REPEAT=4 packed into a u32 (high 16 bits
    /// hold the queue number for NF_QUEUE).
    /// # C: O(1)
    pub fn as_u32(self) -> u32 {
        match self {
            Verdict::Drop      => 0,
            Verdict::Accept    => 1,
            Verdict::Stolen    => 2,
            Verdict::Queue(q)  => 3 | ((q as u32) << 16),
            Verdict::Repeat    => 4,
        }
    }
}

/// Netfilter hook ids per Linux `nf_inet_hooks`. v1 covers the
/// inet protocol family (IPv4/IPv6 share the same numbers).
pub mod hook {
    pub const NF_INET_PRE_ROUTING:  u32 = 0;
    pub const NF_INET_LOCAL_IN:     u32 = 1;
    pub const NF_INET_FORWARD:      u32 = 2;
    pub const NF_INET_LOCAL_OUT:    u32 = 3;
    pub const NF_INET_POST_ROUTING: u32 = 4;
    pub const NF_INET_NUM_HOOKS:    u32 = 5;
}

/// Default chain policy values.
pub const NFT_CHAIN_POLICY_ACCEPT: u32 = 1; // matches Linux NF_ACCEPT
pub const NFT_CHAIN_POLICY_DROP:   u32 = 0; // matches Linux NF_DROP

/// Walk every base chain attached to `hook_id` (sorted ascending
/// by `priority`), run its rules against `pkt`, and return the
/// first non-Accept verdict (or the chain's `policy` if no rule
/// matches).
///
/// v1 rule-expression interpreter is a stub: every rule evaluates
/// to "no match" so chain policy alone decides the verdict. The
/// real `NFTA_RULE_EXPRESSIONS` decoder (NFT_PAYLOAD / NFT_CMP /
/// NFT_IMMEDIATE) rides a follow-up. So today policy=accept means
/// Accept, policy=drop means Drop — a real packet filter.
///
/// `_pkt` is the raw L2/L3 bytes; the future expression
/// interpreter inspects it.
/// # C: O(N_chains) policy-only today; O(N_chains × N_rules) once expression eval lands
pub fn eval(hook_id: u32, _pkt: &[u8]) -> Verdict {
    let mut chains: Vec<NftChain> = CHAINS.lock().clone();
    chains.retain(|c| c.hook == Some(hook_id));
    chains.sort_by_key(|c| c.priority);
    for c in chains.iter() {
        // v1: every rule "doesn't match"; chain policy is the
        // verdict. Future PR walks RULES with c.chain_name and
        // interprets the expression payload.
        match c.policy {
            NFT_CHAIN_POLICY_DROP => return Verdict::Drop,
            _ => continue, // Accept-style policy: try next chain
        }
    }
    Verdict::Accept
}

#[derive(Clone, Debug)]
pub struct NftRule {
    pub table_family: u8,
    pub table_name:   String,
    pub chain_name:   String,
    pub handle:       u64,
    pub raw_expr:     Vec<u8>, // opaque NFTA_RULE_EXPRESSIONS payload
}

static TABLES: Spinlock<Vec<NftTable>, SockLockClass> = Spinlock::new(Vec::new());
static CHAINS: Spinlock<Vec<NftChain>, SockLockClass> = Spinlock::new(Vec::new());
static RULES:  Spinlock<Vec<NftRule>,  SockLockClass> = Spinlock::new(Vec::new());
static SETS:   Spinlock<Vec<NftSet>,   SockLockClass> = Spinlock::new(Vec::new());

#[derive(Clone, Debug)]
pub struct NftSet {
    pub table_family: u8,
    pub table_name:   String,
    pub name:         String,
    pub key_type:     u32,
    pub key_len:      u32,
    pub data_type:    u32,
    pub data_len:     u32,
    pub flags:        u32,
}

/// # C: O(N)
pub fn set_insert(s: NftSet) {
    let mut g = SETS.lock();
    if let Some(i) = g.iter().position(|x|
        x.table_family == s.table_family
        && x.table_name == s.table_name
        && x.name == s.name)
    { g[i] = s; } else { g.push(s); }
}
/// # C: O(N)
pub fn set_remove(family: u8, table_name: &str, set_name: &str) -> usize {
    let mut g = SETS.lock();
    let before = g.len();
    g.retain(|x| !(x.table_family == family
                   && x.table_name == table_name
                   && x.name == set_name));
    before - g.len()
}
/// # C: O(N)
pub fn sets_snapshot() -> Vec<NftSet> { SETS.lock().clone() }

#[derive(Clone, Debug)]
pub struct NftObject {
    pub table_family: u8,
    pub table_name:   String,
    pub name:         String,
    pub ty:           u32,    // NFT_OBJECT_COUNTER / QUOTA / LIMIT / ...
    pub data:         Vec<u8>, // opaque per-type NFTA_OBJ_DATA payload
}

static OBJECTS: Spinlock<Vec<NftObject>, SockLockClass> =
    Spinlock::new(Vec::new());

/// # C: O(N)
pub fn object_insert(o: NftObject) {
    let mut g = OBJECTS.lock();
    if let Some(i) = g.iter().position(|x|
        x.table_family == o.table_family
        && x.table_name == o.table_name
        && x.name == o.name)
    { g[i] = o; } else { g.push(o); }
}
/// # C: O(N)
pub fn object_remove(family: u8, table_name: &str, obj_name: &str) -> usize {
    let mut g = OBJECTS.lock();
    let before = g.len();
    g.retain(|x| !(x.table_family == family
                   && x.table_name == table_name
                   && x.name == obj_name));
    before - g.len()
}
/// # C: O(N)
pub fn objects_snapshot() -> Vec<NftObject> { OBJECTS.lock().clone() }

/// Nftables generation counter. `nft` bumps it across every commit
/// transaction so userspace can detect concurrent edits. Each
/// successful write-side handler (NEWTABLE/CHAIN/RULE/SET/OBJ)
/// `gen_bump()`s; GETGEN reads.
static NFT_GEN: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// # C: O(1)
pub fn gen_current() -> u32 {
    NFT_GEN.load(core::sync::atomic::Ordering::Acquire)
}
/// # C: O(1)
pub fn gen_bump() -> u32 {
    NFT_GEN.fetch_add(1, core::sync::atomic::Ordering::AcqRel) + 1
}

static NEXT_RULE_HANDLE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(1);

/// # C: O(1)
pub fn next_rule_handle() -> u64 {
    NEXT_RULE_HANDLE.fetch_add(1, core::sync::atomic::Ordering::AcqRel)
}

/// # C: O(N) name scan
pub fn table_insert(t: NftTable) {
    let mut g = TABLES.lock();
    if let Some(i) = g.iter().position(|x| x.family == t.family && x.name == t.name) {
        g[i] = t;
    } else {
        g.push(t);
    }
}
/// # C: O(N)
pub fn table_remove(family: u8, name: &str) -> usize {
    let mut g = TABLES.lock();
    let before = g.len();
    g.retain(|x| !(x.family == family && x.name == name));
    before - g.len()
}
/// # C: O(N)
pub fn tables_snapshot() -> Vec<NftTable> { TABLES.lock().clone() }

/// # C: O(N)
pub fn chain_insert(c: NftChain) {
    let mut g = CHAINS.lock();
    if let Some(i) = g.iter().position(|x|
        x.table_family == c.table_family
        && x.table_name == c.table_name
        && x.name == c.name)
    { g[i] = c; } else { g.push(c); }
}
/// # C: O(N)
pub fn chain_remove(family: u8, table_name: &str, chain_name: &str) -> usize {
    let mut g = CHAINS.lock();
    let before = g.len();
    g.retain(|x| !(x.table_family == family
                   && x.table_name == table_name
                   && x.name == chain_name));
    before - g.len()
}
/// # C: O(N)
pub fn chains_snapshot() -> Vec<NftChain> { CHAINS.lock().clone() }

/// # C: O(1) handle alloc
pub fn rule_insert(r: NftRule) -> u64 {
    let h = r.handle;
    RULES.lock().push(r);
    h
}
/// # C: O(N)
pub fn rule_remove(family: u8, table_name: &str, chain_name: &str, handle: u64) -> usize {
    let mut g = RULES.lock();
    let before = g.len();
    g.retain(|r| !(r.table_family == family
                   && r.table_name == table_name
                   && r.chain_name == chain_name
                   && r.handle == handle));
    before - g.len()
}
/// # C: O(N)
pub fn rules_snapshot() -> Vec<NftRule> { RULES.lock().clone() }

// ---- nlattr helpers (private to this crate) -----------------------------

fn put_nlattr(out: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let total = 4 + payload.len();
    out.extend_from_slice(&(total as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(payload);
    let pad = nlmsg_align(total) - total;
    for _ in 0..pad { out.push(0); }
}
fn put_nlattr_u32(out: &mut Vec<u8>, ty: u16, v: u32) {
    put_nlattr(out, ty, &v.to_be_bytes()); // nft attrs are big-endian
}
fn put_nlattr_str(out: &mut Vec<u8>, ty: u16, s: &str) {
    let mut payload: Vec<u8> = Vec::with_capacity(s.len() + 1);
    payload.extend_from_slice(s.as_bytes());
    payload.push(0);
    put_nlattr(out, ty, &payload);
}

fn find_str_attr<'a>(attrs: &'a [u8], target: u16) -> Option<&'a str> {
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]);
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        if nla_type == target {
            let payload = &attrs[off + 4..off + nla_len];
            let end = payload.iter().position(|&b| b == 0).unwrap_or(payload.len());
            return core::str::from_utf8(&payload[..end]).ok();
        }
        off += nlmsg_align(nla_len);
    }
    None
}

fn nlmsg_ack(req: &Nlmsghdr, err: i32) -> Vec<u8> {
    let total = Nlmsghdr::SIZE + 4 + Nlmsghdr::SIZE;
    let hdr = Nlmsghdr {
        nlmsg_len:   total as u32,
        nlmsg_type:  msg::NLMSG_ERROR,
        nlmsg_flags: 0,
        nlmsg_seq:   req.nlmsg_seq,
        nlmsg_pid:   req.nlmsg_pid,
    };
    let mut out = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&err.to_ne_bytes());
    let mut req_buf = [0u8; Nlmsghdr::SIZE];
    req.write_to(&mut req_buf);
    out.extend_from_slice(&req_buf);
    out
}

/// Build a NFT_MSG_NEWTABLE reply describing one table.
/// # C: O(1)
fn build_newtable_reply(seq: u32, pid: u32, t: &NftTable, multi: bool) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(64);
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg {
        nfgen_family: t.family,
        version:      0,
        res_id:       0,
    }.write_to(&mut nfg_buf);
    body.extend_from_slice(&nfg_buf);

    put_nlattr_str(&mut body, nfta_table::NFTA_TABLE_NAME, &t.name);
    put_nlattr_u32(&mut body, nfta_table::NFTA_TABLE_FLAGS, t.flags);
    put_nlattr_u32(&mut body, nfta_table::NFTA_TABLE_USE, 0);

    let nlmsg_type = ((subsys::NFNL_SUBSYS_NFTABLES as u16) << 8)
                   | (nft_msg::NFT_MSG_NEWTABLE as u16);
    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len:   total as u32,
        nlmsg_type,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq:   seq,
        nlmsg_pid:   pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

/// NFNL dispatch entry. `full_msg` is the nlmsghdr-prefixed buffer
/// for one request. Returns the reply byte stream to push onto the
/// NetlinkSocket RX queue.
/// # C: O(1) decode + per-subsys handler cost
pub fn handle(full_msg: &[u8]) -> Vec<u8> {
    let hdr = match Nlmsghdr::parse(full_msg) {
        Some(h) => h,
        None    => return Vec::new(),
    };
    let subsys = (hdr.nlmsg_type >> 8) as u8;
    let cmd    = (hdr.nlmsg_type & 0xFF) as u8;
    let nfg_off = Nlmsghdr::SIZE;
    let nfg = match Nfgenmsg::parse(&full_msg[nfg_off..]) {
        Some(n) => n,
        None    => return nlmsg_ack(&hdr, -22),
    };
    let attrs = &full_msg[nfg_off + Nfgenmsg::SIZE..];
    match subsys {
        subsys::NFNL_SUBSYS_NFTABLES => nft_dispatch::handle_nft(&hdr, &nfg, cmd, attrs),
        _ => nlmsg_ack(&hdr, 0),
    }
}

/// Build a NFT_MSG_NEWCHAIN reply describing one chain.
/// # C: O(1)
fn build_newchain_reply(seq: u32, pid: u32, c: &NftChain, multi: bool) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(64);
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg {
        nfgen_family: c.table_family,
        version:      0,
        res_id:       0,
    }.write_to(&mut nfg_buf);
    body.extend_from_slice(&nfg_buf);

    put_nlattr_str(&mut body, nfta_chain::NFTA_CHAIN_TABLE, &c.table_name);
    put_nlattr_str(&mut body, nfta_chain::NFTA_CHAIN_NAME, &c.name);
    put_nlattr_u32(&mut body, nfta_chain::NFTA_CHAIN_USE, 0);
    put_nlattr_u32(&mut body, nfta_chain::NFTA_CHAIN_POLICY, c.policy);
    // If this is a base chain (hook bound), emit a NFTA_CHAIN_HOOK
    // nested attribute containing { HOOKNUM, PRIORITY }. nft
    // userspace needs both to render `type filter hook input
    // priority 0;`.
    if let Some(hook_id) = c.hook {
        let mut inner: Vec<u8> = Vec::with_capacity(16);
        // NFTA_HOOK_HOOKNUM = 1, NFTA_HOOK_PRIORITY = 2 per Linux.
        put_nlattr(&mut inner, 1u16, &hook_id.to_be_bytes());
        put_nlattr(&mut inner, 2u16, &(c.priority as u32).to_be_bytes());
        put_nlattr(&mut body, nfta_chain::NFTA_CHAIN_HOOK, &inner);
    }

    let nlmsg_type = ((subsys::NFNL_SUBSYS_NFTABLES as u16) << 8)
                   | (nft_msg::NFT_MSG_NEWCHAIN as u16);
    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len:   total as u32,
        nlmsg_type,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq:   seq,
        nlmsg_pid:   pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

/// Find a u32 attribute (big-endian per nft convention).
fn find_u32_attr(attrs: &[u8], target: u16) -> Option<u32> {
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]);
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        if nla_type == target {
            let payload = &attrs[off + 4..off + nla_len];
            if payload.len() == 4 {
                return Some(u32::from_be_bytes(payload.try_into().ok()?));
            }
        }
        off += nlmsg_align(nla_len);
    }
    None
}

/// Find a u64 attribute (big-endian per nft convention).
fn find_u64_attr(attrs: &[u8], target: u16) -> Option<u64> {
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]);
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        if nla_type == target {
            let payload = &attrs[off + 4..off + nla_len];
            if payload.len() == 8 {
                return Some(u64::from_be_bytes(payload.try_into().ok()?));
            }
        }
        off += nlmsg_align(nla_len);
    }
    None
}

/// Find a raw byte-slice attribute (no string trim).
fn find_bytes_attr<'a>(attrs: &'a [u8], target: u16) -> Option<&'a [u8]> {
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]);
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        if nla_type == target {
            return Some(&attrs[off + 4..off + nla_len]);
        }
        off += nlmsg_align(nla_len);
    }
    None
}

/// Build a NFT_MSG_NEWRULE reply describing one rule.
/// # C: O(1)
fn build_newrule_reply(seq: u32, pid: u32, r: &NftRule, multi: bool) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(64);
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg {
        nfgen_family: r.table_family,
        version:      0,
        res_id:       0,
    }.write_to(&mut nfg_buf);
    body.extend_from_slice(&nfg_buf);

    put_nlattr_str(&mut body, nfta_rule::NFTA_RULE_TABLE, &r.table_name);
    put_nlattr_str(&mut body, nfta_rule::NFTA_RULE_CHAIN, &r.chain_name);
    put_nlattr(&mut body, nfta_rule::NFTA_RULE_HANDLE, &r.handle.to_be_bytes());
    if !r.raw_expr.is_empty() {
        put_nlattr(&mut body, nfta_rule::NFTA_RULE_EXPRESSIONS, &r.raw_expr);
    }

    let nlmsg_type = ((subsys::NFNL_SUBSYS_NFTABLES as u16) << 8)
                   | (nft_msg::NFT_MSG_NEWRULE as u16);
    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len:   total as u32,
        nlmsg_type,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq:   seq,
        nlmsg_pid:   pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

/// Build a NFT_MSG_NEWSET reply describing one set.
/// # C: O(1)
fn build_newset_reply(seq: u32, pid: u32, s: &NftSet, multi: bool) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(64);
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg {
        nfgen_family: s.table_family,
        version:      0,
        res_id:       0,
    }.write_to(&mut nfg_buf);
    body.extend_from_slice(&nfg_buf);

    put_nlattr_str(&mut body, nfta_set::NFTA_SET_TABLE, &s.table_name);
    put_nlattr_str(&mut body, nfta_set::NFTA_SET_NAME, &s.name);
    put_nlattr_u32(&mut body, nfta_set::NFTA_SET_FLAGS, s.flags);
    put_nlattr_u32(&mut body, nfta_set::NFTA_SET_KEY_TYPE, s.key_type);
    put_nlattr_u32(&mut body, nfta_set::NFTA_SET_KEY_LEN, s.key_len);
    put_nlattr_u32(&mut body, nfta_set::NFTA_SET_DATA_TYPE, s.data_type);
    put_nlattr_u32(&mut body, nfta_set::NFTA_SET_DATA_LEN, s.data_len);

    let nlmsg_type = ((subsys::NFNL_SUBSYS_NFTABLES as u16) << 8)
                   | (nft_msg::NFT_MSG_NEWSET as u16);
    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len:   total as u32,
        nlmsg_type,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq:   seq,
        nlmsg_pid:   pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}


mod nft_dispatch;

#[cfg(test)]
mod tests;
