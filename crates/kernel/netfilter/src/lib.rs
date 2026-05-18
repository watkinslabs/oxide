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
        subsys::NFNL_SUBSYS_NFTABLES => handle_nft(&hdr, &nfg, cmd, attrs),
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

fn handle_nft(req: &Nlmsghdr, nfg: &Nfgenmsg, cmd: u8, attrs: &[u8]) -> Vec<u8> {
    match cmd {
        nft_msg::NFT_MSG_GETTABLE => {
            // Single table lookup or full dump.
            if let Some(name) = find_str_attr(attrs, nfta_table::NFTA_TABLE_NAME) {
                let g = TABLES.lock();
                let found = g.iter().find(|t|
                    t.family == nfg.nfgen_family && t.name == name).cloned();
                drop(g);
                match found {
                    Some(t) => build_newtable_reply(req.nlmsg_seq, req.nlmsg_pid, &t, false),
                    None    => nlmsg_ack(req, -2 /* ENOENT */),
                }
            } else {
                let mut reply: Vec<u8> = Vec::with_capacity(256);
                for t in tables_snapshot().iter() {
                    let one = build_newtable_reply(req.nlmsg_seq, req.nlmsg_pid, t, true);
                    reply.extend_from_slice(&one);
                }
                let mut done_buf = [0u8; Nlmsghdr::SIZE];
                let mut done = Nlmsghdr::done(req.nlmsg_seq, req.nlmsg_pid);
                done.nlmsg_flags = flags::NLM_F_MULTI;
                done.write_to(&mut done_buf);
                reply.extend_from_slice(&done_buf);
                reply
            }
        }
        nft_msg::NFT_MSG_NEWTABLE => {
            let name = match find_str_attr(attrs, nfta_table::NFTA_TABLE_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            table_insert(NftTable {
                family: nfg.nfgen_family,
                name:   String::from(name),
                flags:  0,
            });
            nlmsg_ack(req, 0)
        }
        nft_msg::NFT_MSG_DELTABLE => {
            let name = match find_str_attr(attrs, nfta_table::NFTA_TABLE_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let n = table_remove(nfg.nfgen_family, name);
            nlmsg_ack(req, if n > 0 { 0 } else { -2 })
        }
        nft_msg::NFT_MSG_GETCHAIN => {
            let table_name = find_str_attr(attrs, nfta_chain::NFTA_CHAIN_TABLE);
            let chain_name = find_str_attr(attrs, nfta_chain::NFTA_CHAIN_NAME);
            if let (Some(tn), Some(cn)) = (table_name, chain_name) {
                let g = CHAINS.lock();
                let found = g.iter().find(|c|
                    c.table_family == nfg.nfgen_family
                    && c.table_name == tn
                    && c.name == cn).cloned();
                drop(g);
                match found {
                    Some(c) => build_newchain_reply(req.nlmsg_seq, req.nlmsg_pid, &c, false),
                    None    => nlmsg_ack(req, -2),
                }
            } else {
                let mut reply: Vec<u8> = Vec::with_capacity(256);
                for c in chains_snapshot().iter()
                    .filter(|c| table_name.map_or(true, |tn|
                        c.table_family == nfg.nfgen_family && c.table_name == tn))
                {
                    reply.extend_from_slice(&build_newchain_reply(
                        req.nlmsg_seq, req.nlmsg_pid, c, true));
                }
                let mut done_buf = [0u8; Nlmsghdr::SIZE];
                let mut done = Nlmsghdr::done(req.nlmsg_seq, req.nlmsg_pid);
                done.nlmsg_flags = flags::NLM_F_MULTI;
                done.write_to(&mut done_buf);
                reply.extend_from_slice(&done_buf);
                reply
            }
        }
        nft_msg::NFT_MSG_NEWCHAIN => {
            let table_name = match find_str_attr(attrs, nfta_chain::NFTA_CHAIN_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let chain_name = match find_str_attr(attrs, nfta_chain::NFTA_CHAIN_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            chain_insert(NftChain {
                table_family: nfg.nfgen_family,
                table_name:   String::from(table_name),
                name:         String::from(chain_name),
            });
            nlmsg_ack(req, 0)
        }
        nft_msg::NFT_MSG_DELCHAIN => {
            let table_name = match find_str_attr(attrs, nfta_chain::NFTA_CHAIN_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let chain_name = match find_str_attr(attrs, nfta_chain::NFTA_CHAIN_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let n = chain_remove(nfg.nfgen_family, table_name, chain_name);
            nlmsg_ack(req, if n > 0 { 0 } else { -2 })
        }
        nft_msg::NFT_MSG_GETRULE => {
            let table_name = find_str_attr(attrs, nfta_rule::NFTA_RULE_TABLE);
            let chain_name = find_str_attr(attrs, nfta_rule::NFTA_RULE_CHAIN);
            let want_handle = find_u64_attr(attrs, nfta_rule::NFTA_RULE_HANDLE);
            if let (Some(tn), Some(cn), Some(h)) = (table_name, chain_name, want_handle) {
                let g = RULES.lock();
                let found = g.iter().find(|r|
                    r.table_family == nfg.nfgen_family
                    && r.table_name == tn
                    && r.chain_name == cn
                    && r.handle == h).cloned();
                drop(g);
                match found {
                    Some(r) => build_newrule_reply(req.nlmsg_seq, req.nlmsg_pid, &r, false),
                    None    => nlmsg_ack(req, -2),
                }
            } else {
                let mut reply: Vec<u8> = Vec::with_capacity(256);
                for r in rules_snapshot().iter().filter(|r|
                    table_name.map_or(true, |tn|
                        r.table_family == nfg.nfgen_family && r.table_name == tn)
                    && chain_name.map_or(true, |cn| r.chain_name == cn))
                {
                    reply.extend_from_slice(&build_newrule_reply(
                        req.nlmsg_seq, req.nlmsg_pid, r, true));
                }
                let mut done_buf = [0u8; Nlmsghdr::SIZE];
                let mut done = Nlmsghdr::done(req.nlmsg_seq, req.nlmsg_pid);
                done.nlmsg_flags = flags::NLM_F_MULTI;
                done.write_to(&mut done_buf);
                reply.extend_from_slice(&done_buf);
                reply
            }
        }
        nft_msg::NFT_MSG_NEWRULE => {
            let table_name = match find_str_attr(attrs, nfta_rule::NFTA_RULE_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let chain_name = match find_str_attr(attrs, nfta_rule::NFTA_RULE_CHAIN) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let raw_expr = find_bytes_attr(attrs, nfta_rule::NFTA_RULE_EXPRESSIONS)
                .map(|b| b.to_vec()).unwrap_or_default();
            rule_insert(NftRule {
                table_family: nfg.nfgen_family,
                table_name:   String::from(table_name),
                chain_name:   String::from(chain_name),
                handle:       next_rule_handle(),
                raw_expr,
            });
            nlmsg_ack(req, 0)
        }
        nft_msg::NFT_MSG_DELRULE => {
            let table_name = match find_str_attr(attrs, nfta_rule::NFTA_RULE_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let chain_name = match find_str_attr(attrs, nfta_rule::NFTA_RULE_CHAIN) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            // No handle = delete every rule in (table, chain). With
            // handle = single-row delete. Mirrors nft userspace semantics.
            let handle = find_u64_attr(attrs, nfta_rule::NFTA_RULE_HANDLE);
            let n = match handle {
                Some(h) => rule_remove(nfg.nfgen_family, table_name, chain_name, h),
                None => {
                    let mut g = RULES.lock();
                    let before = g.len();
                    g.retain(|r| !(r.table_family == nfg.nfgen_family
                                   && r.table_name == table_name
                                   && r.chain_name == chain_name));
                    before - g.len()
                }
            };
            nlmsg_ack(req, if n > 0 || handle.is_none() { 0 } else { -2 })
        }
        nft_msg::NFT_MSG_GETSET => {
            let tn = find_str_attr(attrs, nfta_set::NFTA_SET_TABLE);
            let sn = find_str_attr(attrs, nfta_set::NFTA_SET_NAME);
            if let (Some(tn), Some(sn)) = (tn, sn) {
                let g = SETS.lock();
                let found = g.iter().find(|s|
                    s.table_family == nfg.nfgen_family
                    && s.table_name == tn
                    && s.name == sn).cloned();
                drop(g);
                match found {
                    Some(s) => build_newset_reply(req.nlmsg_seq, req.nlmsg_pid, &s, false),
                    None    => nlmsg_ack(req, -2),
                }
            } else {
                let mut reply: Vec<u8> = Vec::with_capacity(256);
                for s in sets_snapshot().iter().filter(|s|
                    tn.map_or(true, |t|
                        s.table_family == nfg.nfgen_family && s.table_name == t))
                {
                    reply.extend_from_slice(&build_newset_reply(
                        req.nlmsg_seq, req.nlmsg_pid, s, true));
                }
                let mut done_buf = [0u8; Nlmsghdr::SIZE];
                let mut done = Nlmsghdr::done(req.nlmsg_seq, req.nlmsg_pid);
                done.nlmsg_flags = flags::NLM_F_MULTI;
                done.write_to(&mut done_buf);
                reply.extend_from_slice(&done_buf);
                reply
            }
        }
        nft_msg::NFT_MSG_NEWSET => {
            let table_name = match find_str_attr(attrs, nfta_set::NFTA_SET_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let set_name = match find_str_attr(attrs, nfta_set::NFTA_SET_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let flags     = find_u32_attr(attrs, nfta_set::NFTA_SET_FLAGS).unwrap_or(0);
            let key_type  = find_u32_attr(attrs, nfta_set::NFTA_SET_KEY_TYPE).unwrap_or(0);
            let key_len   = find_u32_attr(attrs, nfta_set::NFTA_SET_KEY_LEN).unwrap_or(0);
            let data_type = find_u32_attr(attrs, nfta_set::NFTA_SET_DATA_TYPE).unwrap_or(0);
            let data_len  = find_u32_attr(attrs, nfta_set::NFTA_SET_DATA_LEN).unwrap_or(0);
            set_insert(NftSet {
                table_family: nfg.nfgen_family,
                table_name:   String::from(table_name),
                name:         String::from(set_name),
                key_type, key_len, data_type, data_len, flags,
            });
            nlmsg_ack(req, 0)
        }
        nft_msg::NFT_MSG_DELSET => {
            let table_name = match find_str_attr(attrs, nfta_set::NFTA_SET_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let set_name = match find_str_attr(attrs, nfta_set::NFTA_SET_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let n = set_remove(nfg.nfgen_family, table_name, set_name);
            nlmsg_ack(req, if n > 0 { 0 } else { -2 })
        }
        _ => nlmsg_ack(req, 0), // objects / batches: future PRs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfgenmsg_roundtrip() {
        let n = Nfgenmsg { nfgen_family: 2, version: 0, res_id: 0x1234 };
        let mut buf = [0u8; Nfgenmsg::SIZE];
        n.write_to(&mut buf);
        let p = Nfgenmsg::parse(&buf).unwrap();
        assert_eq!(p.nfgen_family, 2);
        assert_eq!(p.version, 0);
        assert_eq!(p.res_id, 0x1234);
    }

    #[test]
    fn table_insert_dedup_remove() {
        let t = NftTable { family: 2, name: String::from("oxide-test-t"), flags: 0 };
        let before = tables_snapshot().len();
        table_insert(t.clone());
        table_insert(t.clone()); // dedup
        assert_eq!(tables_snapshot().len(), before + 1);
        let n = table_remove(2, "oxide-test-t");
        assert_eq!(n, 1);
        assert_eq!(tables_snapshot().len(), before);
    }

    #[test]
    fn set_insert_dedup_remove() {
        let s = NftSet {
            table_family: 2,
            table_name:   String::from("oxide-test-t"),
            name:         String::from("blocked_ips"),
            key_type: 7, key_len: 4, data_type: 0, data_len: 0, flags: 0,
        };
        let before = sets_snapshot().len();
        set_insert(s.clone());
        set_insert(s);
        assert_eq!(sets_snapshot().len(), before + 1);
        let n = set_remove(2, "oxide-test-t", "blocked_ips");
        assert_eq!(n, 1);
        assert_eq!(sets_snapshot().len(), before);
    }

    #[test]
    fn rule_insert_and_remove_round_trip() {
        let h = next_rule_handle();
        let r = NftRule {
            table_family: 2,
            table_name:   String::from("oxide-test-t"),
            chain_name:   String::from("input"),
            handle:       h,
            raw_expr:     vec![1, 2, 3],
        };
        let before = rules_snapshot().len();
        rule_insert(r);
        assert_eq!(rules_snapshot().len(), before + 1);
        let n = rule_remove(2, "oxide-test-t", "input", h);
        assert_eq!(n, 1);
        assert_eq!(rules_snapshot().len(), before);
    }

    #[test]
    fn chain_insert_dedup_remove() {
        let c = NftChain {
            table_family: 2,
            table_name:   String::from("oxide-test-t"),
            name:         String::from("input"),
        };
        let before = chains_snapshot().len();
        chain_insert(c.clone());
        chain_insert(c.clone());
        assert_eq!(chains_snapshot().len(), before + 1);
        let n = chain_remove(2, "oxide-test-t", "input");
        assert_eq!(n, 1);
        assert_eq!(chains_snapshot().len(), before);
    }

    #[test]
    fn rule_handles_are_unique() {
        let a = next_rule_handle();
        let b = next_rule_handle();
        assert_ne!(a, b);
    }
}
