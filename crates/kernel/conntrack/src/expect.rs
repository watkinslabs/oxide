//! Expectations. A helper watching a control connection declares that a
//! particular data connection is about to appear; when it does, it is admitted
//! as RELATED instead of NEW. The mask is what makes this safe or not — a mask
//! that wildcards too much admits traffic nobody announced.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Socket as SocketLockClass, Spinlock};

use crate::entry::Conn;
use crate::limits::{EXPECT_CLASS_DEFAULT, EXPECT_HASH_BUCKETS, EXPECT_MAX, EXPECT_MAX_CNT};
use crate::tuple::{InetAddr, ProtoPart, Tuple, TupleEnd};

pub const NF_CT_EXPECT_PERMANENT: u32 = 0x1;
pub const NF_CT_EXPECT_INACTIVE:  u32 = 0x2;
pub const NF_CT_EXPECT_USERSPACE: u32 = 0x4;
/// Internal: the expectation has been unlinked and must not fire.
pub const NF_CT_EXPECT_DEAD:      u32 = 0x8;
pub const NF_CT_EXPECT_MASK: u32 =
    NF_CT_EXPECT_PERMANENT | NF_CT_EXPECT_INACTIVE | NF_CT_EXPECT_USERSPACE;

/// Which tuple fields an expectation compares. A zero field is a wildcard.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct TupleMask {
    pub src_addr: InetAddr,
    pub dst_addr: InetAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl TupleMask {
    /// Compare every field the mask selects. `l3num` and `protonum` are always
    /// compared exactly: a wildcard there would let a UDP flow satisfy an
    /// expectation announced for TCP.
    /// # C: O(1)
    pub fn matches(&self, expected: &Tuple, candidate: &Tuple) -> bool {
        if expected.l3num != candidate.l3num { return false; }
        if expected.protonum != candidate.protonum { return false; }
        if expected.zone != candidate.zone { return false; }
        masked_addr_eq(&expected.src.addr, &candidate.src.addr, &self.src_addr)
            && masked_addr_eq(&expected.dst.addr, &candidate.dst.addr, &self.dst_addr)
            && (expected.src.proto.port & self.src_port)
                == (candidate.src.proto.port & self.src_port)
            && (expected.dst.proto.port & self.dst_port)
                == (candidate.dst.proto.port & self.dst_port)
    }

    /// Field-wise intersection — the mask two expectations must be compared
    /// under to decide whether they can both exist. # C: O(1)
    pub fn intersect(&self, other: &TupleMask) -> TupleMask {
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        for i in 0..16 {
            src[i] = self.src_addr.0[i] & other.src_addr.0[i];
            dst[i] = self.dst_addr.0[i] & other.dst_addr.0[i];
        }
        TupleMask {
            src_addr: InetAddr(src), dst_addr: InetAddr(dst),
            src_port: self.src_port & other.src_port,
            dst_port: self.dst_port & other.dst_port,
        }
    }

    /// Mask that compares every field exactly. # C: O(1)
    pub fn exact() -> Self {
        Self { src_addr: InetAddr([0xff; 16]), dst_addr: InetAddr([0xff; 16]),
               src_port: 0xffff, dst_port: 0xffff }
    }

    /// Mask that compares the destination end only — the shape a helper uses
    /// when it knows the server side of the coming connection but not which
    /// source port the client will pick. # C: O(1)
    pub fn dst_only() -> Self {
        Self { src_addr: InetAddr([0xff; 16]), dst_addr: InetAddr([0xff; 16]),
               src_port: 0, dst_port: 0xffff }
    }
}

fn masked_addr_eq(a: &InetAddr, b: &InetAddr, m: &InetAddr) -> bool {
    (0..16).all(|i| (a.0[i] & m.0[i]) == (b.0[i] & m.0[i]))
}

/// One announced connection.
#[derive(Clone, Debug)]
pub struct Expectation {
    pub tuple: Tuple,
    pub mask: TupleMask,
    pub master: Arc<Conn>,
    pub class: u8,
    pub flags: u32,
    /// Absolute expiry, seconds.
    pub timeout: u64,
    pub helper: Option<String>,
    /// Direction of the master connection the expectation was declared from.
    pub dir: u8,
    /// Port the peer actually expects, preserved across a NAT rewrite so the
    /// helper can restore it on the data connection.
    pub saved_proto: ProtoPart,
    /// Address the peer actually expects, likewise.
    pub saved_addr: InetAddr,
}

/// Why an expectation was refused.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExpectError {
    /// The same master already announced this exact tuple in another class.
    Already,
    /// An overlapping expectation exists that this one cannot be told apart from.
    Busy,
    /// Global or per-master ceiling reached.
    TooMany,
}

/// Per-namespace expectation table.
pub struct ExpectTable {
    buckets: Vec<Spinlock<Vec<Expectation>, SocketLockClass>>,
    count: Spinlock<usize, SocketLockClass>,
    seed: u32,
    pub max: usize,
}

impl ExpectTable {
    /// # C: O(N_buckets)
    pub fn new(seed: u32) -> Self {
        let n = core::cmp::max(EXPECT_HASH_BUCKETS, 1);
        let mut buckets = Vec::with_capacity(n);
        for _ in 0..n { buckets.push(Spinlock::new(Vec::new())); }
        Self { buckets, count: Spinlock::new(0), seed, max: EXPECT_MAX }
    }

    /// Expectations hash on the destination end alone: the source is exactly
    /// the part a helper usually cannot predict, so hashing it would put the
    /// expectation in a bucket the arriving connection never reaches.
    fn bucket_index(&self, t: &Tuple) -> usize {
        let key = Tuple {
            src: TupleEnd::default(),
            dst: t.dst,
            l3num: t.l3num, protonum: t.protonum, zone: t.zone,
        };
        (crate::hash::tuple_hash(&key, self.seed) as usize) % self.buckets.len()
    }

    /// Find the expectation an arriving connection satisfies.
    /// # C: O(bucket length)
    pub fn find(&self, t: &Tuple, now: u64) -> Option<Expectation> {
        let g = self.buckets[self.bucket_index(t)].lock();
        g.iter().find(|e| e.timeout > now && e.flags & NF_CT_EXPECT_DEAD == 0
            && e.mask.matches(&e.tuple, t)).cloned()
    }

    /// Install an expectation, applying the reference's admission rules: an
    /// identical announcement from the same master replaces the old one, an
    /// overlapping-but-different one is refused, and both the per-master class
    /// budget and the global ceiling apply.
    /// # C: O(bucket length)
    pub fn insert(&self, exp: Expectation, per_class_max: u32, master_count: u32,
                  now: u64) -> Result<(), ExpectError>
    {
        let idx = self.bucket_index(&exp.tuple);
        let mut g = self.buckets[idx].lock();
        g.retain(|e| e.timeout > now && e.flags & NF_CT_EXPECT_DEAD == 0);
        let mut replaced = false;
        let mut i = 0;
        while i < g.len() {
            let same_master = Arc::ptr_eq(&g[i].master, &exp.master);
            let identical = g[i].tuple == exp.tuple && g[i].mask == exp.mask;
            if same_master && identical {
                if g[i].class != exp.class { return Err(ExpectError::Already); }
                g.remove(i);
                replaced = true;
                break;
            }
            if clash(&g[i], &exp) { return Err(ExpectError::Busy); }
            i += 1;
        }
        if !replaced {
            let limit = if per_class_max == 0 { EXPECT_MAX_CNT } else { per_class_max };
            if master_count >= limit { return Err(ExpectError::TooMany); }
            let mut c = self.count.lock();
            if *c >= self.max { return Err(ExpectError::TooMany); }
            *c += 1;
        }
        g.push(exp);
        Ok(())
    }

    /// Remove one expectation by tuple. # C: O(bucket length)
    pub fn remove(&self, t: &Tuple) -> bool {
        let idx = self.bucket_index(t);
        let mut g = self.buckets[idx].lock();
        match g.iter().position(|e| e.tuple == *t) {
            Some(i) => { g.remove(i); *self.count.lock() -= 1; true }
            None => false,
        }
    }

    /// Drop every expectation announced by one master — what happens when the
    /// control connection goes away. # C: O(N)
    pub fn purge_master(&self, master: &Arc<Conn>) -> usize {
        let mut n = 0;
        for b in self.buckets.iter() {
            let mut g = b.lock();
            let before = g.len();
            g.retain(|e| !Arc::ptr_eq(&e.master, master));
            n += before - g.len();
        }
        if n > 0 { *self.count.lock() -= n; }
        n
    }

    /// # C: O(N)
    pub fn snapshot(&self) -> Vec<Expectation> {
        let mut out = Vec::new();
        for b in self.buckets.iter() { out.extend(b.lock().iter().cloned()); }
        out
    }

    /// # C: O(1)
    pub fn count(&self) -> usize { *self.count.lock() }
}

/// Two expectations clash when, under the intersection of their masks, they
/// describe the same connection: an arriving packet would satisfy both and
/// there is no way to say which helper owns it.
/// # C: O(1)
pub fn clash(a: &Expectation, b: &Expectation) -> bool {
    let m = a.mask.intersect(&b.mask);
    m.matches(&a.tuple, &b.tuple)
}

/// Default expectation class. # C: O(1)
pub const fn default_class() -> u8 { EXPECT_CLASS_DEFAULT }
