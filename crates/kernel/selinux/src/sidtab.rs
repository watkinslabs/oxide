// SID table: the two-way map between a small integer handle and the security
// context it names.
//
// Two properties here are load-bearing for the whole engine. First, a SID once
// handed out is never reused for a different context, because callers stamp
// SIDs into long-lived objects (inodes, sockets, tasks) and compare them later;
// recycling a number silently relabels every object still carrying it. Second,
// the reverse lookup compares the FULL context on a hash hit — a hash is a
// bucket selector, never an identity. Matching on the digest, or on a subset of
// the fields, hands a caller another subject's SID.

use alloc::vec::Vec;

use crate::context::Context;
use crate::error::{Error, Result};
use crate::uapi::initsid::{InitSid, SECINITSID_NUM};
use crate::uapi::version::{SECSID_NULL, SECSID_WILD};

/// Handle naming one security context.
pub type Sid = u32;

/// First SID handed out by dynamic allocation; everything at or below
/// `SECINITSID_NUM` is an initial SID fixed by the ABI.
pub const FIRST_DYNAMIC_SID: Sid = SECINITSID_NUM + 1;

/// Bucket count of the reverse (context to SID) index. A power of two so the
/// bucket is a mask of the hash rather than a division.
const HASH_BUCKETS: usize = 512;

/// Mask selecting a bucket from a hash.
const HASH_MASK: usize = HASH_BUCKETS - 1;

/// FNV-1a 64-bit offset basis.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64-bit prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Hash-index shape, for the same statistics userspace reads about the
/// engine's tables.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct HashStats {
    /// Keys held in the index.
    pub entries: u32,
    /// Buckets the index was built with.
    pub buckets: u32,
    /// Buckets holding at least one key.
    pub used_buckets: u32,
    /// Length of the longest chain.
    pub longest_chain: u32,
}

/// Two-way map between SIDs and security contexts.
pub struct Sidtab {
    /// Initial SIDs, indexed `sid - 1`; `None` where policy set none.
    isids: Vec<Option<Context>>,
    /// Dynamically allocated contexts, indexed `sid - FIRST_DYNAMIC_SID`.
    dynamic: Vec<Context>,
    /// Reverse index: context hash bucket to the SIDs hashed into it.
    buckets: Vec<Vec<Sid>>,
    /// Set while a reload converts this table; allocation must not proceed.
    frozen: bool,
}

impl Default for Sidtab {
    /// Empty table. # C: O(buckets)
    fn default() -> Self { Self::new() }
}

impl Sidtab {
    /// Empty table with no initial SID set. # C: O(buckets)
    pub fn new() -> Self {
        let mut isids = Vec::new();
        isids.resize(SECINITSID_NUM as usize, None);
        let mut buckets = Vec::new();
        buckets.resize_with(HASH_BUCKETS, Vec::new);
        Self { isids, dynamic: Vec::new(), buckets, frozen: false }
    }

    /// Install one initial SID's context. # C: O(chain)
    ///
    /// Several initial SIDs commonly share one context. Only the first is
    /// entered in the reverse index: a later `context_to_sid` for that context
    /// must resolve to a single, stable SID rather than to whichever duplicate
    /// the chain happened to reach first.
    pub fn set_initial(&mut self, sid: Sid, context: Context) -> Result<()> {
        if sid == SECSID_NULL || sid > SECINITSID_NUM { return Err(Error::UnknownSid); }
        let h = context_hash(&context);
        let already = self.find_hashed(h, &context).is_some();
        self.isids[(sid - 1) as usize] = Some(context);
        if !already { self.hash_insert(h, sid)?; }
        Ok(())
    }

    /// Context for a SID, with no fallback. # C: O(1)
    pub fn lookup(&self, sid: Sid) -> Option<&Context> {
        if sid == SECSID_NULL || sid == SECSID_WILD { return None; }
        if sid <= SECINITSID_NUM { return self.isids[(sid - 1) as usize].as_ref(); }
        self.dynamic.get((sid - FIRST_DYNAMIC_SID) as usize)
    }

    /// Context for a SID, substituting the unlabeled context for an absent SID
    /// or a retained-unmapped entry. # C: O(1)
    ///
    /// The substitution is what keeps a reload that drops a type from becoming
    /// a mass relabel: the object keeps its SID and its original context, and
    /// merely reads as unlabeled until a policy that understands it returns.
    pub fn search(&self, sid: Sid) -> Option<&Context> {
        let usable = matches!(self.lookup(sid), Some(c) if !c.is_unmapped());
        if usable { self.lookup(sid) } else { self.lookup(InitSid::Unlabeled.sid()) }
    }

    /// Context for a SID including retained-unmapped entries. # C: O(1)
    pub fn search_force(&self, sid: Sid) -> Option<&Context> {
        if self.lookup(sid).is_some() { self.lookup(sid) } else { self.lookup(InitSid::Unlabeled.sid()) }
    }

    /// SID for a context, allocating one if it is new. # C: O(chain)
    pub fn context_to_sid(&mut self, context: Context) -> Result<Sid> {
        let h = context_hash(&context);
        if let Some(sid) = self.find_hashed(h, &context) { return Ok(sid); }
        // A frozen table is mid-conversion: allocating here would mint a SID
        // against a policy that is already being replaced, so the caller must
        // retry once the new policy is live.
        if self.frozen { return Err(Error::Stale); }
        let idx = self.dynamic.len() as u64;
        let sid = u64::from(FIRST_DYNAMIC_SID) + idx;
        if sid >= u64::from(SECSID_WILD) { return Err(Error::TooLarge); }
        let sid = sid as Sid;
        self.dynamic.try_reserve(1).map_err(|_| Error::NoMemory)?;
        self.hash_insert(h, sid)?;
        self.dynamic.push(context);
        Ok(sid)
    }

    /// Number of dynamically allocated entries. # C: O(1)
    pub fn count(&self) -> u32 { self.dynamic.len() as u32 }

    /// Refuse further allocation; a reload is converting this table. # C: O(1)
    pub fn freeze(&mut self) { self.frozen = true; }

    /// Whether allocation is refused. # C: O(1)
    pub fn is_frozen(&self) -> bool { self.frozen }

    /// Shape of the reverse index. # C: O(entries)
    pub fn hash_stats(&self) -> HashStats {
        let mut st = HashStats { entries: 0, buckets: HASH_BUCKETS as u32, used_buckets: 0, longest_chain: 0 };
        for b in &self.buckets {
            let n = b.len() as u32;
            if n == 0 { continue; }
            st.entries += n;
            st.used_buckets += 1;
            if n > st.longest_chain { st.longest_chain = n; }
        }
        st
    }

    /// Every dynamic entry in SID order, for policy-reload conversion. # C: O(1)
    pub fn entries(&self) -> impl Iterator<Item = (Sid, &Context)> {
        self.dynamic.iter().enumerate().map(|(i, c)| (FIRST_DYNAMIC_SID + i as Sid, c))
    }

    /// SID already holding this exact context, if any. # C: O(chain)
    ///
    /// The full context decides, not the hash: a bucket hit is a candidate.
    fn find_hashed(&self, h: u64, context: &Context) -> Option<Sid> {
        self.buckets[(h as usize) & HASH_MASK].iter()
            .find(|&&sid| self.lookup(sid) == Some(context)).copied()
    }

    /// Record a SID in the reverse index. # C: O(1)
    fn hash_insert(&mut self, h: u64, sid: Sid) -> Result<()> {
        let b = &mut self.buckets[(h as usize) & HASH_MASK];
        b.try_reserve(1).map_err(|_| Error::NoMemory)?;
        b.push(sid);
        Ok(())
    }
}

/// Bucket selector for a context. # C: O(categories)
///
/// Every field that distinguishes two contexts feeds the digest, so that equal
/// contexts always collide and unequal ones usually do not. Both MLS levels
/// participate: two contexts differing only in clearance are different
/// subjects and must not share a SID.
fn context_hash(context: &Context) -> u64 {
    let mut h = FNV_OFFSET;
    match context {
        Context::Unmapped(s) => {
            h = mix(h, UNMAPPED_TAG);
            for b in s.as_bytes() { h = mix(h, u64::from(*b)); }
        }
        Context::Valid(c) => {
            h = mix(h, VALID_TAG);
            h = mix(h, u64::from(c.user));
            h = mix(h, u64::from(c.role));
            h = mix(h, u64::from(c.ty));
            h = mix(h, u64::from(c.range.low.sens));
            for bit in c.range.low.cat.iter() { h = mix(h, u64::from(bit)); }
            h = mix(h, LEVEL_SEP);
            h = mix(h, u64::from(c.range.high.sens));
            for bit in c.range.high.cat.iter() { h = mix(h, u64::from(bit)); }
        }
    }
    h
}

/// Domain tag distinguishing an interpreted context from a retained string.
const VALID_TAG: u64 = 0;
/// Domain tag for a retained unmapped context.
const UNMAPPED_TAG: u64 = 1;
/// Separator between the two MLS levels, so that moving a category from the
/// low level to the high one changes the digest.
const LEVEL_SEP: u64 = 0xff;

/// One FNV-1a step over a whole word. # C: O(1)
fn mix(h: u64, v: u64) -> u64 { (h ^ v).wrapping_mul(FNV_PRIME) }

#[cfg(test)]
#[path = "tests/sidtab.rs"]
mod tests;
