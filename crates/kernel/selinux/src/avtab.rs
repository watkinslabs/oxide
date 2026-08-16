// Access-vector table: the type-enforcement rules, keyed by
// (source type, target type, class, rule kind).
//
// The stored source and target values are types OR attributes, interchangeably
// — the loader never distinguishes them. Turning a concrete type into the set
// of values to look up is the job of the policy's type-to-attribute map, and
// skipping that expansion makes every attribute-based rule invisible: the
// engine would answer "no rule, therefore denied" for rules the policy plainly
// contains.

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::reader::Reader;
use crate::uapi::version::{POLICYDB_VERSION_AVTAB, POLICYDB_VERSION_COND_XPERMS,
                           POLICYDB_VERSION_XPERMS_IOCTL};

/// Rule grants the permissions in its access vector.
pub const AVTAB_ALLOWED: u16 = 0x0001;
/// Rule audits the permissions it names when they are granted.
pub const AVTAB_AUDITALLOW: u16 = 0x0002;
/// Rule names the permissions still audited when denied.
pub const AVTAB_AUDITDENY: u16 = 0x0004;
/// Mask covering the three access-vector rule kinds.
pub const AVTAB_AV: u16 = AVTAB_ALLOWED | AVTAB_AUDITALLOW | AVTAB_AUDITDENY;
/// Rule supplies the type of a newly created object.
pub const AVTAB_TRANSITION: u16 = 0x0010;
/// Rule supplies the type of a polyinstantiated member.
pub const AVTAB_MEMBER: u16 = 0x0020;
/// Rule supplies the type of a relabelled object.
pub const AVTAB_CHANGE: u16 = 0x0040;
/// Mask covering the three type rule kinds.
pub const AVTAB_TYPE: u16 = AVTAB_TRANSITION | AVTAB_MEMBER | AVTAB_CHANGE;
/// Rule grants extended permissions.
pub const AVTAB_XPERMS_ALLOWED: u16 = 0x0100;
/// Rule audits granted extended permissions.
pub const AVTAB_XPERMS_AUDITALLOW: u16 = 0x0200;
/// Rule suppresses auditing of denied extended permissions.
pub const AVTAB_XPERMS_DONTAUDIT: u16 = 0x0400;
/// Mask covering the extended-permission rule kinds.
pub const AVTAB_XPERMS: u16 =
    AVTAB_XPERMS_ALLOWED | AVTAB_XPERMS_AUDITALLOW | AVTAB_XPERMS_DONTAUDIT;
/// Conditional rule is currently in force.
pub const AVTAB_ENABLED: u16 = 0x8000;
/// Conditional-enabled bit in the pre-hashed wire format.
pub const AVTAB_ENABLED_OLD: u32 = 0x8000_0000;
/// Every bit the `specified` field may carry.
pub const AVTAB_SPECIFIER_MASK: u16 = AVTAB_AV | AVTAB_TYPE | AVTAB_XPERMS | AVTAB_ENABLED;

/// Extended permissions select individual ioctl functions.
pub const AVTAB_XPERMS_IOCTLFUNCTION: u8 = 0x01;
/// Extended permissions select a whole ioctl driver range.
pub const AVTAB_XPERMS_IOCTLDRIVER: u8 = 0x02;
/// Extended permissions select netlink message types.
pub const AVTAB_XPERMS_NLMSG: u8 = 0x03;

/// Order in which the pre-hashed wire format lists its data words.
const SPEC_ORDER: [u16; 9] = [
    AVTAB_ALLOWED, AVTAB_AUDITDENY, AVTAB_AUDITALLOW,
    AVTAB_TRANSITION, AVTAB_CHANGE, AVTAB_MEMBER,
    AVTAB_XPERMS_ALLOWED, AVTAB_XPERMS_AUDITALLOW, AVTAB_XPERMS_DONTAUDIT,
];

/// Words in an extended-permission bitmap.
pub const XPERMS_WORDS: usize = 8;

/// A 256-bit extended-permission selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Xperms {
    /// Which family of extended permissions the bitmap indexes.
    pub specified: u8,
    /// Driver or message-family selector for the bitmap.
    pub driver: u8,
    /// The selection bitmap, least-significant word first.
    pub perms: [u32; XPERMS_WORDS],
}

impl Xperms {
    /// Whether one extended permission is selected. # C: O(1)
    pub const fn get(&self, bit: u8) -> bool {
        self.perms[(bit >> 5) as usize] & (1u32 << (bit & 31)) != 0
    }
}

/// What a rule carries beside its key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Datum {
    /// An access vector, or a target type value for the type rule kinds.
    Word(u32),
    /// An extended-permission selection.
    Xperms(Xperms),
}

impl Datum {
    /// Access-vector or type value, or zero for an extended-permission rule. # C: O(1)
    pub const fn word(&self) -> u32 {
        match self { Self::Word(w) => *w, Self::Xperms(_) => 0 }
    }

    /// Extended-permission selection, if this rule carries one. # C: O(1)
    pub const fn xperms(&self) -> Option<&Xperms> {
        match self { Self::Xperms(x) => Some(x), Self::Word(_) => None }
    }
}

/// Key identifying one rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Key {
    /// Source type or attribute value.
    pub source_type: u16,
    /// Target type or attribute value.
    pub target_type: u16,
    /// Security class value.
    pub target_class: u16,
    /// Rule kind, plus the conditional-enabled bit.
    pub specified: u16,
}

impl Key {
    /// Rule kind with the conditional-enabled bit removed. # C: O(1)
    pub const fn kind(&self) -> u16 { self.specified & !AVTAB_ENABLED }

    /// Whether a conditional rule is currently in force. # C: O(1)
    pub const fn enabled(&self) -> bool { self.specified & AVTAB_ENABLED != 0 }

    /// Whether `specified` names exactly one rule kind. # C: O(1)
    pub const fn kind_is_singular(&self) -> bool {
        self.specified & !AVTAB_SPECIFIER_MASK == 0 && self.kind().count_ones() == 1
    }

    /// The three values that select a bucket, ignoring rule kind. # C: O(1)
    const fn bucket_key(&self) -> (u16, u16, u16) {
        (self.source_type, self.target_type, self.target_class)
    }
}

/// One stored rule.
#[derive(Clone, Copy, Debug)]
pub struct Rule {
    /// Key selecting when the rule applies.
    pub key: Key,
    /// What the rule carries.
    pub datum: Datum,
}

/// A set of type-enforcement rules with a lookup index.
#[derive(Clone, Debug)]
pub struct Avtab {
    rules: Vec<Rule>,
    /// Hash buckets over `(source, target, class)`, holding indices into `rules`.
    buckets: Vec<Vec<u32>>,
    mask: u32,
}

impl Default for Avtab {
    /// Empty table with a usable bucket array. # C: O(1)
    ///
    /// Hand-written rather than derived: a derived default would leave the
    /// bucket array empty and the mask zero, and the first insert or lookup
    /// would index a bucket that is not there.
    fn default() -> Self { Self::with_capacity(0) }
}

impl Avtab {
    /// Empty table sized for `nel` rules. # C: O(buckets)
    pub fn with_capacity(nel: u32) -> Self {
        let nslot = if nel > 3 { prev_power_of_two(nel / 2) } else { 2 };
        let nslot = nslot.clamp(2, 1 << 16);
        let mut buckets = Vec::new();
        buckets.resize(nslot as usize, Vec::new());
        Self { rules: Vec::new(), buckets, mask: nslot - 1 }
    }

    /// Number of stored rules. # C: O(1)
    pub fn len(&self) -> usize { self.rules.len() }

    /// Whether no rule is stored. # C: O(1)
    pub fn is_empty(&self) -> bool { self.rules.is_empty() }

    /// Every stored rule, in insertion order. # C: O(1)
    pub fn rules(&self) -> &[Rule] { &self.rules }

    /// Mutable access to one rule, for toggling conditional enablement. # C: O(1)
    pub fn rule_mut(&mut self, index: usize) -> Option<&mut Rule> { self.rules.get_mut(index) }

    /// Add a rule, refusing an exact duplicate key. # C: O(bucket)
    pub fn insert_unique(&mut self, rule: Rule) -> Result<()> {
        if self.find_exact(&rule.key).is_some() { return Err(Error::Duplicate); }
        self.insert(rule);
        Ok(())
    }

    /// Add a rule that may share a key with an existing one. # C: O(1)
    pub fn insert(&mut self, rule: Rule) {
        let slot = self.slot(&rule.key);
        let index = self.rules.len() as u32;
        self.rules.push(rule);
        self.buckets[slot].push(index);
    }

    /// Indices of every rule sharing a key's `(source, target, class)`. # C: O(bucket)
    pub fn bucket(&self, key: &Key) -> impl Iterator<Item = usize> + '_ {
        let want = key.bucket_key();
        let slot = self.slot(key);
        self.buckets[slot].iter().map(|i| *i as usize)
            .filter(move |i| self.rules[*i].key.bucket_key() == want)
    }

    /// Rules matching a key's triple and sharing any of its kind bits. # C: O(bucket)
    pub fn search(&self, key: &Key) -> impl Iterator<Item = &Rule> + '_ {
        let want = key.specified;
        self.bucket(key).map(move |i| &self.rules[i])
            .filter(move |r| r.key.kind() & want != 0)
    }

    fn find_exact(&self, key: &Key) -> Option<usize> {
        self.bucket(key).find(|i| self.rules[*i].key.specified == key.specified)
    }

    fn slot(&self, key: &Key) -> usize {
        (hash(key.source_type, key.target_type, key.target_class) & self.mask) as usize
    }

    /// Read a whole table from a policy image. # C: O(nel)
    pub fn read(r: &mut Reader<'_>, version: u32) -> Result<Self> {
        let nel = r.u32()?;
        if nel == 0 { return Err(Error::Malformed); }
        let mut table = Self::with_capacity(nel);
        for _ in 0..nel {
            read_item(r, version, false, &mut |rule| table.insert_unique(rule))?;
        }
        Ok(table)
    }
}

/// Read one rule, delivering every rule the record expands into.
///
/// The pre-hashed format packs several rule kinds into one record, so a single
/// wire item can produce up to six rules; `emit` is called once per rule.
pub fn read_item(r: &mut Reader<'_>, version: u32, conditional: bool,
                 emit: &mut impl FnMut(Rule) -> Result<()>) -> Result<()> {
    if version < POLICYDB_VERSION_AVTAB { return read_item_prehash(r, emit); }

    let source_type = r.u16()?;
    let target_type = r.u16()?;
    let target_class = r.u16()?;
    let specified = r.u16()?;
    let key = Key { source_type, target_type, target_class, specified };
    if !key.kind_is_singular() { return Err(Error::Malformed); }

    let datum = if specified & AVTAB_XPERMS != 0 {
        if version < POLICYDB_VERSION_XPERMS_IOCTL { return Err(Error::Malformed); }
        if conditional && version < POLICYDB_VERSION_COND_XPERMS { return Err(Error::Malformed); }
        Datum::Xperms(read_xperms(r)?)
    } else {
        Datum::Word(r.u32()?)
    };
    emit(Rule { key, datum })
}

fn read_xperms(r: &mut Reader<'_>) -> Result<Xperms> {
    let specified = r.u8()?;
    let driver = r.u8()?;
    let mut perms = [0u32; XPERMS_WORDS];
    for word in perms.iter_mut() { *word = r.u32()?; }
    Ok(Xperms { specified, driver, perms })
}

/// Read one record of the pre-hashed format, which lists a data word per kind
/// bit set in a combined flags field.
fn read_item_prehash(r: &mut Reader<'_>, emit: &mut impl FnMut(Rule) -> Result<()>) -> Result<()> {
    let items = r.u32()?;
    if !(5..=9).contains(&items) { return Err(Error::Malformed); }
    let source_type = u16::try_from(r.u32()?).map_err(|_| Error::Malformed)?;
    let target_type = u16::try_from(r.u32()?).map_err(|_| Error::Malformed)?;
    let target_class = u16::try_from(r.u32()?).map_err(|_| Error::Malformed)?;
    let val = r.u32()?;

    let enabled = if val & AVTAB_ENABLED_OLD != 0 { AVTAB_ENABLED } else { 0 };
    let kinds = (val & !AVTAB_ENABLED_OLD) as u16;
    if kinds & AVTAB_XPERMS != 0 { return Err(Error::Malformed); }
    if kinds & !(AVTAB_AV | AVTAB_TYPE) != 0 { return Err(Error::Malformed); }

    for kind in SPEC_ORDER {
        if kinds & kind == 0 { continue; }
        let datum = Datum::Word(r.u32()?);
        let key = Key { source_type, target_type, target_class, specified: kind | enabled };
        emit(Rule { key, datum })?;
    }
    Ok(())
}

/// Largest power of two not exceeding `n`, or 1 for zero. # C: O(1)
const fn prev_power_of_two(n: u32) -> u32 {
    if n == 0 { return 1; }
    1u32 << (u32::BITS - 1 - n.leading_zeros())
}

/// Bucket hash over the key triple. # C: O(1)
///
/// The distribution only has to be even; correctness never depends on it,
/// because every bucket walk re-compares the full triple.
pub const fn hash(source_type: u16, target_type: u16, target_class: u16) -> u32 {
    let mut h = (target_class as u32).wrapping_mul(0x9e37_79b9);
    h ^= (target_type as u32).wrapping_mul(0x85eb_ca6b);
    h = h.rotate_left(13);
    h ^= (source_type as u32).wrapping_mul(0xc2b2_ae35);
    h ^ (h >> 16)
}

#[cfg(test)]
#[path = "tests/avtab.rs"]
mod tests;
