// What the read side of each node renders.

use alloc::format;
use alloc::string::String;

use selinux::avc::{AvDecision, CacheStats};
use selinux::sidtab::HashStats;

/// Legacy all-ones field in the decision response.
///
/// The field once carried a second decision mask and is now fixed. It is
/// emitted literally because the response is positional: dropping it shifts
/// every later field left, so a caller would read the audit masks as the
/// grant and act on the wrong one.
pub const AV_LEGACY_ALL_ONES: &str = "ffffffff";

/// Render one access decision. # C: O(1)
///
/// Field order is `allowed`, the legacy all-ones word, `auditallow`,
/// `auditdeny`, the sequence number, the flags. Swapping either audit field
/// for the other reports a mask userspace then treats as the grant.
pub fn access_response(avd: &AvDecision) -> String {
    format!("{:x} {} {:x} {:x} {} {:x}",
            avd.allowed, AV_LEGACY_ALL_ONES, avd.auditallow, avd.auditdeny,
            avd.seqno, avd.flags)
}

/// Render one boolean's committed and pending values. # C: O(1)
///
/// Two decimals, one space. The pending value is the second: a caller reads
/// this to see what a commit would apply, so ordering them the other way
/// reports a change as already in force.
pub fn bool_response(committed: bool, pending: bool) -> String {
    format!("{} {}", u8::from(committed), u8::from(pending))
}

/// Render the highest policy version the engine reads. # C: O(1)
pub fn policyvers_response(version: u32) -> String { format!("{version}\n") }

/// Header naming the columns of a bucket-shape report.
const HASH_STATS_HEADER: &str = "entries buckets used_buckets longest_chain\n";
/// Header naming the columns of a cache-activity report.
const CACHE_STATS_HEADER: &str = "lookups misses allocations reclaims frees\n";

/// Render a bucket-shape report. # C: O(1)
pub fn hash_stats_response(entries: u32, buckets: u32, used: u32, longest: u32) -> String {
    format!("{HASH_STATS_HEADER}{entries} {buckets} {used} {longest}\n")
}

/// Render the decision cache's bucket shape. # C: O(1)
pub fn avc_hash_stats_response(st: &HashStats) -> String {
    hash_stats_response(st.entries, st.buckets, st.used_buckets, st.longest_chain)
}

/// Render the SID table's bucket shape. # C: O(1)
pub fn sidtab_hash_stats_response(st: &HashStats) -> String {
    hash_stats_response(st.entries, st.buckets, st.used_buckets, st.longest_chain)
}

/// Render the decision cache's activity counters. # C: O(1)
pub fn cache_stats_response(st: &CacheStats) -> String {
    format!("{CACHE_STATS_HEADER}{} {} {} {} {}\n",
            st.lookups, st.misses, st.allocations, st.reclaims, st.frees)
}

/// Version of the status page's layout.
pub const STATUS_VERSION: u32 = 1;

/// Fields the status page carries, each a little-endian word.
pub const STATUS_FIELDS: usize = 5;

/// Bytes of the whole status page.
pub const STATUS_PAGE_BYTES: usize = STATUS_FIELDS * STATUS_FIELD_BYTES;

/// Bytes of one status-page field.
pub const STATUS_FIELD_BYTES: usize = 4;

/// Render the status page userspace polls instead of re-reading each node.
/// # C: O(1)
///
/// The SEQUENCE word is what makes the page readable without a lock: it is
/// odd while the rest is being rewritten, so a reader that sees the same even
/// value before and after knows the fields between were consistent.
pub fn status_page(sequence: u32, enforcing: bool, policyload: u32, deny_unknown: bool)
    -> [u8; STATUS_PAGE_BYTES]
{
    let words = [STATUS_VERSION, sequence, u32::from(enforcing), policyload,
                 u32::from(deny_unknown)];
    let mut out = [0u8; STATUS_PAGE_BYTES];
    for (i, w) in words.iter().enumerate() {
        let at = i * STATUS_FIELD_BYTES;
        out[at..at + STATUS_FIELD_BYTES].copy_from_slice(&w.to_le_bytes());
    }
    out
}

#[cfg(test)]
#[path = "../tests/format_response.rs"]
mod tests;
