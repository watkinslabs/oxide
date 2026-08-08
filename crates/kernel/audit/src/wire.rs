// `struct audit_status` and `struct audit_features` on the wire.
//
// Both grew fields over time and userspace sends whichever prefix it was built
// against, so a short request is zero-extended rather than refused — an older
// `auditctl` must not stop working on a newer kernel.

extern crate alloc;

use alloc::vec::Vec;

use crate::config::{Config, FeatureRequest};
use crate::uapi::*;

/// Field order of `struct audit_status`.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Status {
    pub mask: u32,
    pub enabled: u32,
    pub failure: u32,
    pub pid: u32,
    pub rate_limit: u32,
    pub backlog_limit: u32,
    pub lost: u32,
    pub backlog: u32,
    pub feature_bitmap: u32,
    pub backlog_wait_time: u32,
    pub backlog_wait_time_actual: u32,
}

/// Number of `u32` words in `struct audit_status`.
const STATUS_WORDS: usize = AUDIT_STATUS_LEN / 4;
/// Number of `u32` words in `struct audit_features`.
const FEATURES_WORDS: usize = AUDIT_FEATURES_LEN / 4;

/// Read `n` little-endian words, zero-extending past the end of `data`.
/// # C: O(n)
fn words<const N: usize>(data: &[u8]) -> [u32; N] {
    let mut out = [0u32; N];
    for (i, w) in out.iter_mut().enumerate() {
        let off = i * 4;
        if off + 4 > data.len() { break; }
        *w = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    }
    out
}

impl Status {
    /// Decode a request, zero-extending a short one.
    /// # C: O(1)
    pub fn decode(data: &[u8]) -> Self {
        let w = words::<STATUS_WORDS>(data);
        Self {
            mask: w[0], enabled: w[1], failure: w[2], pid: w[3], rate_limit: w[4],
            backlog_limit: w[5], lost: w[6], backlog: w[7], feature_bitmap: w[8],
            backlog_wait_time: w[9], backlog_wait_time_actual: w[10],
        }
    }

    /// # C: O(1)
    pub fn encode(&self) -> Vec<u8> {
        let w = [self.mask, self.enabled, self.failure, self.pid, self.rate_limit,
                 self.backlog_limit, self.lost, self.backlog, self.feature_bitmap,
                 self.backlog_wait_time, self.backlog_wait_time_actual];
        let mut out = Vec::with_capacity(AUDIT_STATUS_LEN);
        for v in w { out.extend_from_slice(&v.to_le_bytes()); }
        out
    }

    /// The status a `AUDIT_GET` reply carries. `mask` is zero on a reply: it
    /// selects fields on the way in, and every field is present on the way out.
    /// # C: O(1)
    pub fn from_config(cfg: &Config, auditd_pid: u32, backlog: usize) -> Self {
        Self {
            mask: 0,
            enabled: cfg.enabled,
            failure: cfg.failure,
            pid: auditd_pid,
            rate_limit: cfg.rate_limit,
            backlog_limit: cfg.backlog_limit,
            lost: cfg.lost,
            backlog: backlog as u32,
            feature_bitmap: AUDIT_FEATURE_BITMAP_ALL,
            backlog_wait_time: cfg.backlog_wait_time,
            backlog_wait_time_actual: cfg.backlog_wait_time_actual,
        }
    }
}

impl FeatureRequest {
    /// # C: O(1)
    pub fn decode(data: &[u8]) -> Self {
        let w = words::<FEATURES_WORDS>(data);
        Self { vers: w[0], mask: w[1], features: w[2], lock: w[3] }
    }

    /// The features reply: the version this kernel speaks, every toggleable
    /// bit as the changeable mask, then the live values.
    /// # C: O(1)
    pub fn reply(cfg: &Config) -> Vec<u8> {
        let mut mask = 0u32;
        for i in 0..=AUDIT_LAST_FEATURE { mask |= feature_to_mask(i); }
        let w = [AUDIT_FEATURE_VERSION, mask, cfg.features, cfg.feature_lock];
        let mut out = Vec::with_capacity(AUDIT_FEATURES_LEN);
        for v in w { out.extend_from_slice(&v.to_le_bytes()); }
        out
    }
}

#[cfg(test)]
#[path = "tests/wire.rs"]
mod tests;
