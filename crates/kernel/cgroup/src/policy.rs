use alloc::vec::Vec;

/// Parse a Linux cpulist (`"0-3,7,9-11"`) into a CPU bitmask (bit N ⇔
/// CPU N), capped at 64. Empty/whitespace → `None` (no restriction).
/// Malformed tokens are skipped (best-effort, matching how the kernel
/// tolerates partial writes). Pure — hosted-tested.
/// # C: O(len)
pub fn cpulist_to_mask(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() { return None; }
    let mut mask = 0u64;
    for tok in s.split(',') {
        let tok = tok.trim();
        if tok.is_empty() { continue; }
        if let Some((a, b)) = tok.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
                for c in lo..=hi.min(63) { if c < 64 { mask |= 1u64 << c; } }
            }
        } else if let Ok(c) = tok.parse::<u32>() {
            if c < 64 { mask |= 1u64 << c; }
        }
    }
    if mask == 0 { None } else { Some(mask) }
}

/// Map cgroup v2 `cpu.weight` (1..=10000, default 100) → CFS load weight
/// (nice-0 == cpu.weight 100 == weight 1024). Saturates to ≥1.
/// # C: O(1)
pub fn cpu_weight_to_cfs(cpu_weight: u32) -> u32 {
    ((cpu_weight as u64 * NICE_0_CFS as u64) / 100).clamp(1, u32::MAX as u64) as u32
}

/// CFS weight of a nice-0 task — kept in sync with `sched::cputime`.
const NICE_0_CFS: u32 = 1024;

/// cpu.max bandwidth-scan decision for one cgroup.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CpuAction {
    /// Within quota this period — leave members running.
    Continue,
    /// Over quota this period — freeze members until the next refill.
    Throttle,
    /// Period elapsed — start a new period: unthrottle + re-baseline at
    /// `new_base_ns` (the current cumulative member runtime).
    Refill { new_base_ns: u64 },
}

/// Decide the bandwidth action for a cgroup given the cumulative member
/// runtime `total_ns` (sum of members' sum_exec_runtime), the quota +
/// period, the runtime `base_ns` captured at period start, the period
/// start time, and `now_ns`. Pure — hosted-tested.
///
/// - period elapsed (`now - period_start >= period`) → Refill (re-baseline
///   to `total_ns`, unthrottle).
/// - else consumed (`total - base`) >= quota → Throttle.
/// - else Continue.
/// # C: O(1)
pub fn cpu_bandwidth_decision(
    total_ns: u64, base_ns: u64, quota_ns: u64, period_ns: u64,
    period_start_ns: u64, now_ns: u64,
) -> CpuAction {
    if period_ns == 0 || now_ns.saturating_sub(period_start_ns) >= period_ns {
        return CpuAction::Refill { new_base_ns: total_ns };
    }
    let consumed = total_ns.saturating_sub(base_ns);
    if consumed >= quota_ns { CpuAction::Throttle } else { CpuAction::Continue }
}

pub(crate) fn empty_cpu_groups() -> Vec<crate::tree::CpuGroup> {
    Vec::new()
}
