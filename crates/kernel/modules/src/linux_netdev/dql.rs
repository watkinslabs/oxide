use super::types::LinuxDql;

const DQL_MAX_OBJECT: u32 = u32::MAX / 16;
const DQL_MAX_LIMIT: u32 = u32::MAX / 2 - DQL_MAX_OBJECT;

/// Register dynamic queue-limit KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("dql_completed", dql_completed as *const () as usize, false);
    export("dql_reset", dql_reset as *const () as usize, false);
}

pub(super) fn init(dql: &mut LinuxDql, hold_time: u32) {
    dql.max_limit = DQL_MAX_LIMIT;
    dql.min_limit = 0;
    dql.slack_hold_time = hold_time;
    dql.stall_thrs = 0;
    reset(dql, now());
}

/// # C: O(1)
unsafe extern "C" fn dql_reset(dql: *mut LinuxDql) {
    if dql.is_null() { return; }
    // SAFETY: non-null dql is a driver-owned queue-limit object.
    unsafe { reset(&mut *dql, now()); }
}

/// # C: O(1)
unsafe extern "C" fn dql_completed(dql: *mut LinuxDql, count: u32) {
    if dql.is_null() { return; }
    // SAFETY: non-null dql is serialized by the driver's completion path.
    unsafe { completed(&mut *dql, count, now()); }
}

fn reset(dql: &mut LinuxDql, now: usize) {
    dql.limit = dql.min_limit;
    dql.num_queued = 0;
    dql.num_completed = 0;
    dql.last_obj_cnt = 0;
    dql.prev_num_queued = 0;
    dql.prev_last_obj_cnt = 0;
    dql.prev_ovlimit = 0;
    dql.lowest_slack = u32::MAX;
    dql.slack_start_time = now;
    dql.last_reap = now;
    dql.history_head = now / usize::BITS as usize;
    dql.history.fill(0);
}

fn completed(dql: &mut LinuxDql, count: u32, now: usize) {
    let queued = dql.num_queued;
    let outstanding = queued.wrapping_sub(dql.num_completed);
    if count > outstanding { return; }
    let completed = dql.num_completed.wrapping_add(count);
    let mut limit = dql.limit;
    let mut ovlimit = posdiff(queued.wrapping_sub(dql.num_completed), limit);
    let inprogress = queued.wrapping_sub(completed);
    let previous = dql.prev_num_queued.wrapping_sub(dql.num_completed);
    let all_previous = completed.wrapping_sub(dql.prev_num_queued) as i32 >= 0;
    if (ovlimit != 0 && inprogress == 0) || (dql.prev_ovlimit != 0 && all_previous) {
        limit = limit.saturating_add(posdiff(completed, dql.prev_num_queued)).saturating_add(dql.prev_ovlimit);
        dql.slack_start_time = now;
        dql.lowest_slack = u32::MAX;
    } else if inprogress != 0 && previous != 0 && !all_previous {
        let slack = posdiff(limit.saturating_add(dql.prev_ovlimit),
            completed.wrapping_sub(dql.num_completed).saturating_mul(2));
        let last = if dql.prev_ovlimit != 0 { posdiff(dql.prev_last_obj_cnt, dql.prev_ovlimit) } else { 0 };
        dql.lowest_slack = dql.lowest_slack.min(slack.max(last));
        if now.wrapping_sub(dql.slack_start_time) as isize > dql.slack_hold_time as isize {
            limit = posdiff(limit, dql.lowest_slack);
            dql.slack_start_time = now;
            dql.lowest_slack = u32::MAX;
        }
    }
    limit = limit.clamp(dql.min_limit, dql.max_limit);
    if limit != dql.limit { dql.limit = limit; ovlimit = 0; }
    dql.adj_limit = limit.wrapping_add(completed);
    dql.prev_ovlimit = ovlimit;
    dql.prev_last_obj_cnt = dql.last_obj_cnt;
    dql.num_completed = completed;
    dql.prev_num_queued = queued;
    if dql.stall_thrs != 0 { dql.last_reap = now; }
}

fn posdiff(a: u32, b: u32) -> u32 { if a.wrapping_sub(b) as i32 > 0 { a.wrapping_sub(b) } else { 0 } }

fn now() -> usize {
    crate::linux_time::jiffies_now() as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_returns_queue_budget() {
        let mut dql: LinuxDql = unsafe { core::mem::zeroed() };
        init(&mut dql, 1000);
        dql.limit = 4096;
        dql.num_queued = 1500;
        completed(&mut dql, 1500, 10);
        assert_eq!(dql.num_completed, 1500);
        assert_eq!(dql.adj_limit, dql.limit + 1500);
    }
}
