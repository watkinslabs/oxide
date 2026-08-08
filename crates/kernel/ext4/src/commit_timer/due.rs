// When a mount's running transaction is old enough to commit.
//
// UNGATED: this is the whole of what `commit=` decides, and it is stated here
// so `cargo test` can reach it without a clock, a timer or a mounted
// filesystem.

/// How often the periodic commit runs. One second is the finest interval
/// `commit=` can name, so a mount that asks for one second gets one second
/// rather than the next multiple of a coarser tick.
pub const TICK_PERIOD_NS: u64 = NS_PER_SEC;

/// Nanoseconds in a second; `commit=` is written in seconds.
pub const NS_PER_SEC: u64 = 1_000_000_000;

/// Whether a transaction last committed at `last_ns` is due at `now_ns`, for a
/// mount whose `commit=` interval is `commit_secs`.
///
/// A clock that went backwards (or a mount registered a hair in the future)
/// answers "not yet" rather than "immediately": treating a negative age as an
/// enormous one would commit on every tick until the clock caught up.
/// # C: O(1)
pub fn is_due(last_ns: u64, now_ns: u64, commit_secs: u32) -> bool {
    let Some(age) = now_ns.checked_sub(last_ns) else { return false };
    age >= interval_ns(commit_secs)
}

/// The interval in nanoseconds, saturating rather than wrapping — the option's
/// own ceiling keeps it far below that, and a wrap here would turn the longest
/// interval a mount can ask for into the shortest.
/// # C: O(1)
pub fn interval_ns(commit_secs: u32) -> u64 { (commit_secs as u64).saturating_mul(NS_PER_SEC) }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount_opts::behaviour::DEFAULT_COMMIT_SECS;

    /// The interval is real seconds, and the default one is the one a mount
    /// that named no option gets.
    #[test]
    fn the_interval_is_the_option_in_nanoseconds() {
        assert_eq!(interval_ns(1), NS_PER_SEC);
        assert_eq!(interval_ns(30), 30 * NS_PER_SEC);
        assert_eq!(interval_ns(DEFAULT_COMMIT_SECS), 5 * NS_PER_SEC);
    }

    /// A transaction younger than the interval waits; one that has reached it
    /// commits. The boundary is inclusive — a 5 s interval commits at 5 s, not
    /// at the tick after.
    #[test]
    fn a_transaction_commits_once_it_reaches_its_interval() {
        assert!(!is_due(0, 4 * NS_PER_SEC, 5));
        assert!(is_due(0, 5 * NS_PER_SEC, 5));
        assert!(is_due(0, 60 * NS_PER_SEC, 5));
    }

    /// The interval is PER MOUNT: the same age is due for a short interval and
    /// not for a long one, which is the whole point of the option being a
    /// mount option rather than a constant.
    #[test]
    fn each_mounts_own_interval_decides_it() {
        let age = 10 * NS_PER_SEC;
        assert!(is_due(0, age, 5), "commit=5 is due at 10 s");
        assert!(!is_due(0, age, 30), "commit=30 is not");
    }

    /// A clock that ran backwards must not commit on every tick until it
    /// catches up.
    #[test]
    fn a_backwards_clock_is_not_permanently_due() {
        assert!(!is_due(10 * NS_PER_SEC, NS_PER_SEC, 5));
    }

    /// The largest interval the option accepts stays an interval, rather than
    /// wrapping into a tiny one that would commit constantly.
    #[test]
    fn the_longest_interval_does_not_wrap_into_the_shortest() {
        let longest = interval_ns(crate::mount_opts::behaviour::MAX_COMMIT_SECS);
        assert!(longest > 60 * NS_PER_SEC);
        assert!(!is_due(0, 60 * NS_PER_SEC, crate::mount_opts::behaviour::MAX_COMMIT_SECS));
    }
}
