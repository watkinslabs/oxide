use sched::task::WaitOutcome;
use syscall::errno::Errno;

/// Translate the killable sibling-drain result at exec's point of no return.
/// # C: O(1)
pub const fn result(outcome: WaitOutcome) -> Result<(), Errno> {
    match outcome {
        WaitOutcome::Ready => Ok(()),
        WaitOutcome::Interrupted | WaitOutcome::TimedOut => Err(Errno::Eagain),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibling_retirement_allows_exec_to_commit() {
        assert_eq!(result(WaitOutcome::Ready), Ok(()));
    }

    #[test]
    fn fatal_interruption_reports_eagain_not_eintr_or_restart() {
        assert_eq!(result(WaitOutcome::Interrupted), Err(Errno::Eagain));
    }

    #[test]
    fn an_impossible_timeout_cannot_commit_the_new_mm() {
        assert_eq!(result(WaitOutcome::TimedOut), Err(Errno::Eagain));
    }
}
