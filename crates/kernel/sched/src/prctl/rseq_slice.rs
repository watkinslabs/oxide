// `prctl(PR_RSEQ_SLICE_EXTENSION, cmd, ctrl)` argument decoding.
//
// The task-state and user-area mutation belongs to `sched::rseq`; this small
// ungated owner keeps the ABI ordering hosted-testable.

use syscall::errno::Errno;
use super::uapi::{PR_RSEQ_SLICE_EXT_ENABLE, PR_RSEQ_SLICE_EXTENSION_GET,
                  PR_RSEQ_SLICE_EXTENSION_SET};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request { Get, Set(bool) }

/// Decode `PR_RSEQ_SLICE_EXTENSION`. # C: O(1)
pub fn decide(cmd: u64, ctrl: u64, a4: u64, a5: u64) -> Result<Request, Errno> {
    if a4 != 0 || a5 != 0 { return Err(Errno::Einval); }
    match cmd {
        PR_RSEQ_SLICE_EXTENSION_GET if ctrl == 0 => Ok(Request::Get),
        PR_RSEQ_SLICE_EXTENSION_GET => Err(Errno::Einval),
        PR_RSEQ_SLICE_EXTENSION_SET if ctrl & !PR_RSEQ_SLICE_EXT_ENABLE == 0 =>
            Ok(Request::Set(ctrl != 0)),
        PR_RSEQ_SLICE_EXTENSION_SET => Err(Errno::Einval),
        _ => Err(Errno::Einval),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_and_set_admit_only_the_published_control_shape() {
        assert_eq!(decide(PR_RSEQ_SLICE_EXTENSION_GET, 0, 0, 0), Ok(Request::Get));
        assert_eq!(decide(PR_RSEQ_SLICE_EXTENSION_SET, 0, 0, 0), Ok(Request::Set(false)));
        assert_eq!(decide(PR_RSEQ_SLICE_EXTENSION_SET, PR_RSEQ_SLICE_EXT_ENABLE, 0, 0),
                   Ok(Request::Set(true)));
        assert_eq!(decide(PR_RSEQ_SLICE_EXTENSION_GET, 1, 0, 0), Err(Errno::Einval));
        assert_eq!(decide(PR_RSEQ_SLICE_EXTENSION_SET, 2, 0, 0), Err(Errno::Einval));
        assert_eq!(decide(PR_RSEQ_SLICE_EXTENSION_GET, 0, 1, 0), Err(Errno::Einval));
    }
}
