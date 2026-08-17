// The retransmission schedule.
//
// Two deadlines govern an outstanding call, and conflating them is the classic
// way to get this wrong:
//
//   * the MINOR timeout is when the current attempt has waited long enough and
//     the call is retransmitted with a longer next interval;
//   * the MAJOR timeout is when the whole call gives up.
//
// A client with only the minor deadline retransmits forever; one with only the
// major deadline sends once and waits the entire budget before reporting a loss
// that a resend would have recovered in a fraction of it.
//
// Times are in milliseconds so this module is testable without a tick source.

/// A transport's retransmission policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcTimeout {
    /// Wait before the first retransmission.
    pub initval: u64,
    /// Ceiling on the per-attempt wait.
    pub maxval: u64,
    /// Added to the wait per attempt when the backoff is linear.
    pub increment: u64,
    /// Retransmissions before the call gives up.
    pub retries: u32,
    /// Double the wait each attempt instead of adding `increment`.
    pub exponential: bool,
}

impl RpcTimeout {
    /// The default for a stream transport: one long wait, no backoff growth.
    /// A stream already retransmits beneath us, so the RPC layer's job is to
    /// decide when to give up, not when to resend. # C: O(1)
    pub const TCP: RpcTimeout = RpcTimeout {
        initval: 60_000, maxval: 60_000, increment: 0, retries: 2, exponential: false,
    };

    /// The default for a datagram transport: short first wait, linear growth,
    /// several attempts — nothing else will resend a lost datagram. # C: O(1)
    pub const UDP: RpcTimeout = RpcTimeout {
        initval: 5_000, maxval: 30_000, increment: 5_000, retries: 5, exponential: false,
    };

    /// Total budget one call gets from its start, given a current per-attempt
    /// wait of `timeout`. # C: O(1)
    pub const fn major_span(&self, timeout: u64) -> u64 {
        let mut m = if self.exponential { timeout << self.retries }
                    else { timeout + self.increment * self.retries as u64 };
        if m > self.maxval || m == 0 { m = self.maxval; }
        m
    }
}

/// What the schedule says to do now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutOutcome {
    /// The current attempt still has time; keep waiting.
    Wait,
    /// The minor deadline passed; resend with the adjusted interval.
    Retransmit,
    /// The major deadline passed; the call has failed.
    MajorTimeout,
}

/// Per-call retransmission state.
#[derive(Clone, Copy, Debug)]
pub struct RetryState {
    /// The current per-attempt wait.
    pub timeout: u64,
    /// Retransmissions made so far.
    pub retries: u32,
    /// Absolute time the call gives up.
    pub majortimeo: u64,
    /// Absolute time the current attempt is retransmitted.
    pub minortimeo: u64,
}

impl RetryState {
    /// Start a call at `now` under `to`. # C: O(1)
    pub fn start(to: &RpcTimeout, now: u64) -> Self {
        Self {
            timeout: to.initval,
            retries: 0,
            majortimeo: now + to.major_span(to.initval),
            minortimeo: now + to.initval,
        }
    }

    /// Advance the schedule to `now`.
    ///
    /// On a major timeout the state is RESET to a fresh budget as well as
    /// reported: a caller that chooses to keep the call alive — because the
    /// operation is idempotent and the server is merely slow — then continues
    /// from a clean schedule rather than re-reporting a deadline that has
    /// already passed on every subsequent poll. # C: O(1)
    pub fn adjust(&mut self, to: &RpcTimeout, now: u64) -> TimeoutOutcome {
        // Both deadlines advance by ADDING to themselves, not by restarting
        // from `now`. Restarting would hand back the whole interval every time
        // the schedule is polled a little late, so a call polled slightly after
        // each deadline would never accumulate elapsed time and the major
        // budget would never expire.
        let outcome;
        if now < self.majortimeo {
            if now < self.minortimeo { return TimeoutOutcome::Wait; }
            if to.exponential { self.timeout <<= 1; } else { self.timeout += to.increment; }
            if to.maxval != 0 && self.timeout >= to.maxval { self.timeout = to.maxval; }
            self.retries += 1;
            outcome = TimeoutOutcome::Retransmit;
        } else {
            self.timeout = to.initval;
            self.retries = 0;
            self.majortimeo += to.major_span(self.timeout);
            outcome = TimeoutOutcome::MajorTimeout;
        }
        self.minortimeo += self.timeout;
        outcome
    }
}
