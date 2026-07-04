/// Canonical line buffer cap. Linux N_TTY_BUF_SIZE is 4096; a cooked
/// line that overruns simply stops accepting non-terminator bytes
/// (the terminator still completes the line) — matches Linux's
/// behaviour of dropping past the limit while keeping the line usable.
pub(super) const CANON_CAP: usize = 4096;

/// Tab stop width for OPOST tab expansion (Linux `XTABS`/`TAB3` expands
/// to the next multiple of 8 columns).
pub(super) const TAB_WIDTH: u16 = 8;

/// Withheld-output cap while IXON-stopped. A producer that keeps writing
/// while flow is stopped is bounded here (Linux backpressures the writer;
/// at this lock-free layer we cap and drop past the limit — the visible
/// effect on resume is identical for the scroll-pause use case).
pub(super) const HOLD_CAP: usize = 4096;

/// IXON input-byte classification (Linux `n_tty.c` flow control). Pure:
/// the caller supplies the live termios bits + the byte, and acts on the
/// verdict (set/clear `stopped`, consume the byte). Host-testable alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowAction {
    /// VSTOP (^S): set `stopped`, consume the byte (not queued/echoed).
    Stop,
    /// VSTART (^Q) or any byte under IXANY while stopped: clear `stopped`,
    /// consume the byte.
    Start,
    /// Not a flow-control byte — process normally.
    Normal,
}

/// Classify one input byte for IXON flow control given the live termios.
///   * `iflag` — c_iflag (IXON / IXANY bits read via `crate::pty::iflag`)
///   * `vstop` = c_cc[VSTOP] (^S), `vstart` = c_cc[VSTART] (^Q)
///   * `b` = the (i-mapped) input byte, `stopped` = current flow state
///
/// Linux rules: IXON off → always Normal. VSTOP byte → Stop. VSTART byte
/// → Start. While `stopped` with IXANY set, ANY other byte → Start (Linux
/// restarts output on any key). A `0` cc disables that control char.
/// # C: O(1)
pub fn flow_action(iflag: u32, vstop: u8, vstart: u8, b: u8, stopped: bool) -> FlowAction {
    if iflag & crate::pty::iflag::IXON == 0 { return FlowAction::Normal; }
    if vstop != 0 && b == vstop { return FlowAction::Stop; }
    if vstart != 0 && b == vstart { return FlowAction::Start; }
    // IXANY: any byte resumes paused output (but is still processed).
    if stopped && iflag & crate::pty::iflag::IXANY != 0 { return FlowAction::Start; }
    FlowAction::Normal
}

/// Noncanonical (raw-mode) VMIN/VTIME read decision (Linux `n_tty.c`
/// `n_tty_read` / `job_control` + the VMIN/VTIME state machine). Pure:
/// no clock, no lock — the tty core (T4) supplies elapsed values and
/// acts on the verdict. Host-testable in isolation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmtDecision {
    /// Enough is satisfied — drain `n` bytes (`min(available, buf_len)`)
    /// and return. `n` may be 0 (polling / timeout with nothing queued).
    ReturnNow(usize),
    /// Block until an RX wake OR the monotonic clock reaches the carried
    /// deadline (relative ns from the read-entry base — caller adds its
    /// `now_ns` base). A VTIME timer.
    BlockUntil(u64),
    /// Block until an RX wake, no timer (MIN>0, TIME==0: wait for MIN
    /// bytes; or MIN>0, TIME>0 before the first byte arrives).
    BlockNoDeadline,
}

/// VTIME unit: tenths of a second, in nanoseconds (Linux c_cc[VTIME] is
/// in 1/10 s). `TIME * VTIME_TENTH_NS` is the timer length.
pub const VTIME_TENTH_NS: u64 = 100_000_000;

/// Decide a noncanonical read's next action from the 4 Linux VMIN/VTIME
/// cases. Inputs are all caller-measured so this stays a pure function:
///   * `min`  = c_cc[VMIN], `time` = c_cc[VTIME] (raw cc bytes)
///   * `avail` = bytes drainable now, `buf_len` = caller buffer
///   * `since_start_ns` = ns since read entry (for MIN==0,TIME>0)
///   * `since_byte_ns`  = ns since the most recent byte arrived, and
///     `got_any` = at least one byte has arrived this read (interbyte
///     timer, MIN>0 TIME>0)
///
/// The 4 Linux cases:
///   MIN==0,TIME==0: polling — return immediately (0 if empty).
///   MIN>0, TIME==0: block until ≥MIN available (no timer).
///   MIN==0,TIME>0 : read timer — first byte ends it; else BlockUntil
///                   start+TIME; on expiry return what's there (maybe 0).
///   MIN>0, TIME>0 : interbyte timer — before any byte: BlockNoDeadline;
///                   after first byte: return at MIN/buf-full, else
///                   BlockUntil last-byte+TIME; on interbyte expiry
///                   return what's there.
/// # C: O(1)
pub fn vmin_vtime_decision(
    min: u8, time: u8, avail: usize, buf_len: usize,
    since_start_ns: u64, since_byte_ns: u64, got_any: bool,
) -> VmtDecision {
    let min = min as usize;
    let take = avail.min(buf_len);
    match (min == 0, time == 0) {
        // MIN==0, TIME==0: pure polling read.
        (true, true) => VmtDecision::ReturnNow(take),
        // MIN>0, TIME==0: block until at least MIN bytes (or buf full).
        (false, true) => {
            if avail >= min || avail >= buf_len { VmtDecision::ReturnNow(take) }
            else { VmtDecision::BlockNoDeadline }
        }
        // MIN==0, TIME>0: read timer on the FIRST byte.
        (true, false) => {
            if avail > 0 { return VmtDecision::ReturnNow(take); }
            let dl = time as u64 * VTIME_TENTH_NS;
            if since_start_ns >= dl { VmtDecision::ReturnNow(0) }
            else { VmtDecision::BlockUntil(dl) }
        }
        // MIN>0, TIME>0: interbyte timer (starts after the first byte).
        (false, false) => {
            if avail >= min || avail >= buf_len { return VmtDecision::ReturnNow(take); }
            if !got_any { return VmtDecision::BlockNoDeadline; }
            let dl = time as u64 * VTIME_TENTH_NS;
            if since_byte_ns >= dl { VmtDecision::ReturnNow(take) }
            else { VmtDecision::BlockUntil(dl) }
        }
    }
}
