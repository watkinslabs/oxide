// `IOCB_CMD_POLL` wake arithmetic. A poll request completes from the wait-queue
// wakeup itself — not from a reap — so these two rules run inside the source's
// subscriber lock and are the only decision made there.

/// Conditions reported whether or not the caller asked for them, matching what
/// `poll(2)` always returns and what the request mask is widened with before it
/// is ever compared against a wake.
pub const POLL_ALWAYS: u32 = vfs::POLL_ERR | vfs::POLL_HUP;

/// Effective interest for a submitted poll request: what the caller asked for,
/// plus the always-reported error and hangup bits.
/// # C: O(1)
pub const fn request_events(mask: u16) -> u32 { mask as u32 | POLL_ALWAYS }

/// Mask a wake should complete a request with, or `0` to leave it pending.
///
/// `key` is what the source published with the wakeup; `0` marks a keyless
/// wake, where the source could not name the transition and `live` — the
/// file's freshly-read mask — is what decides instead. Restricting the result
/// to the request's own interest is what keeps an unrelated readiness change
/// from completing a request that never asked about it.
/// # C: O(1)
pub const fn wake_mask(key: u32, live: u32, req_events: u32) -> u32 {
    let observed = if key != 0 { key } else { live };
    observed & req_events
}
