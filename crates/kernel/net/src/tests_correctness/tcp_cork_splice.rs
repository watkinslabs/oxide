// B275: `splice(2)` into a TCP socket must coalesce pipe segments the same
// way `sendmsg(MSG_MORE)`/`TCP_CORK` does. The socket-side fix
// (`InetSocket::write_more` -> `write_more_policy::plan_write_more`, in
// `sock/write_more_policy.rs` and `sock/io.rs`) is entirely
// `#[cfg(target_os = "oxide-kernel")]`-gated, so it cannot carry its own
// `cargo test` (a nested `#[cfg(test)]` module there compiles out silently
// under a hosted build — the pure cork decision has its own hosted test in
// `sock::write_more_policy::tests`).
//
// What CAN be driven hosted is the mechanism that decision feeds:
// `TcpConn::output_limit`'s `cork` parameter, exercised here exactly as the
// gated shim would drive it for a spliced multi-segment write. `nodelay` is
// held true throughout — Nagle alone already withholds a second sub-MSS
// write once the first is unacked in `retx_q`, which would mask the cork
// contribution; `TCP_NODELAY` (a common pairing with `sendfile`/`splice` for
// latency-sensitive senders) disables that masking, isolating what `cork`
// alone contributes.

use super::*;

#[test]
fn b275_corked_sub_mss_appends_hold_until_the_final_segment_releases() {
    let mut c = client_established();
    assert!(c.retx_q.is_empty(), "idle conn starts with nothing in flight");

    // Three spliced segments of an application record too small to fill one
    // MSS individually. The first two carry SPLICE_F_MORE-equivalent cork
    // (more pipe data queued) — this is `plan_write_more`'s `WriteMorePlan::
    // Tcp { cork: true }` arm reaching `output_limit`.
    c.send(b"AAAA");
    let segs = c.output(1500, /*nodelay*/ true, /*cork*/ true);
    assert!(segs.is_empty(), "corked: first segment held, nothing goes on the wire");
    assert_eq!(c.send_buf.len(), 4);
    assert!(c.retx_q.is_empty());

    c.send(b"BBBB");
    let segs = c.output(1500, true, true);
    assert!(segs.is_empty(), "corked: second segment held too");
    assert_eq!(c.send_buf.len(), 8);
    assert!(c.retx_q.is_empty());

    // Final segment: the pipe is drained, so the socket computes `more =
    // false` and (with `TCP_CORK` untouched on this conn) `cork = false`.
    c.send(b"CCCC");
    let segs = c.output(1500, true, false);
    assert_eq!(segs.len(), 1, "release flushes every held byte as ONE coalesced segment");
    assert_eq!(c.retx_q.len(), 1);
    assert_eq!(c.retx_q.back().unwrap().payload.len(), 12,
        "the coalesced segment carries all three spliced writes, not one segment per write");
    assert!(c.send_buf.is_empty());
}

/// Positive control for the test above: with the hint dropped (`cork` never
/// true — the pre-fix shape, `write_more_file`'s default forwarding to the
/// plain write), each spliced segment goes out immediately as its own small
/// TCP segment. `TCP_NODELAY` isolates this from Nagle's independent
/// in-flight hold, which would otherwise mask the missing cork.
#[test]
fn b275_uncorked_sub_mss_appends_each_flush_immediately() {
    let mut c = client_established();

    c.send(b"AAAA");
    let segs = c.output(1500, true, false);
    assert_eq!(segs.len(), 1, "no cork: first write flushes on its own");
    assert_eq!(c.retx_q.len(), 1);

    c.send(b"BBBB");
    let segs = c.output(1500, true, false);
    assert_eq!(segs.len(), 1, "no cork: second write flushes on its own too — the bug this row fixes");
    assert_eq!(c.retx_q.len(), 2, "two small segments on the wire instead of one coalesced one");

    c.send(b"CCCC");
    let segs = c.output(1500, true, false);
    assert_eq!(segs.len(), 1, "no cork: third write flushes on its own as well");
    assert_eq!(c.retx_q.len(), 3, "three tiny segments where the fixed path emits one");
}
