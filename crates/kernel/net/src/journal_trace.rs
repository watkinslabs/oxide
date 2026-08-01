// B288 journald/syslog/sd_notify datagram trace, and the field-selection
// decision behind it. Split out of `lib.rs` per the manifest-only rule
// (CLAUDE.md "Crate/module shape rules").

/// B288 diagnostic: dump AF_UNIX SOCK_DGRAM payloads sent to the
/// journal / syslog / sd_notify sockets so early-boot service error
/// strings (tmpfiles/sysusers/udevd/journald) surface in klog. The
/// services log their fatal reason to journald's socket (which queues
/// because journald itself is wedged), so the payload is the only
/// place the human-readable cause appears — and it is where `boot-smoke`'s
/// `Reached target basic.target` marker comes from, so this stays on
/// `debug-boot`.
///
/// B1474: on `debug-boot` only the human-readable line is emitted. A journald
/// native record is a set of `FIELD=value` lines of which exactly one
/// (`MESSAGE=`) is prose; the rest — PRIORITY, SYSLOG_FACILITY, TID, CODE_FILE,
/// CODE_LINE, CODE_FUNC, INVOCATION_ID, MESSAGE_ID, UNIT, JOB_* — is machine
/// metadata that multiplied console volume ~14x per record and carried no fact
/// a reader or the smoke marker uses. `debug-journal` restores the complete
/// record. Payloads with no `MESSAGE=` field (`/dev/log` syslog text,
/// `sd_notify` READY=1/STATUS=) are already one short line and print whole.
/// # C: O(payload bytes)
#[cfg(all(target_os = "oxide-kernel", any(feature = "debug-boot", feature = "debug-journal")))]
pub fn trace_dgram_journal(path: &[u8], payload: &[u8]) {
    let is_journal = path.windows(7).any(|w| w == b"journal")
        || path.windows(4).any(|w| w == b"/log")
        || path.windows(6).any(|w| w == b"notify")
        || path.windows(7).any(|w| w == b"dev-log");
    if !is_journal { return; }
    // Cap the dump so a huge journal record can't flood the UART.
    const DUMP_CAP: usize = 512;
    #[cfg(feature = "debug-journal")]
    let body = payload;
    #[cfg(not(feature = "debug-journal"))]
    let body = message_field(payload).unwrap_or(payload);
    klog::write_raw(b"[B288 dgram ");
    klog::write_raw(&crate::unix_sock::unix_path_display(path));
    klog::write_raw(b" pid=");
    let pid = sched::live::current().map(|t| t.visible_pid()).unwrap_or(0);
    klog::write_dec_u64(pid as u64);
    klog::write_raw(b"] ");
    klog::write_raw(&body[..core::cmp::min(body.len(), DUMP_CAP)]);
    klog::write_raw(b"\n");
}

/// The `MESSAGE=`-prefixed line of a journald native record, without its
/// newline. `None` when the payload carries no such field, which is the
/// non-journald case (syslog text, sd_notify) and prints whole.
///
/// Ungated and hosted-tested: `net`'s kernel body is target-gated, so decision
/// logic placed there would compile its tests out silently (CLAUDE.md phantom
/// -test rule).
/// # C: O(payload.len())
pub fn message_field(payload: &[u8]) -> Option<&[u8]> {
    const KEY: &[u8] = b"MESSAGE=";
    let mut start = 0usize;
    while start < payload.len() {
        let mut end = start;
        while end < payload.len() && payload[end] != b'\n' { end += 1; }
        let line = &payload[start..end];
        if line.starts_with(KEY) { return Some(line); }
        start = end + 1;
    }
    None
}

/// No-op when neither `debug-boot` nor `debug-journal` is on.
/// # C: O(1)
#[cfg(not(all(target_os = "oxide-kernel", any(feature = "debug-boot", feature = "debug-journal"))))]
#[inline]
pub fn trace_dgram_journal(_path: &[u8], _payload: &[u8]) {}
