// Where a connection meets the per-destination metrics cache: once when its
// handshake finishes, once when it closes.
//
// Both are shims. The seed and the write-back are decided in ungated
// `crate::tcp_metrics`, and the unit conversion between this connection's
// bytes and the cache's segments is `crate::tcp_conn::metrics`; this file
// only knows which namespace the destination is reachable through and when
// the two moments happen.

use super::*;

/// `tcp_init_metrics`: seed a connection whose handshake has just finished
/// from what this host remembers about the destination. # C: O(log N)
pub(crate) fn seed_from_cache(entry: &TcpEntry) {
    let net_ns = entry.net_ns();
    let no_ssthresh_save = crate::sysctl::tcp_no_ssthresh_metrics_save_in(net_ns);
    let (src, dst, fresh) = {
        let conn = entry.conn.lock();
        (conn.local.ip, conn.remote.ip,
         conn.metrics_fresh(crate::tcp_conn::metrics::DEFAULT_REORDERING, no_ssthresh_save))
    };
    let cached = crate::tcp_metrics::cached_in(net_ns, src, dst);
    let seed = crate::tcp_metrics::seed(cached, fresh);
    entry.conn.lock().apply_metrics_seed(seed);
}

/// `tcp_update_metrics`: leave what this connection measured for the next one
/// to the same destination. # C: O(log N)
pub(crate) fn record_to_cache(entry: &TcpEntry, now_ns: u64) {
    let net_ns = entry.net_ns();
    if crate::sysctl::tcp_nometrics_save_in(net_ns) { return; }
    let no_ssthresh_save = crate::sysctl::tcp_no_ssthresh_metrics_save_in(net_ns);
    let (src, dst, closing) = {
        let conn = entry.conn.lock();
        if !conn.metrics_worth_recording() { return; }
        (conn.local.ip, conn.remote.ip,
         conn.metrics_closing(crate::tcp_conn::metrics::DEFAULT_REORDERING, no_ssthresh_save))
    };
    crate::tcp_metrics::record_in(net_ns, src, dst, now_ns, closing);
}
