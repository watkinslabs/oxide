// The connection table's two-kind mutations, owned here because publishing a
// passive open and unhooking it are the listener's half of that table.
//
// Every one is EXACT: it acts only where the table still holds the entry the
// caller means. A promoted request is REPLACED in its slot by the child, so a
// timer firing against the vanished request cannot remove the connection that
// took its place.

use super::super::*;

pub(crate) fn remove_tcp_entry_exact(tables: &super::inet_tables::InetTables,
                                     key: &TcpKey, entry: &Arc<TcpEntry>) -> bool {
    let mut conns = tables.tcp_conns.lock();
    if !conns.get(key).and_then(super::TcpSlot::sock)
        .is_some_and(|current| Arc::ptr_eq(current, entry)) { return false; }
    conns.remove(key);
    drop(conns);
    super::tcp_timer::cancel(entry);
    true
}

/// Unhook a half-open request, but only where the table still holds THIS one:
/// the acknowledgement that promotes a request replaces it in the same slot,
/// so a late timer must not remove the child that took its place. # C: O(log N)
pub(crate) fn remove_tcp_request_exact(tables: &super::inet_tables::InetTables,
                                       key: &TcpKey, req: &Arc<super::TcpReq>) -> bool {
    let mut conns = tables.tcp_conns.lock();
    if !conns.get(key).and_then(super::TcpSlot::req)
        .is_some_and(|current| Arc::ptr_eq(current, req)) { return false; }
    conns.remove(key);
    drop(conns);
    super::tcp_timer::cancel_req(req);
    true
}

/// Put a completed child in the table slot its request occupied. The request
/// is replaced rather than removed and re-inserted, so no arriving segment
/// sees the 4-tuple unoccupied. # C: O(log N)
pub(crate) fn replace_request_with_child(tables: &super::inet_tables::InetTables,
                                         key: &TcpKey, req: &Arc<super::TcpReq>,
                                         entry: &Arc<TcpEntry>) -> bool {
    let mut conns = tables.tcp_conns.lock();
    if !conns.get(key).and_then(super::TcpSlot::req)
        .is_some_and(|current| Arc::ptr_eq(current, req)) { return false; }
    conns.insert(*key, super::TcpSlot::Sock(entry.clone()));
    drop(conns);
    super::tcp_timer::cancel_req(req);
    true
}

/// Publish a half-open request into the connection table. # C: O(log N)
pub(crate) fn publish_request(tables: &super::inet_tables::InetTables,
                              listener: &TcpListenEntry, key: TcpKey,
                              req: &Arc<super::TcpReq>) -> bool {
    let mut conns = tables.tcp_conns.lock();
    if listener.is_closed() || conns.contains_key(&key) {
        drop(conns);
        req.release_syn_backlog();
        return false;
    }
    conns.insert(key, super::TcpSlot::Req(req.clone()));
    true
}

pub(crate) fn publish_passive_child(tables: &super::inet_tables::InetTables,
                                    listener: &TcpListenEntry, key: TcpKey,
                                    entry: &Arc<TcpEntry>) -> bool {
    let mut conns = tables.tcp_conns.lock();
    if listener.is_closed() || conns.contains_key(&key) {
        drop(conns);
        entry.release_backlog();
        entry.close_and_wake();
        return false;
    }
    conns.insert(key, super::TcpSlot::Sock(entry.clone()));
    true
}
