// The namespace-wide half of fast open: the enable bits every socket in the
// namespace is judged against, and the default keys every listener that named
// none of its own mints from.
//
// The keys are drawn once, lazily, at the first moment a listener could need
// them — not at namespace creation, so a namespace that never listens never
// spends the entropy. A draw that loses the race leaves the winner's keys in
// place rather than replacing them: two listeners starting at once must agree
// on which key their cookies were minted from.

use network_namespace::NetworkNamespaceRef;
use sync::{Socket as SockLockClass, Spinlock};

use super::keys::{Key, KeyCtx, KEY_LEN};
use crate::net_ns::NetSysctlKey;

/// A namespace's default keys.
pub type NsKeys = Spinlock<Option<KeyCtx>, SockLockClass>;

/// `net.ipv4.tcp_fastopen` for a retained namespace. # C: O(log N)
pub fn enable_bits(namespace: &NetworkNamespaceRef) -> i32 {
    crate::net_ns::materialize_state(namespace).sysctls.get(NetSysctlKey::TcpFastopen) as i32
}

/// `net.ipv4.tcp_fastopen` in a live namespace, without creating state.
/// # C: O(log N)
pub fn enable_bits_in(ns: u64) -> Option<i32> {
    crate::sysctl::value_in(ns, NetSysctlKey::TcpFastopen).map(|bits| bits as i32)
}

/// The namespace's default keys, or `None` while it has drawn none.
/// # C: O(log N)
pub fn ns_keys(namespace: &NetworkNamespaceRef) -> Option<KeyCtx> {
    *crate::net_ns::materialize_state(namespace).fastopen_keys.lock()
}

/// Install the namespace's default keys, replacing whatever it held. This is
/// the administrative write; a cookie minted from the old key stops verifying
/// unless the write kept it as the backup. # C: O(log N)
pub fn set_ns_keys(namespace: &NetworkNamespaceRef, ctx: KeyCtx) {
    *crate::net_ns::materialize_state(namespace).fastopen_keys.lock() = Some(ctx);
}

/// Draw the namespace's default keys if it has none yet. # C: O(log N)
pub fn init_key_once(namespace: &NetworkNamespaceRef) {
    let state = crate::net_ns::materialize_state(namespace);
    if state.fastopen_keys.lock().is_some() { return; }
    let mut raw = [0u8; KEY_LEN];
    crng::fill(&mut raw);
    let mut keys = state.fastopen_keys.lock();
    if keys.is_none() { *keys = Some(KeyCtx::new(Key::new(raw), None)); }
}

#[cfg(test)]
#[path = "ns_tests.rs"]
mod tests;
