//! Per-network-namespace string `proc_handler`: a leaf whose live value is a
//! namespace-owned text value rather than an integer, and whose file may be
//! readable only by the owner (`net/ipv4/tcp_fastopen_key` is a secret, so its
//! file is 0600 while every other leaf beside it is 0644).
//!
//! Split out of `proc_handler` for the file-length cap; the split moves text,
//! not policy. Like the integer per-namespace handlers, `current_ns` runs once
//! at open and the returned handler carries that namespace for its lifetime,
//! so a leaf opened in one namespace never starts reporting another's.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use network_namespace::NetworkNamespaceRef;

use crate::proc_handler::ProcHandler;

pub struct PerNetStrHook {
    pub current_ns: fn() -> NetworkNamespaceRef,
    pub get: fn(&NetworkNamespaceRef) -> Vec<u8>,
    pub set: fn(&NetworkNamespaceRef, &[u8]) -> Result<(), ()>,
    /// The value is a secret, so the file is readable only by its owner.
    pub owner_only: bool,
}

struct BoundPerNetStrHook {
    namespace: NetworkNamespaceRef,
    get: fn(&NetworkNamespaceRef) -> Vec<u8>,
    set: fn(&NetworkNamespaceRef, &[u8]) -> Result<(), ()>,
    owner_only: bool,
}

fn format_in(namespace: &NetworkNamespaceRef,
    get: fn(&NetworkNamespaceRef) -> Vec<u8>) -> Vec<u8>
{
    let mut text = get(namespace);
    if text.last() != Some(&b'\n') { text.push(b'\n'); }
    text
}

impl ProcHandler for PerNetStrHook {
    fn format(&self) -> Vec<u8> { format_in(&(self.current_ns)(), self.get) }
    fn store(&self, src: &[u8]) -> Result<(), ()> { (self.set)(&(self.current_ns)(), src) }
    fn owner_only(&self) -> bool { self.owner_only }
    fn bind(&self) -> Option<Arc<dyn ProcHandler>> {
        Some(Arc::new(BoundPerNetStrHook {
            namespace: (self.current_ns)(), get: self.get, set: self.set,
            owner_only: self.owner_only,
        }))
    }
}

impl ProcHandler for BoundPerNetStrHook {
    fn format(&self) -> Vec<u8> { format_in(&self.namespace, self.get) }
    fn store(&self, src: &[u8]) -> Result<(), ()> { (self.set)(&self.namespace, src) }
    fn owner_only(&self) -> bool { self.owner_only }
}

#[cfg(test)]
#[path = "proc_handler_netstr_tests.rs"]
mod tests;
