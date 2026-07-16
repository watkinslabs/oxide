//! Canonical network security hook boundary.
//!
//! Policy is keyed by the concrete network-namespace id.  Callers pass only
//! operation metadata; syscall shims must not duplicate policy decisions.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{Namespace, Spinlock};

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Operation { Create, Bind, Connect, Listen, Accept, Send, Receive, Shutdown,
    NameQuery, SocketPair, Option, Ioctl, Packet }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Verdict { Allow, Deny }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Context { pub namespace: u64, pub family: u16, pub socket_type: u32,
    pub protocol: u32, pub operation: Operation }

pub type Hook = fn(Context) -> Verdict;

struct Entry { hook: Hook, allowed: AtomicU64, denied: AtomicU64 }

static HOOKS: Spinlock<BTreeMap<u64, BTreeMap<Operation, Entry>>, Namespace> =
    Spinlock::new(BTreeMap::new());

pub fn install(namespace: u64, operation: Operation, hook: Hook) -> Option<Hook> {
    let mut all = HOOKS.lock();
    all.entry(namespace).or_default().insert(operation, Entry {
        hook, allowed: AtomicU64::new(0), denied: AtomicU64::new(0),
    }).map(|old| old.hook)
}

pub fn remove(namespace: u64, operation: Operation) -> Option<Hook> {
    let mut all = HOOKS.lock();
    let old = all.get_mut(&namespace)?.remove(&operation).map(|entry| entry.hook);
    if all.get(&namespace).is_some_and(BTreeMap::is_empty) { all.remove(&namespace); }
    old
}

pub fn evaluate(context: Context) -> Verdict {
    let all = HOOKS.lock();
    let Some(entry) = all.get(&context.namespace).and_then(|ops| ops.get(&context.operation))
        else { return Verdict::Allow; };
    let verdict = (entry.hook)(context);
    match verdict { Verdict::Allow => { entry.allowed.fetch_add(1, Ordering::Relaxed); }
        Verdict::Deny => { entry.denied.fetch_add(1, Ordering::Relaxed); } }
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;
    fn deny(ctx: Context) -> Verdict { assert_eq!(ctx.namespace, 7); Verdict::Deny }
    #[test]
    fn policies_are_namespace_and_operation_scoped() {
        let _ = remove(7, Operation::Packet);
        assert_eq!(install(7, Operation::Packet, deny), None);
        let context = Context { namespace: 7, family: 2, socket_type: 2,
            protocol: 17, operation: Operation::Packet };
        assert_eq!(evaluate(context), Verdict::Deny);
        assert_eq!(evaluate(Context { namespace: 8, ..context }), Verdict::Allow);
        assert_eq!(remove(7, Operation::Packet), Some(deny as Hook));
    }
}
