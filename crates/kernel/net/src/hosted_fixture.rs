//! Canonical ownership for hosted tests that exercise the initial network domain.

use alloc::vec::Vec;
use std::sync::{Mutex, MutexGuard};

use crate::iface_addr::Ipv4IfaceAddr;

static INITIAL_NET_DOMAIN: Mutex<()> = Mutex::new(());

/// Exclusive hosted ownership of namespace-0 address and process hook state.
pub struct InitNetDomain {
    _guard: MutexGuard<'static, ()>,
    ipv4_rows: Vec<Ipv4IfaceAddr>,
    notifier: Option<crate::control_event::Notifier>,
    nf_hook: Option<crate::netfilter_hook::NfHookFn>,
}

impl InitNetDomain {
    /// Install a scoped control-event consumer. # C: O(1)
    pub fn set_notifier(&self, notifier: crate::control_event::Notifier) {
        let _ = crate::control_event::swap_notifier(Some(notifier));
    }

    /// Install a scoped netfilter callback. # C: O(1)
    pub fn set_nf_hook(&self, hook: crate::netfilter_hook::NfHookFn) {
        let _ = crate::netfilter_hook::swap_nf_hook(Some(hook));
    }
}

impl Drop for InitNetDomain {
    fn drop(&mut self) {
        crate::iface_addr::restore_ns(0, core::mem::take(&mut self.ipv4_rows));
        let _ = crate::netfilter_hook::swap_nf_hook(self.nf_hook);
        let _ = crate::control_event::swap_notifier(self.notifier);
    }
}

/// Acquire the canonical hosted initial-network ownership domain. # C: O(wait + N rows)
pub fn init_net_domain() -> InitNetDomain {
    let guard = INITIAL_NET_DOMAIN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    InitNetDomain {
        _guard: guard,
        ipv4_rows: crate::iface_addr::snapshot_ns(0),
        notifier: crate::control_event::swap_notifier(None),
        nf_hook: crate::netfilter_hook::swap_nf_hook(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ipv4Addr, NetIfaceId};

    fn drop_all(_hook: u32, _packet: &[u8], _family: u8) -> u32 { 0 }
    fn ignore_event(_event: &crate::control_event::ControlEvent) {}

    #[test]
    fn domain_restores_initial_namespace_rows_and_hooks() {
        let before = crate::iface_addr::snapshot_ns(0);
        let expected_notifier;
        let expected_nf_hook;
        {
            let domain = init_net_domain();
            expected_notifier = domain.notifier.map(|notifier| notifier as usize);
            expected_nf_hook = domain.nf_hook.map(|hook| hook as usize);
            crate::iface_addr::set_prefix(0, NetIfaceId(4_294_967_000),
                Ipv4Addr::new(192, 0, 2, 1), 24, 0);
            domain.set_notifier(ignore_event);
            domain.set_nf_hook(drop_all);
            assert_eq!(crate::netfilter_hook::nf_hook_eval(0, &[], 2), 0);
        }
        assert_eq!(crate::iface_addr::snapshot_ns(0), before);
        let restored = init_net_domain();
        assert_eq!(restored.notifier.map(|notifier| notifier as usize), expected_notifier);
        assert_eq!(restored.nf_hook.map(|hook| hook as usize), expected_nf_hook);
    }

    #[test]
    fn independent_threads_cannot_overlap_initial_domain_ownership() {
        let domain = init_net_domain();
        let (attempt_tx, attempt_rx) = std::sync::mpsc::channel();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let contender = std::thread::spawn(move || {
            attempt_tx.send(()).unwrap();
            let _domain = init_net_domain();
            acquired_tx.send(()).unwrap();
        });
        attempt_rx.recv().unwrap();
        assert!(acquired_rx.try_recv().is_err());
        drop(domain);
        acquired_rx.recv().unwrap();
        contender.join().unwrap();
    }
}
