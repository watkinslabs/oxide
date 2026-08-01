use super::*;

use std::sync::{Mutex, MutexGuard};

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn reset() {
    ENDPOINTS.lock().clear();
    PRIMARY_OWNER.store(VSOCK_OWNER_ANY_RAW, Ordering::Release);
    TABLE.reset_for_hosted_test();
}

/// Exclusive hosted ownership of process-global VSOCK state.
#[must_use]
pub struct Domain { _guard: MutexGuard<'static, ()> }

impl Domain {
    /// Restore global state while retaining exclusive ownership. # C: O(global state)
    pub fn reset(&mut self) { reset(); }
}

impl Drop for Domain {
    fn drop(&mut self) { reset(); }
}

/// Reset and own the process-global VSOCK hosted domain. # C: O(global state)
pub fn domain() -> Domain {
    let guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    reset();
    Domain { _guard: guard }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_restores_every_process_global_vsock_fixture() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        reset();
        let owner = VsockOwner::from_raw(0x0d00_0001).expect("nonzero owner");
        assert!(driver_reserve(owner));
        assert!(driver_quiesce(owner));
        let key = ConnKey { owner, local_cid: 3, local_port: 64_001,
            peer_cid: 2, peer_port: 1024 };
        assert!(TABLE.insert(alloc::sync::Arc::new(VsockConn::new(owner, key.local_cid,
            key.local_port, key.peer_cid, key.peer_port, VsockState::Connected))));
        assert!(TABLE.add_listener(Some(owner), 64_002).is_some());
        let binding = TABLE.reserve_bind(Some(owner), Some(64_003)).expect("bind reservation");

        reset();

        assert!(!driver_cancel_reserved(owner));
        assert!(TABLE.find(key).is_none());
        assert!(!TABLE.is_listening(owner, 64_002));
        assert!(!TABLE.release_bind(&binding));
        let ephemeral = TABLE.reserve_bind(None, None).expect("reset ephemeral allocation");
        assert_eq!(ephemeral.port, 1024);
        assert!(TABLE.release_bind(&ephemeral));
    }

    #[test]
    fn unwind_releases_poisoned_domain_and_restores_invisible_endpoint() {
        let owner = VsockOwner::from_raw(0x0d00_0002).expect("nonzero owner");
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _domain = domain();
            assert!(driver_reserve(owner));
            assert!(driver_quiesce(owner));
            assert_eq!(driver_owner(), None, "quiesced endpoint is invisible to live lookup");
            panic!("inject VSOCK hosted-domain unwind");
        }));
        assert!(unwound.is_err());

        let _domain = domain();
        assert!(!driver_cancel_reserved(owner), "RAII drop removes invisible endpoint");
        assert_eq!(driver_owner(), None);
    }

    #[test]
    fn domain_retains_exact_exclusive_lock_until_drop() {
        let owner_domain = domain();
        assert!(matches!(TEST_LOCK.try_lock(), Err(std::sync::TryLockError::WouldBlock)),
            "second domain cannot acquire while owner lives");
        drop(owner_domain);
        let _reacquired = domain();
    }
}
