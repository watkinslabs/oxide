// Canonical local (CID, port) ownership and ephemeral selection.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use super::{Listener, VsockOwner, VsockTable, VsockTransportType};

/// Linux VSOCK's final privileged local port (`LAST_RESERVED_PORT`). # C: O(1)
pub const LAST_RESERVED_PORT: u32 = 1_023;
pub(super) const FIRST_EPHEMERAL_PORT: u32 = LAST_RESERVED_PORT + 1;

/// Exact ownership token for one bound local VSOCK identity. # C: O(1)
pub struct BindReservation {
    pub owner: Option<VsockOwner>,
    pub port: u32,
}

impl VsockTable {
    /// Allocate an ephemeral local port not owned by a bind or listener. # C: O(N endpoints)
    pub fn alloc_port(&self) -> u32 {
        let bindings = self.bindings.lock();
        let listeners = self.listeners.lock();
        loop {
            let port = self.next_ephemeral();
            if !bindings.iter().any(|binding| binding.port == port)
                && !listeners.iter().any(|listener| listener.local_port == port)
            { return port; }
        }
    }

    /// Atomically reserve an explicit or ephemeral local identity. # C: O(N endpoints)
    pub fn reserve_bind(&self, owner: Option<VsockOwner>, port: Option<u32>)
        -> Result<Arc<BindReservation>, crate::NetError>
    {
        let mut bindings = self.bindings.lock();
        let listeners = self.listeners.lock();
        let conflicts = |port: u32| {
            bindings.iter().any(|binding| binding.port == port
                && owners_conflict(binding.owner, owner))
                || listeners.iter().any(|listener| listener.local_port == port
                    && owners_conflict(listener.owner, owner))
        };
        let port = match port {
            Some(port) if conflicts(port) => return Err(crate::NetError::Eaddrinuse),
            Some(port) => port,
            None => loop {
                let candidate = self.next_ephemeral();
                if !conflicts(candidate) { break candidate; }
            },
        };
        let reservation = Arc::new(BindReservation { owner, port });
        bindings.push(reservation.clone());
        Ok(reservation)
    }

    /// Release only the exact bind token, preserving later reuse. # C: O(N bindings)
    pub fn release_bind(&self, reservation: &Arc<BindReservation>) -> bool {
        let mut bindings = self.bindings.lock();
        let Some(pos) = bindings.iter().position(|current| Arc::ptr_eq(current, reservation)) else {
            return false;
        };
        bindings.remove(pos);
        true
    }

    /// Promote only the exact bind token into a listener record. # C: O(N endpoints)
    pub fn promote_bind(&self, reservation: &Arc<BindReservation>) -> Option<Arc<Listener>> {
        self.promote_bind_with_filter(reservation,
            &Arc::new(crate::bpf_filter::SocketFilter::new()))
    }

    /// Promote while sharing the listener socket's filter state. # C: O(N endpoints)
    pub fn promote_bind_with_filter(&self, reservation: &Arc<BindReservation>,
                                    filter: &Arc<crate::bpf_filter::SocketFilter>) -> Option<Arc<Listener>> {
        self.promote_bind_with_filter_and_backlog(reservation, filter,
            VsockTransportType::Stream, crate::sysctl::DEFAULT_SOMAXCONN)
    }

    /// Promote one bind token with its Linux-normalized accept capacity. # C: O(N endpoints)
    pub fn promote_bind_with_filter_and_backlog(&self, reservation: &Arc<BindReservation>,
                                    filter: &Arc<crate::bpf_filter::SocketFilter>,
                                    transport_type: VsockTransportType,
                                    backlog: usize) -> Option<Arc<Listener>> {
        let mut bindings = self.bindings.lock();
        let mut listeners = self.listeners.lock();
        let pos = bindings.iter().position(|current| Arc::ptr_eq(current, reservation))?;
        if listeners.iter().any(|listener| listener.local_port == reservation.port
            && owners_conflict(listener.owner, reservation.owner))
        { return None; }
        bindings.remove(pos);
        let listener = Arc::new(Listener::new(reservation.owner, reservation.port, transport_type,
            filter.clone()));
        listener.backlog_cap.store(backlog, core::sync::atomic::Ordering::Release);
        listeners.push(listener.clone());
        Some(listener)
    }

    fn next_ephemeral(&self) -> u32 {
        let port = self.ephem_next.fetch_add(1, Ordering::Relaxed);
        if port >= FIRST_EPHEMERAL_PORT && port != u32::MAX { return port; }
        self.ephem_next.store(FIRST_EPHEMERAL_PORT + 1, Ordering::Relaxed);
        FIRST_EPHEMERAL_PORT
    }
}

fn owners_conflict(left: Option<VsockOwner>, right: Option<VsockOwner>) -> bool {
    left == right || left.is_none() || right.is_none()
}
