use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketMembershipRequest {
    pub ifindex: u32,
    pub kind: u16,
    pub address: crate::PacketLinkAddress,
}

#[derive(Clone, Copy)]
struct PacketMembership {
    request: PacketMembershipRequest,
    generation: u64,
    count: usize,
}

pub(crate) struct PacketMemberships {
    rows: Spinlock<Vec<PacketMembership>, SockLockClass>,
}

impl PacketMemberships {
    pub(crate) const fn new() -> Self { Self { rows: Spinlock::new(Vec::new()) } }

    fn change(&self, socket: &InetSocket, request: PacketMembershipRequest, add: bool)
        -> crate::NetResult<()> {
        self.change_staged(socket, request, add, || {})
    }

    fn change_staged<F: FnOnce()>(&self, socket: &InetSocket,
        request: PacketMembershipRequest, add: bool, admitted: F)
        -> crate::NetResult<()> {
        if !matches!(*socket.kind.lock(), SockKind::Packet { .. }) {
            return Err(crate::NetError::Enoprotoopt);
        }
        let stack = stack();
        let rtnl = stack.rtnl_lock();
        if socket.released.load(core::sync::atomic::Ordering::Acquire) {
            return Err(crate::NetError::Einval);
        }
        admitted();
        if add { self.add(&rtnl, socket.net_ns(), request) }
        else { self.drop_one(&rtnl, socket.net_ns(), request); Ok(()) }
    }

    fn add(&self, rtnl: &crate::RtnlGuard<'_>, net_ns: u64,
           request: PacketMembershipRequest) -> crate::NetResult<()> {
        let iface = NetIfaceId::from_raw(request.ifindex);
        let (generation, address_len) = rtnl.stack().ifaces
            .packet_filter_generation(rtnl, iface, net_ns)?;
        if request.address.len > address_len { return Err(crate::NetError::Einval); }
        if matches!(request.kind,
            crate::uapi::PACKET_MR_MULTICAST | crate::uapi::PACKET_MR_UNICAST)
            && request.address.len != address_len
        {
            return Err(crate::NetError::Einval);
        }
        let mut rows = self.rows.lock();
        if let Some(row) = rows.iter_mut().find(|row| row.request == request
            && row.generation == generation)
        {
            row.count = row.count.saturating_add(1);
            return Ok(());
        }
        rtnl.stack().ifaces.update_packet_filter(rtnl, iface, net_ns, generation,
            request.kind, request.address, true)?;
        rows.push(PacketMembership { request, generation, count: 1 });
        Ok(())
    }

    fn drop_one(&self, rtnl: &crate::RtnlGuard<'_>, net_ns: u64,
                request: PacketMembershipRequest) {
        let mut rows = self.rows.lock();
        let Some(index) = rows.iter().position(|row| row.request == request) else { return };
        if rows[index].count > 1 { rows[index].count -= 1; return; }
        let row = rows.remove(index);
        let _ = rtnl.stack().ifaces.update_packet_filter(rtnl,
            NetIfaceId::from_raw(row.request.ifindex), net_ns, row.generation,
            row.request.kind, row.request.address, false);
    }

    fn release(&self, socket: &InetSocket) {
        if !matches!(*socket.kind.lock(), SockKind::Packet { .. }) { return; }
        let stack = stack();
        let rtnl = stack.rtnl_lock();
        let rows = core::mem::take(&mut *self.rows.lock());
        for row in rows {
            let _ = stack.ifaces.update_packet_filter(&rtnl,
                NetIfaceId::from_raw(row.request.ifindex), socket.net_ns(), row.generation,
                row.request.kind, row.request.address, false);
        }
    }

    fn detach(&self, iface: NetIfaceId, generation: u64) {
        self.rows.lock().retain(|row| row.request.ifindex != iface.raw()
            || row.generation != generation);
    }

    #[cfg(test)]
    /// Number of unique socket-local memberships. # C: O(1)
    pub(crate) fn count(&self) -> usize { self.rows.lock().len() }
}

impl InetSocket {
    /// Add or drop one Linux packet membership under RTNL. # C: O(N memberships)
    pub fn change_packet_membership(self: &Arc<Self>, request: PacketMembershipRequest, add: bool)
        -> crate::NetResult<()> {
        register_packet(self);
        self.packet_memberships.change(self, request, add)
    }

    /// Flush packet memberships during final file release. # C: O(N memberships)
    pub(crate) fn release_packet_memberships(&self) {
        self.packet_memberships.release(self);
    }

    #[cfg(test)]
    /// Run one membership transition with a deterministic admission hook. # C: O(N memberships)
    pub(crate) fn change_packet_membership_staged<F: FnOnce()>(self: &Arc<Self>,
        request: PacketMembershipRequest, add: bool, admitted: F)
        -> crate::NetResult<()> {
        register_packet(self);
        self.packet_memberships.change_staged(self, request, add, admitted)
    }
}

/// Detach packet memberships and binds from one unregistering device generation. # C: O(N sockets)
pub(crate) fn detach_packet_device(rtnl: &crate::RtnlGuard<'_>,
                                   teardown: &crate::netdev::IfaceTeardown) {
    let net_ns = teardown.net_ns();
    let iface = teardown.iface();
    let generation = teardown.generation();
    let sockets = {
        // `lock_bh`: `deliver` takes this registry from the packet-RX SOFTIRQ,
        // so a plain acquisition in process context lets that softirq land on
        // this CPU mid-hold and spin forever (`06§3.1`, `skizm.md` Step 3e-bh).
        // Safe to release here — the guard is scoped to this block, so
        // `local_bh_enable`'s inline drain holds no other lock.
        let mut registry = PACKET_REGISTRY.lock_bh::<sched::bh::SchedBh>();
        registry.retain(|weak| weak.upgrade().is_some());
        registry.iter().filter_map(alloc::sync::Weak::upgrade).collect::<Vec<_>>()
    };
    for socket in sockets {
        if socket.net_ns() != net_ns { continue; }
        socket.packet_memberships.detach(iface, generation);
        let kind = socket.kind.lock();
        let SockKind::Packet { ifindex, .. } = &*kind else { continue };
        if ifindex.load(core::sync::atomic::Ordering::Acquire) == iface.raw() {
            ifindex.store(u32::MAX, core::sync::atomic::Ordering::Release);
            drop(kind);
            socket.error.set(syscall::errno::Errno::Enetdown as i32);
            socket.poll_subs.notify();
            #[cfg(target_os = "oxide-kernel")]
            socket.recv_waiters.wake_all();
        }
    }
    let _ = rtnl.stack().ifaces.reset_packet_filter(rtnl, teardown);
}
