use super::*;

impl NetStack {
    /// Remove per-interface network state and unregister the netdev.
    /// # C: O(N routes + N addrs + N groups + N ndp)
    pub fn unregister_iface(&self, iface: NetIfaceId) -> bool {
        self.unregister_iface_in(0, iface)
    }

    fn drain_teardown(&self, teardown: &crate::netdev::IfaceTeardown) {
        teardown.wait();
        teardown.mcast_report.retire();
        teardown.dev.retire_namespace();
    }

    fn remove_teardown_state(&self, _rtnl: &crate::RtnlGuard<'_>,
                             iface: NetIfaceId, teardown: &crate::netdev::IfaceTeardown) {
        let net_ns = teardown.net_ns();
        let _ = crate::iface_addr::remove_iface(net_ns, iface);
        self.v6_addrs.lock().remove(&iface);
        self.ndp.lock().retain(|(id, _), _| *id != iface);
        self.v6_mcast.lock().remove(&iface);
        self.v4_mcast.lock().remove(&iface);
        self.routes.retain_in(net_ns, |e| e.iface != iface);
        self.routes6.retain_in(net_ns, |e| e.iface != iface);
    }

    fn claim_iface_in(&self, net_ns: u64, iface: NetIfaceId)
        -> Option<crate::netdev::IfaceTeardown>
    {
        loop {
            let claim = {
                let _rtnl = self.rtnl_lock();
                self.ifaces.claim_unregister_in(iface, Some(net_ns))
            };
            match claim {
                crate::netdev::IfaceUnregisterClaim::Gone => return None,
                crate::netdev::IfaceUnregisterClaim::WaitComplete(gate) => {
                    crate::netdev::IfaceRegistry::wait_unregister(&gate);
                }
                crate::netdev::IfaceUnregisterClaim::WaitResume(gate) => {
                    crate::netdev::IfaceRegistry::wait_resume(&gate);
                }
                crate::netdev::IfaceUnregisterClaim::Teardown(teardown) => return Some(teardown),
            }
        }
    }

    /// Remove one namespace-owned interface and all attached network state. # C: O(N)
    pub fn unregister_iface_in(&self, net_ns: u64, iface: NetIfaceId) -> bool {
        let Some(teardown) = self.claim_iface_in(net_ns, iface) else { return false };
        self.drain_teardown(&teardown);
        let rtnl = self.rtnl_lock();
        self.remove_teardown_state(&rtnl, iface, &teardown);
        self.ifaces.finish_destroy(&teardown).is_some()
    }

    /// Synchronously remove an interface from its canonical namespace generation. # C: O(N)
    /// # Ctx: schedulable process context; caller holds no ingress lease for `iface`.
    pub fn unregister_iface_current(&self, iface: NetIfaceId) -> bool {
        loop {
            let claim = {
                let _rtnl = self.rtnl_lock();
                self.ifaces.claim_unregister(iface)
            };
            match claim {
                crate::netdev::IfaceUnregisterClaim::Gone => return true,
                crate::netdev::IfaceUnregisterClaim::WaitComplete(gate) => {
                    crate::netdev::IfaceRegistry::wait_unregister(&gate);
                }
                crate::netdev::IfaceUnregisterClaim::WaitResume(gate) => {
                    crate::netdev::IfaceRegistry::wait_resume(&gate);
                }
                crate::netdev::IfaceUnregisterClaim::Teardown(teardown) => {
                    self.drain_teardown(&teardown);
                    let rtnl = self.rtnl_lock();
                    self.remove_teardown_state(&rtnl, iface, &teardown);
                    if self.ifaces.finish_destroy(&teardown).is_some() { return true; }
                }
            }
        }
    }

    /// Apply Linux namespace-exit disposition after quiescing interface state. # C: O(N)
    pub fn teardown_iface_in(&self, net_ns: u64, iface: NetIfaceId) -> bool {
        let Some(teardown) = self.claim_iface_in(net_ns, iface) else { return false };
        self.drain_teardown(&teardown);
        match teardown.dev.namespace_drop_action() {
            crate::NamespaceDropAction::Destroy => {
                let rtnl = self.rtnl_lock();
                self.remove_teardown_state(&rtnl, iface, &teardown);
                self.ifaces.finish_destroy(&teardown).is_some()
            }
            crate::NamespaceDropAction::MoveToInitial => {
                let next = {
                    let rtnl = self.rtnl_lock();
                    self.remove_teardown_state(&rtnl, iface, &teardown);
                    let Some(next) = self.ifaces.begin_move_to_initial(&teardown) else { return false };
                    next
                };
                teardown.dev.resume_namespace();
                let _rtnl = self.rtnl_lock();
                self.ifaces.finish_move_to_initial(&teardown, &next)
            }
        }
    }
}
