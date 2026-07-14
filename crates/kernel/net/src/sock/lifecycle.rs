use super::*;

impl InetSocket {
    /// Record the latest positive Linux receive errno until consumed. # C: O(1)
    pub fn set_pending_recv_error(&self, errno: i32) -> bool {
        let kind = self.kind.lock();
        if let SockKind::TcpConn(entry) = &*kind {
            let entry = entry.clone();
            drop(kind);
            return entry.set_error(errno);
        }
        if matches!(*kind, SockKind::Udp) {
            if let Some(q) = self.udp6.lock().as_ref().cloned() {
                drop(kind);
                return q.set_error(errno);
            }
            if let Some(q) = self.udp4.lock().as_ref().cloned() {
                drop(kind);
                return q.set_error(errno);
            }
        }
        let changed = self.error.set(errno);
        if changed {
            #[cfg(target_os = "oxide-kernel")]
            { self.recv_waiters.wake_all(); self.connect_waiters.wake_all(); }
            self.poll_subs.notify_mask(vfs::POLL_ERR);
        }
        changed
    }

    /// Consume the pending positive Linux receive errno, or zero. # C: O(1)
    pub fn take_pending_recv_error(&self) -> i32 { self.error.take() }

    /// Observe whether a receive error is pending without consuming it. # C: O(1)
    pub fn has_pending_recv_error(&self) -> bool { self.error.has() }

    /// Consume the oldest queued Linux extended error. # C: O(1)
    pub fn take_extended_error(&self) -> Option<crate::SocketErrorEntry> { self.error.take_extended() }

    /// Observe queued Linux extended-error state. # C: O(1)
    pub fn has_extended_error(&self) -> bool { self.error.has_extended() }

    /// Apply SO_BINDTODEVICE atomically with bind and close. # C: O(N_port)
    pub fn set_bound_iface(&self, iface: Option<NetIfaceId>) -> Result<(), NetError> {
        use core::sync::atomic::Ordering;
        let _lifecycle = self.local_port.lock();
        if self.released.load(Ordering::Acquire) { return Err(NetError::Einval); }
        if let Some(endpoint) = self.udp4.lock().as_ref() {
            stack().rebind_udp_endpoint_iface(endpoint, iface)?;
        }
        if let Some(endpoint) = self.udp6.lock().as_ref() {
            stack().rebind_udp6_endpoint_iface(endpoint, iface)?;
        }
        if let Some(bind) = self.tcp_bind.lock().as_ref() {
            stack().tcp_rebind_iface(bind, iface)?;
        }
        match &*self.kind.lock() {
            SockKind::Raw4(endpoint) => endpoint.set_bound_iface(iface)?,
            SockKind::Raw6(endpoint) => endpoint.set_bound_iface(iface),
            _ => {}
        }
        self.opts.bound_ifindex.store(iface.map(|id| id.raw()).unwrap_or(0), Ordering::Release);
        Ok(())
    }

    /// Ensure a local port is bound, allocating one endpoint if needed. # C: O(N)
    pub fn ensure_bound(&self) -> Result<u16, NetError> {
        use core::sync::atomic::Ordering;
        let mut local_port = self.local_port.lock();
        if self.released.load(Ordering::Acquire) { return Err(NetError::Einval); }
        if let Some(port) = *local_port { return Ok(port); }
        let net_ns = self.net_ns.load(Ordering::Acquire);
        let iface = stack().bound_iface_in(net_ns, self.opts.bound_ifindex.load(Ordering::Acquire))?;
        let (port, endpoint) = alloc_ephemeral_udp4(
            net_ns, Ipv4Addr::ANY, self.error.clone(), iface,
            self.opts.reuseaddr.clone(), self.opts.reuseport.clone(),
            self.opts.ip_mtu_discover.clone(), self.owner_uid,
            self.peer.clone(), self.bpf_filter.clone(), self.mcast.clone(),
        ).map_err(|error| if error == NetError::Eaddrinuse { NetError::Eagain } else { error })?;
        endpoint.register_poll_subs(&self.poll_subs);
        *self.udp4.lock() = Some(endpoint);
        *local_port = Some(port);
        Ok(port)
    }
}

#[cfg(test)]
mod tests {
    use super::InetSocket;
    use alloc::sync::Arc;
    use alloc::vec;
    use syscall::errno::Errno;

    #[test]
    fn pending_recv_error_overwrites_with_latest_positive_errno() {
        let sock = InetSocket::new_udp();
        assert_eq!(sock.take_pending_recv_error(), 0);
        assert!(!sock.set_pending_recv_error(0));
        assert!(!sock.set_pending_recv_error(-5));
        assert!(sock.set_pending_recv_error(Errno::Econnrefused as i32));
        assert!(sock.set_pending_recv_error(Errno::Econnreset as i32));
        assert_eq!(sock.take_pending_recv_error(), Errno::Econnreset as i32);
        assert_eq!(sock.take_pending_recv_error(), 0);
    }

    #[test]
    fn udp_send_consumes_pending_error_before_other_work() {
        let sock = InetSocket::new_udp();
        sock.set_pending_recv_error(Errno::Econnrefused as i32);
        assert_eq!(
            crate::sock::socket_sendto(&sock, crate::Ipv4Addr::LOOPBACK, 9, &[]),
            Err(crate::NetError::Econnrefused),
        );
        assert!(!sock.has_pending_recv_error());
    }

    #[test]
    fn udp_receive_reports_pending_error_before_queued_datagram() {
        let sock = InetSocket::new_udp();
        let endpoint = Arc::new(crate::UdpRxQueue::new(crate::Ipv4Addr::ANY, 41_234));
        assert!(endpoint.enqueue((
            crate::Ipv4Addr::LOOPBACK, 53, crate::Ipv4Addr::LOOPBACK,
            crate::NetIfaceId::from_raw(1), 64, vec![1, 2, 3],
        )));
        *sock.udp4.lock() = Some(endpoint);
        sock.set_pending_recv_error(Errno::Econnrefused as i32);
        assert_eq!(
            crate::sock_io::recvfrom_opts(&sock, 8, crate::sock_io::RecvOptions::default()),
            Err(crate::NetError::Econnrefused),
        );
        assert_eq!(
            crate::sock_io::recvfrom_opts(&sock, 8, crate::sock_io::RecvOptions::default())
                .unwrap().payload,
            vec![1, 2, 3],
        );
    }
}
