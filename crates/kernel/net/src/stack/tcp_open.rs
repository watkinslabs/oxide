use super::*;

impl NetStack {
    /// Hosted transport-only ingress adapter; wire RX supplies full L3 separately. # C: O(packet)
    #[cfg(test)]
    pub(crate) fn deliver_tcp(&self, net_ns: u64, iface: NetIfaceId,
        src_ip: IpAddr, dst_ip: IpAddr, seg: &[u8]) -> NetResult<()> {
        self.deliver_tcp_packet(net_ns, iface, src_ip, dst_ip, seg, seg)
    }

    /// Open an active TCP connection and publish its half-open entry. # C: O(log N + xmit)
    pub fn tcp_connect(&self, local_ip: Ipv4Addr, local_port: u16,
                       remote_ip: Ipv4Addr, remote_port: u16)
        -> NetResult<Arc<TcpEntry>>
    {
        self.tcp_connect_ip(
            IpAddr::V4(local_ip), local_port, IpAddr::V4(remote_ip), remote_port)
    }

    /// Address-family-aware active open. # C: O(log N + xmit)
    pub fn tcp_connect_ip(&self, local_ip: IpAddr, local_port: u16,
                          remote_ip: IpAddr, remote_port: u16)
        -> NetResult<Arc<TcpEntry>>
    {
        self.tcp_connect_ip_bound(local_ip, local_port, remote_ip, remote_port, None,
            Arc::new(crate::SocketError::new()))
    }

    /// Remove a connected TCP entry from the demux table. # C: O(log N)
    pub fn tcp_disconnect_entry(&self, entry: &Arc<TcpEntry>) {
        let key = {
            let c = entry.conn.lock();
            TcpKey {
                local_ip: c.local.ip, local_port: c.local.port,
                remote_ip: c.remote.ip, remote_port: c.remote.port,
            }
        };
        let tables = self.inet_tables(entry.net_ns());
        super::tcp_listener::remove_tcp_entry_exact(&tables, &key, entry);
        if let Some(bind) = entry.bind.as_ref() {
            bind.role.store(TCP_BIND_BOUND, ::core::sync::atomic::Ordering::Release);
        }
    }
}
