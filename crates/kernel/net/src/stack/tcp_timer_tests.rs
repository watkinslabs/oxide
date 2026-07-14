use super::*;

fn time_wait_entry(net_ns: u64, port: u16) -> (TcpKey, Arc<TcpEntry>) {
    let local = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port };
    let remote = Endpoint { ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), port: 80 };
    let bind = Arc::new(TcpBindReservation::new(net_ns, local, None, false, false, 0, false));
    let mut conn = TcpConn::new_client(local, remote, 1);
    conn.state = crate::tcp_state::TcpState::TimeWait;
    let key = TcpKey {
        local_ip: local.ip, local_port: local.port,
        remote_ip: remote.ip, remote_port: remote.port,
    };
    (key, Arc::new(TcpEntry::new_bound_with_error(
        conn, Arc::new(crate::SocketError::new()), Some(bind),
    )))
}

#[test]
fn timer_scans_init_and_skips_namespace_after_final_owner_drop() {
    crate::net_ns::install_final_drop_pending_notifier().unwrap();
    let stack = NetStack::new();
    let owner = network_namespace::allocate(0).unwrap();
    let net_ns = owner.id().as_u64();
    let (init_key, init_entry) = time_wait_entry(0, 40_001);
    let (dead_key, dead_entry) = time_wait_entry(net_ns, 40_002);
    stack.inet_tables(0).tcp_conns.lock().insert(init_key, init_entry.clone());
    stack.inet_tables(net_ns).tcp_conns.lock().insert(dead_key, dead_entry.clone());

    drop(owner);
    stack.tcp_retx_tick(123);

    assert_eq!(init_entry.conn.lock().tw_start_ns, 123, "init namespace uses its immortal owner");
    assert_eq!(dead_entry.conn.lock().tw_start_ns, 0, "dead namespace timer work is skipped");
}
