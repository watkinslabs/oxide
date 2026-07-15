use super::*;

/// Bind a raw IPv4 socket while excluding device changes and close. # C: O(N)
pub(crate) fn bind_raw4(sock: &InetSocket, ip: Ipv4Addr) -> Option<Result<(), NetError>> {
    let _lifecycle = sock.local_port.lock();
    bind_raw4_locked(sock, ip)
}

fn bind_raw4_locked(sock: &InetSocket, ip: Ipv4Addr) -> Option<Result<(), NetError>> {
    use core::sync::atomic::Ordering;
    let kind = sock.kind.lock();
    let SockKind::Raw4(endpoint) = &*kind else { return None };
    if sock.released.load(Ordering::Acquire) { return Some(Err(NetError::Einval)); }
    let iface = match bound_iface(sock) { Ok(iface) => iface, Err(error) => return Some(Err(error)) };
    Some(endpoint.bind_checked(ip, iface))
}

/// Bind a raw IPv6 socket while excluding device changes and close. # C: O(N)
pub(crate) fn bind_raw6(sock: &InetSocket, ip: crate::Ipv6Addr, scope_id: u32)
    -> Option<Result<(), NetError>>
{
    let _lifecycle = sock.local_port.lock();
    bind_raw6_locked(sock, ip, scope_id)
}

fn bind_raw6_locked(sock: &InetSocket, ip: crate::Ipv6Addr, scope_id: u32)
    -> Option<Result<(), NetError>>
{
    use core::sync::atomic::Ordering;
    let kind = sock.kind.lock();
    let SockKind::Raw6(endpoint) = &*kind else { return None };
    if sock.released.load(Ordering::Acquire) { return Some(Err(NetError::Einval)); }
    let iface = match scoped_iface(sock, ip, scope_id) {
        Ok(iface) => iface, Err(error) => return Some(Err(error)),
    };
    Some(endpoint.bind_checked(crate::raw6::Raw6Address::new(ip, scope_id), iface))
}

fn scoped_iface(sock: &InetSocket, dst: crate::Ipv6Addr, scope_id: u32)
    -> Result<Option<NetIfaceId>, NetError>
{
    if scope_id == 0 { return crate::sock_mcast::bound_iface6(sock, dst); }
    let iface = NetIfaceId::from_raw(scope_id);
    if stack().ifaces.lookup_in_ns(iface, sock.net_ns()).is_none() { return Err(NetError::Enodev); }
    let bound = sock.opts.bound_ifindex.load(core::sync::atomic::Ordering::Acquire);
    if bound != 0 && bound != scope_id { return Err(NetError::Enodev); }
    Ok(Some(iface))
}

#[cfg(test)]
enum TryRawBind { Contended, NotRaw, Complete }

#[cfg(test)]
fn try_bind_raw4(sock: &InetSocket, ip: Ipv4Addr) -> Result<TryRawBind, NetError> {
    let Some(_lifecycle) = sock.local_port.try_lock() else { return Ok(TryRawBind::Contended) };
    match bind_raw4_locked(sock, ip) {
        Some(result) => result.map(|()| TryRawBind::Complete), None => Ok(TryRawBind::NotRaw),
    }
}

#[cfg(test)]
fn try_bind_raw6(sock: &InetSocket, ip: crate::Ipv6Addr, scope_id: u32)
    -> Result<TryRawBind, NetError>
{
    let Some(_lifecycle) = sock.local_port.try_lock() else { return Ok(TryRawBind::Contended) };
    match bind_raw6_locked(sock, ip, scope_id) {
        Some(result) => result.map(|()| TryRawBind::Complete), None => Ok(TryRawBind::NotRaw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;
    use std::sync::mpsc;

    fn interfaces() -> (NetIfaceId, NetIfaceId) {
        let stack = crate::global_stack();
        let (first, _) = stack.register_loopback();
        let (second, _) = stack.register_loopback();
        (first, second)
    }

    fn staged_change(sock: Arc<InetSocket>, iface: Option<NetIfaceId>)
        -> (mpsc::Receiver<()>, mpsc::Sender<()>, std::thread::JoinHandle<Result<(), NetError>>)
    {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let handle = std::thread::spawn(move || sock.set_bound_iface_staged(iface, || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        }));
        (entered_rx, release_tx, handle)
    }

    #[test]
    fn raw4_bind_serializes_with_bind_to_device() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let (first, second) = interfaces();
        let sock = Arc::new(InetSocket::new_raw4(crate::addr::IpProto::Icmp as u8));
        sock.set_bound_iface(Some(first)).unwrap();
        let endpoint = match &*sock.kind.lock() { SockKind::Raw4(endpoint) => endpoint.clone(), _ => unreachable!() };

        for next in [Some(second), None] {
            let (entered, release, setter) = staged_change(sock.clone(), next);
            entered.recv().unwrap();
            assert!(matches!(try_bind_raw4(&sock, Ipv4Addr::ANY), Ok(TryRawBind::Contended)));
            release.send(()).unwrap();
            setter.join().unwrap().unwrap();
            assert_eq!(bind_raw4(&sock, Ipv4Addr::ANY).unwrap(), Ok(()));
            assert_eq!(endpoint.snapshot().bound_iface, next);
            assert_eq!(sock.opts.bound_ifindex.load(Ordering::Acquire), next.map(NetIfaceId::raw).unwrap_or(0));
        }
        drop(sock);
        assert!(crate::global_stack().unregister_iface(first));
        assert!(crate::global_stack().unregister_iface(second));
    }

    #[test]
    fn raw6_bind_serializes_with_bind_to_device() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let (first, second) = interfaces();
        let sock = Arc::new(InetSocket::new_raw6(crate::addr::IpProto::Icmpv6 as u8));
        sock.set_bound_iface(Some(first)).unwrap();
        let endpoint = match &*sock.kind.lock() { SockKind::Raw6(endpoint) => endpoint.clone(), _ => unreachable!() };

        for next in [Some(second), None] {
            let (entered, release, setter) = staged_change(sock.clone(), next);
            entered.recv().unwrap();
            assert!(matches!(try_bind_raw6(&sock, crate::Ipv6Addr::ANY, 0), Ok(TryRawBind::Contended)));
            release.send(()).unwrap();
            setter.join().unwrap().unwrap();
            assert_eq!(bind_raw6(&sock, crate::Ipv6Addr::ANY, 0).unwrap(), Ok(()));
            assert_eq!(endpoint.snapshot().bound_iface, next);
            assert_eq!(sock.opts.bound_ifindex.load(Ordering::Acquire), next.map(NetIfaceId::raw).unwrap_or(0));
        }
        drop(sock);
        assert!(crate::global_stack().unregister_iface(first));
        assert!(crate::global_stack().unregister_iface(second));
    }
}
