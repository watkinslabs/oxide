use super::*;

/// Process-global stack; AF_INET ops take a `&'static` via `stack()`.
static STACK: NetStack = NetStack::new();

/// Cached lo iface id + Arc<LoopbackDev> after `init()`. None before.
static LO: Spinlock<Option<(NetIfaceId, Arc<LoopbackDev>)>, SockLockClass>
    = Spinlock::new(None);

/// Register the loopback netdev, install the 127.0.0.0/8 route.
/// Idempotent.
/// # SAFETY: caller is the boot path post-allocator-up; no other
/// CPU has yet executed AF_INET syscalls.
/// # C: O(1)
pub unsafe fn init() {
    let mut g = LO.lock();
    if g.is_some() { return; }
    let (id, lo) = STACK.register_loopback();
    *g = Some((id, lo));
    crate::register_timers(); // net self-registers its periodic timers
}

/// `&'static` ref to the global stack; lookups miss until `init()`.
/// # C: O(1)
pub fn stack() -> &'static NetStack { &STACK }

/// Drain lo's xmit queue back through deliver_rx; synchronous on
/// every UDP send + after deliver_rx (so ICMP echo replies the
/// path itself xmit'd land). Replaces a real soft-IRQ NET_RX.
/// # C: O(N pending)
pub fn drain_loopback() {
    let g = LO.lock();
    if let Some((id, lo)) = g.as_ref() {
        STACK.drain_loopback(*id, lo);
    }
}

/// AF_INET ephemeral-port allocator; rolls over within 49152..=65535.
static EPHEM_NEXT: core::sync::atomic::AtomicU16
    = core::sync::atomic::AtomicU16::new(49152);

/// Allocate an unused ephemeral src port + bind it under
/// `Ipv4Addr::ANY` so reply datagrams can be received.
/// # C: O(N tries)
pub fn alloc_ephemeral_port() -> Result<u16, NetError> {
    use core::sync::atomic::Ordering;
    for _ in 0..(65535 - 49152) {
        let p = EPHEM_NEXT.fetch_add(1, Ordering::Relaxed);
        let p = if p < 49152 { 49152 } else if p == 0 { 49152 } else { p };
        if STACK.bind_udp(Ipv4Addr::ANY, p).is_ok() {
            return Ok(p);
        }
    }
    Err(NetError::Eaddrinuse)
}

/// AF_INET6 ephemeral-port allocator. Binds under `Ipv6Addr::ANY` in
/// the v6 UDP map so reply datagrams to a v6 client reach its recv
/// queue (the v4 `alloc_ephemeral_port` would bind in the wrong map
/// and replies via `deliver_rx_ipv6` would miss).
/// # C: O(N tries)
pub fn alloc_ephemeral_port6() -> Result<u16, NetError> {
    use core::sync::atomic::Ordering;
    for _ in 0..(65535 - 49152) {
        let p = EPHEM_NEXT.fetch_add(1, Ordering::Relaxed);
        let p = if p < 49152 { 49152 } else if p == 0 { 49152 } else { p };
        if STACK.bind_udp6(crate::Ipv6Addr::ANY, p).is_ok() {
            return Ok(p);
        }
    }
    Err(NetError::Eaddrinuse)
}

/// Per-AF_INET-socket variant.
