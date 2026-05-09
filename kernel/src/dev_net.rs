// Kernel-side wrapper around `net::NetStack`. One global stack
// owns the iface registry + UDP port map; boot calls `init()` to
// register the loopback netdev. AF_INET socket fds are VFS Inodes
// that hold an ephemeral src port + a destination address (set by
// connect / overridden per-sendto).

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;

use net::{NetStack, LoopbackDev, Ipv4Addr, NetIfaceId, NetError};
use net::stack::{TcpEntry, TcpListenEntry};
use sync::{Spinlock, Socket as SockLockClass};

/// Process-global stack. Initialised by `init()`; subsequent
/// AF_INET socket ops take a `&'static` view through `stack()`.
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
}

/// `&'static` reference to the global stack. Safe to call after
/// `init()`; before init lookups will all miss.
/// # C: O(1)
pub fn stack() -> &'static NetStack { &STACK }

/// Drain loopback's xmit queue back through deliver_rx. v1 calls
/// this synchronously after every UDP send + after deliver_rx
/// (for ICMP echo replies that `deliver_rx` itself xmit'd).
/// Replaces a real soft-IRQ NET_RX scheduler.
/// # C: O(N pending)
pub fn drain_loopback() {
    let g = LO.lock();
    if let Some((id, lo)) = g.as_ref() {
        STACK.drain_loopback(*id, lo);
    }
}

/// Snapshot of the AF_INET ephemeral-port allocator. Counter
/// rolls over within the dynamic-port range (49152..=65535).
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

/// Per-AF_INET-socket variant.
pub enum SockKind {
    /// SOCK_DGRAM — bound port managed via NetStack's UDP map.
    Udp,
    /// SOCK_STREAM, after `listen()`. Holds the listener handle.
    TcpListener(Arc<TcpListenEntry>),
    /// SOCK_STREAM, after `connect()` or `accept()`.
    TcpConn(Arc<TcpEntry>),
    /// AF_UNIX SOCK_STREAM — both ends share an `UnixPair`; the
    /// `UnixEnd` tags this fd as the A or B side.
    Unix(Arc<net::UnixPair>, net::UnixEnd),
    /// AF_UNIX path-bound listener. `accept` pops a queued pair.
    UnixListener(Arc<net::UnixListener>),
}

/// Process-global AF_UNIX path registry.
pub static UNIX_REGISTRY: net::UnixRegistry = net::UnixRegistry::new();

/// Per-AF_INET / AF_INET6 socket VFS state — one Inode per socket fd.
///
/// `family` records the address family the userspace `socket(2)` call
/// asked for: AF_INET (2) or AF_INET6 (10). The `local_ip` / `peer`
/// slots stay V4-shaped for v1 because the transport layer is V4-only
/// on the wire; on AF_INET6 sockets the V4 slot mirrors the IPv4
/// equivalent of an IPv6 address (V4-mapped ::ffff:x.x.x.x or the
/// loopback `127.0.0.1` for `::1`). Real V6 transport lands in
/// phase 18b. The `family` tag drives which sockaddr shape the
/// syscall path reads + writes.
pub struct InetSocket {
    pub family:     core::sync::atomic::AtomicU16,
    pub local_port: Spinlock<Option<u16>, SockLockClass>,
    pub local_ip:   Spinlock<Ipv4Addr, SockLockClass>,
    pub peer:       Spinlock<Option<(Ipv4Addr, u16)>, SockLockClass>,
    pub kind:       Spinlock<SockKind, SockLockClass>,
}

/// Linux `AF_INET` numeric value — kept here so dev_net code can tag
/// new sockets without depending on syscall_glue_net's private const.
pub const AF_INET:  u16 = 2;
pub const AF_INET6: u16 = 10;
pub const AF_UNIX:  u16 = 1;

impl InetSocket {
    /// # C: O(1)
    pub fn new_udp() -> Self {
        Self {
            family:     core::sync::atomic::AtomicU16::new(AF_INET),
            local_port: Spinlock::new(None),
            local_ip:   Spinlock::new(Ipv4Addr::ANY),
            peer:       Spinlock::new(None),
            kind:       Spinlock::new(SockKind::Udp),
        }
    }
    /// # C: O(1)
    pub fn new_tcp() -> Self {
        Self {
            family:     core::sync::atomic::AtomicU16::new(AF_INET),
            local_port: Spinlock::new(None),
            local_ip:   Spinlock::new(Ipv4Addr::ANY),
            peer:       Spinlock::new(None),
            // Placeholder — set by listen() / connect() / accept().
            kind:       Spinlock::new(SockKind::Udp),
        }
    }
    /// `socket(AF_INET6, SOCK_DGRAM, …)` — same V4 transport substrate
    /// for v1; `family = AF_INET6` flips the syscall ABI to the
    /// 28-byte sockaddr_in6 shape on bind/connect/sendto/recv*.
    /// # C: O(1)
    pub fn new_udp6() -> Self {
        let s = Self::new_udp();
        s.family.store(AF_INET6, core::sync::atomic::Ordering::Release);
        s
    }
    /// `socket(AF_INET6, SOCK_STREAM, …)`. # C: O(1)
    pub fn new_tcp6() -> Self {
        let s = Self::new_tcp();
        s.family.store(AF_INET6, core::sync::atomic::Ordering::Release);
        s
    }

    /// `socket(AF_UNIX, SOCK_STREAM, …)`. F114: InetSocket shell
    /// tagged AF_UNIX with no kind set yet — bind/connect/accept
    /// transition it to `SockKind::Unix(pair, end)`. Without this
    /// `socket(AF_UNIX, …)` returned EAFNOSUPPORT, breaking the
    /// standard 4-step AF_UNIX flow.
    /// # C: O(1)
    pub fn new_unix() -> Self {
        let s = Self::new_tcp();
        s.family.store(AF_UNIX, core::sync::atomic::Ordering::Release);
        s
    }

    /// Ensure a local port is bound (auto-bind to an ephemeral
    /// port when sendto is called before bind).
    /// # C: O(1) if already bound, else O(N) ephemeral scan
    pub fn ensure_bound(&self) -> Result<u16, NetError> {
        let mut g = self.local_port.lock();
        if let Some(p) = *g { return Ok(p); }
        let p = alloc_ephemeral_port()?;
        *g = Some(p);
        Ok(p)
    }
}

impl Default for InetSocket { fn default() -> Self { Self::new_udp() } }

impl vfs::Inode for InetSocket {
    fn ino(&self) -> vfs::Ino {
        // High-bits tag so socket inode numbers don't collide
        // with fs inode space.
        0x534F_434B_0000_0000u64 | (self as *const _ as u64 & 0xFFFF_FFFF) as vfs::Ino
    }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }

    fn read(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        match &*self.kind.lock() {
            SockKind::Unix(pair, end) => {
                let got = pair.read(*end, buf.len());
                let n = got.len();
                buf[..n].copy_from_slice(&got);
                Ok(n)
            }
            SockKind::TcpConn(entry) => {
                drain_loopback();
                let got = stack().tcp_recv(entry, buf.len());
                let n = got.len();
                buf[..n].copy_from_slice(&got);
                Ok(n)
            }
            _ => Err(vfs::VfsError::Einval),
        }
    }

    fn write(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        match &*self.kind.lock() {
            SockKind::Unix(pair, end) => Ok(pair.write(*end, buf)),
            SockKind::TcpConn(entry) => {
                let n = stack().tcp_send(entry, buf).map_err(|_| vfs::VfsError::Eio)?;
                drain_loopback();
                Ok(n)
            }
            _ => Err(vfs::VfsError::Einval),
        }
    }

    fn poll(&self) -> u32 {
        use vfs::{POLL_IN, POLL_OUT, POLL_HUP};
        match &*self.kind.lock() {
            SockKind::Udp => {
                let mut mask = POLL_OUT;
                if let Some(p) = *self.local_port.lock() {
                    drain_loopback();
                    if stack().recv_udp(p).is_some() {
                        // Re-queue; recv_udp consumed it.
                        // To peek without consuming we'd need an
                        // explicit API; v1 just signals readable
                        // when something was recently visible.
                        mask |= POLL_IN;
                    }
                }
                mask
            }
            SockKind::TcpListener(l) => {
                if l.accept_q.lock().is_empty() { POLL_OUT } else { POLL_IN | POLL_OUT }
            }
            SockKind::TcpConn(entry) => {
                drain_loopback();
                let c = entry.conn.lock();
                let mut mask = POLL_OUT;
                if !c.recv_buf.is_empty() { mask |= POLL_IN; }
                if c.state == net::tcp_state::TcpState::Closed
                    || c.state.is_closing() { mask |= POLL_HUP; }
                mask
            }
            SockKind::Unix(pair, end) => {
                let mut mask = POLL_OUT;
                let read_q = match end {
                    net::UnixEnd::A => &pair.b_to_a,
                    net::UnixEnd::B => &pair.a_to_b,
                };
                if !read_q.lock().buf.is_empty() { mask |= POLL_IN; }
                if pair.is_eof(*end) { mask |= POLL_HUP; }
                mask
            }
            SockKind::UnixListener(l) => {
                if l.accept_q.lock().is_empty() { POLL_OUT } else { POLL_IN | POLL_OUT }
            }
        }
    }
}

/// AF_INET dgram-socket recv — pops one queued datagram for the
/// bound port. Returns (src_ip, src_port, payload) or None.
/// Also drains lo first so any in-flight loopback packets land
/// in the rx queue before we look.
/// # C: O(1)
pub fn socket_recv(sock: &InetSocket) -> Option<(Ipv4Addr, u16, Vec<u8>)> {
    drain_loopback();
    let port = (*sock.local_port.lock())?;
    STACK.recv_udp(port)
}

/// AF_INET dgram-socket send — auto-binds an ephemeral local
/// port if not already bound, builds + xmits the datagram,
/// drains lo so an immediate recv on the same socket sees it.
/// # C: O(1)
pub fn socket_sendto(sock: &InetSocket, dst: Ipv4Addr, dst_port: u16, payload: &[u8])
    -> Result<usize, NetError>
{
    let src_port = sock.ensure_bound()?;
    let src_ip   = *sock.local_ip.lock();
    let src_ip   = if src_ip == Ipv4Addr::ANY { Ipv4Addr::LOOPBACK } else { src_ip };
    STACK.send_udp_to(src_ip, src_port, dst, dst_port, payload)?;
    drain_loopback();
    Ok(payload.len())
}
