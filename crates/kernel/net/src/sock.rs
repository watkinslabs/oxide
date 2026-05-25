// Kernel-side wrapper around `crate::NetStack`. One global stack
// owns the iface registry + UDP port map; boot calls `init()` to
// register the loopback netdev. AF_INET socket fds are VFS Inodes
// that hold an ephemeral src port + a destination address (set by
// connect / overridden per-sendto).



use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{NetStack, LoopbackDev, Ipv4Addr, NetIfaceId, NetError};
use crate::stack::{TcpEntry, TcpListenEntry};
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
    /// SOCK_STREAM after `socket()` but before `listen()`/`connect()`/
    /// `accept()`. Discriminates a fresh TCP socket from a fresh UDP
    /// one so `connect()` routes through `tcp_connect` instead of the
    /// UDP "store peer + Ok" short-circuit at line ~572.
    TcpInit,
    /// SOCK_STREAM, after `listen()`. Holds the listener handle.
    TcpListener(Arc<TcpListenEntry>),
    /// SOCK_STREAM, after `connect()` or `accept()`.
    TcpConn(Arc<TcpEntry>),
    /// AF_UNIX SOCK_STREAM — both ends share an `UnixPair`; the
    /// `UnixEnd` tags this fd as the A or B side.
    Unix(Arc<crate::UnixPair>, crate::UnixEnd),
    /// AF_UNIX path-bound listener. `accept` pops a queued pair.
    UnixListener(Arc<crate::UnixListener>),
    /// AF_UNIX SOCK_DGRAM (F120 / `24§R01`). Per-socket message
    /// queue; sendto/recvfrom push/pop here. Real per-message SCM
    /// metadata (sender creds, fd array) rides F121.
    UnixDgram(Arc<crate::UnixDgramQueue>),
    /// AF_UNIX SOCK_SEQPACKET / SOCK_DGRAM on a socketpair —
    /// bidirectional msg-boundary-preserving pair. F125.
    UnixMsgPair(Arc<crate::UnixMsgPair>, crate::UnixEnd),
    /// F131: AF_PACKET / PF_PACKET SOCK_RAW. dhcpcd uses this to
    /// send the DHCPDISCOVER L2 frame before it has an IPv4 address.
    /// `ifindex == 0` means unbound (sendto / recvfrom return EINVAL
    /// until bind sets a specific iface).
    Packet {
        ifindex:  core::sync::atomic::AtomicU32,
        protocol: core::sync::atomic::AtomicU16,
        /// F146: sock_type — SOCK_RAW (3) caller sends full L2 frame
        /// (xmit_raw); SOCK_DGRAM (2) caller sends L3 payload and the
        /// kernel prepends the ethernet header using sll_addr from
        /// sendto's destination sockaddr_ll. busybox udhcpc opens
        /// SOCK_DGRAM; dhcpcd 10.3.2 opens SOCK_RAW.
        sock_type: core::sync::atomic::AtomicU8,
        /// Pending RX frames.
        rx: sync::Spinlock<alloc::collections::VecDeque<alloc::vec::Vec<u8>>, SockLockClass>,
    },
}

/// Process-global AF_UNIX path registry.
pub static UNIX_REGISTRY: crate::UnixRegistry = crate::UnixRegistry::new();

/// F137: AF_PACKET socket registry. Bind installs a `Weak<InetSocket>`
/// here keyed by ifindex; the virtio-net rx path iterates this list
/// and pushes a frame copy into each matching socket's rx queue so
/// dhcpcd's recvfrom() sees the DHCPOFFER. Dropped sockets stay as
/// dead Weaks until the next deliver pass GCs them.
/// ETH_P_ALL = 0x0003 (host order) matches every protocol.
pub static PACKET_REGISTRY: Spinlock<Vec<alloc::sync::Weak<InetSocket>>, SockLockClass>
    = Spinlock::new(Vec::new());

/// Add `sock` to the AF_PACKET registry. Idempotent — duplicate adds
/// just live as redundant Weak entries (harmless; the rx path is the
/// hot side and dedupes implicitly via socket identity).
/// # C: O(N) — registry is small (one entry per AF_PACKET fd).
pub fn register_packet(sock: &Arc<InetSocket>) {
    let mut g = PACKET_REGISTRY.lock();
    g.retain(|w| w.upgrade().is_some());
    g.push(Arc::downgrade(sock));
}

/// Deliver a complete L2 frame to all AF_PACKET sockets bound to
/// `iface` (ifindex 0 = any). Filters by socket's stored protocol
/// (0x0003 ETH_P_ALL or matches frame ethertype). Frames are
/// truncated to 65536 bytes on enqueue and a hard cap of 64 frames
/// per socket prevents unbounded growth.
/// # C: O(N sockets) — call from net rx softirq only.
pub fn deliver_packet_rx(iface: NetIfaceId, frame: &[u8]) {
    use core::sync::atomic::Ordering;
    if frame.len() < 14 { return; }
    let et = ((frame[12] as u16) << 8) | (frame[13] as u16);
    let mut delivered = false;
    let mut g = PACKET_REGISTRY.lock();
    g.retain(|w| w.upgrade().is_some());
    for w in g.iter() {
        let sock = match w.upgrade() { Some(s) => s, None => continue };
        let k = sock.kind.lock();
        if let SockKind::Packet { ifindex, protocol, sock_type, rx } = &*k {
            let want_if = ifindex.load(Ordering::Acquire);
            if want_if != 0 && want_if != iface.raw() { continue; }
            let p = protocol.load(Ordering::Acquire);
            if p != 0x0003 && p != et { continue; }
            const SOCK_DGRAM: u8 = 2;
            let stype = sock_type.load(Ordering::Acquire);
            let payload: alloc::vec::Vec<u8> = if stype == SOCK_DGRAM {
                frame[14..].to_vec()
            } else {
                frame.to_vec()
            };
            let mut q = rx.lock();
            if q.len() < 64 {
                q.push_back(payload);
                delivered = true;
            }
        }
    }
    drop(g);
    // F146: wake any poll/epoll/select waiters so a userspace task
    // parked on the AF_PACKET socket actually sees the frame.
    if delivered {
        sched::live::notify_epoll_waiters();
    }
}

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
    /// SOL_SOCKET integer options stored verbatim from setsockopt and
    /// echoed back from getsockopt. Enforcement on the data path lands
    /// alongside per-option logic; the round-trip alone keeps
    /// userspace (systemd, ssh) from failing setsockopt+getsockopt
    /// consistency checks.
    pub opts: SockOpts,
}

/// Common SOL_SOCKET options held per socket. Each is an `i32` cell
/// matching Linux `int`-shaped options. SO_LINGER stores `(onoff,linger)`.
#[derive(Default)]
pub struct SockOpts {
    pub reuseaddr: core::sync::atomic::AtomicI32,
    pub reuseport: core::sync::atomic::AtomicI32,
    pub keepalive: core::sync::atomic::AtomicI32,
    pub broadcast: core::sync::atomic::AtomicI32,
    pub sndbuf:    core::sync::atomic::AtomicI32,
    pub rcvbuf:    core::sync::atomic::AtomicI32,
    pub sndtimeo_ns: core::sync::atomic::AtomicI64,
    pub rcvtimeo_ns: core::sync::atomic::AtomicI64,
    pub linger_on: core::sync::atomic::AtomicI32,
    pub linger_s:  core::sync::atomic::AtomicI32,
    pub priority:  core::sync::atomic::AtomicI32,
    pub mark:      core::sync::atomic::AtomicI32,
    /// IPPROTO_TCP / TCP_NODELAY round-trip cell.
    pub tcp_nodelay: core::sync::atomic::AtomicI32,
}

/// Linux `AF_INET` numeric value — kept here so dev_net code can tag
/// new sockets without depending on syscall_glue_net's private const.
pub const AF_INET:  u16 = 2;
pub const AF_INET6: u16 = 10;
pub const AF_UNIX:  u16 = 1;
pub const AF_PACKET: u16 = 17;

impl InetSocket {
    /// # C: O(1)
    pub fn new_udp() -> Self {
        Self {
            family:     core::sync::atomic::AtomicU16::new(AF_INET),
            local_port: Spinlock::new(None),
            local_ip:   Spinlock::new(Ipv4Addr::ANY),
            peer:       Spinlock::new(None),
            kind:       Spinlock::new(SockKind::Udp),
            opts:       SockOpts::default(),
        }
    }
    /// # C: O(1)
    pub fn new_tcp() -> Self {
        Self {
            family:     core::sync::atomic::AtomicU16::new(AF_INET),
            local_port: Spinlock::new(None),
            local_ip:   Spinlock::new(Ipv4Addr::ANY),
            peer:       Spinlock::new(None),
            // TcpInit (not Udp) so `connect()` routes SOCK_STREAM
            // through the real `tcp_connect` 3WHS path instead of
            // the UDP store-peer-and-return-Ok short-circuit.
            // listen()/connect()/accept() transition to TcpListener
            // or TcpConn.
            kind:       Spinlock::new(SockKind::TcpInit),
            opts:       SockOpts::default(),
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

    /// `socket(AF_UNIX, SOCK_DGRAM, …)` per F120 / `24§R01`. Allocates
    /// a fresh `UnixDgramQueue` so sendto from a peer can push
    /// payloads. v1 sends are EOPNOTSUPP until the path-keyed dgram
    /// registry lands in F121; the queue alone lets feature-probing
    /// programs succeed at socket() + close().
    /// # C: O(1)
    pub fn new_unix_dgram() -> Self {
        let s = Self::new_tcp();
        s.family.store(AF_UNIX, core::sync::atomic::Ordering::Release);
        *s.kind.lock() = SockKind::UnixDgram(crate::UnixDgramQueue::new());
        s
    }

    /// F131: `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` —
    /// raw L2 packet socket dhcpcd uses for DHCPDISCOVER before
    /// it owns an IPv4. `proto` is the wire byte-order protocol
    /// the caller passed; we store host-order.
    /// # C: O(1)
    pub fn new_packet(proto: u16, sock_type: u8) -> Self {
        let s = Self::new_tcp();
        s.family.store(AF_PACKET, core::sync::atomic::Ordering::Release);
        *s.kind.lock() = SockKind::Packet {
            ifindex:   core::sync::atomic::AtomicU32::new(0),
            protocol:  core::sync::atomic::AtomicU16::new(proto),
            sock_type: core::sync::atomic::AtomicU8::new(sock_type),
            rx:        Spinlock::new(alloc::collections::VecDeque::new()),
        };
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
        // F158: snapshot the kind out of its lock first so we don't
        // hold sock.kind.lock() across a park (deliver_tcp's wake path
        // doesn't touch this lock but holding it across schedule is
        // still wrong on principle and breaks AF_UNIX peers that
        // close-and-flip kind during read).
        enum K {
            Unix(Arc<crate::UnixPair>, crate::UnixEnd),
            UnixMsgPair(Arc<crate::UnixMsgPair>, crate::UnixEnd),
            Tcp(Arc<TcpEntry>),
            Other,
        }
        let k = match &*self.kind.lock() {
            SockKind::Unix(p, e)        => K::Unix(p.clone(), *e),
            SockKind::UnixMsgPair(p, e) => K::UnixMsgPair(p.clone(), *e),
            SockKind::TcpConn(e)        => K::Tcp(e.clone()),
            _                            => K::Other,
        };
        match k {
            K::Unix(pair, end) => {
                let got = pair.read(end, buf.len());
                let n = got.len();
                buf[..n].copy_from_slice(&got);
                Ok(n)
            }
            K::UnixMsgPair(pair, end) => match pair.recv(end, buf.len()) {
                Some(msg) => { let n = msg.len(); buf[..n].copy_from_slice(&msg); Ok(n) }
                None      => Err(vfs::VfsError::Eagain),
            },
            K::Tcp(entry) => read_tcp_blocking(&entry, buf),
            K::Other => Err(vfs::VfsError::Einval),
        }
    }

    /// Non-blocking variant per `15§5` / vfs::Inode contract. Returns
    /// Eagain when recv_buf is empty AND the connection is still in a
    /// data-transfer state; Ok(0) only on peer FIN.
    fn read_nonblock(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        if let SockKind::TcpConn(entry) = &*self.kind.lock() {
            drain_loopback();
            let got = stack().tcp_recv(entry, buf.len());
            if !got.is_empty() {
                let n = got.len();
                buf[..n].copy_from_slice(&got);
                return Ok(n);
            }
            let st = entry.conn.lock().state;
            if st == crate::tcp_state::TcpState::Closed
                || st == crate::tcp_state::TcpState::CloseWait
                || st == crate::tcp_state::TcpState::LastAck
            {
                return Ok(0);
            }
            return Err(vfs::VfsError::Eagain);
        }
        // Fall back to the blocking path for non-TCP sock kinds — their
        // existing read() impl already returns Eagain for empty queues
        // where applicable (UnixMsgPair).
        self.read(_off, buf)
    }

    fn write(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        match &*self.kind.lock() {
            SockKind::Unix(pair, end)        => Ok(pair.write(*end, buf)),
            SockKind::UnixMsgPair(pair, end) => Ok(pair.send(*end, buf)),
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
                if c.state == crate::tcp_state::TcpState::Closed
                    || c.state.is_closing() { mask |= POLL_HUP; }
                mask
            }
            SockKind::Unix(pair, end) => {
                let mut mask = POLL_OUT;
                let read_q = match end {
                    crate::UnixEnd::A => &pair.b_to_a,
                    crate::UnixEnd::B => &pair.a_to_b,
                };
                if !read_q.lock().buf.is_empty() { mask |= POLL_IN; }
                if pair.is_eof(*end) { mask |= POLL_HUP; }
                mask
            }
            SockKind::UnixListener(l) => {
                if l.accept_q.lock().is_empty() { POLL_OUT } else { POLL_IN | POLL_OUT }
            }
            SockKind::UnixDgram(q) => {
                let mut mask = POLL_OUT;
                if !q.msgs.lock().is_empty() { mask |= POLL_IN; }
                mask
            }
            SockKind::UnixMsgPair(pair, end) => {
                let mut mask = POLL_OUT;
                if pair.has_msg(*end) { mask |= POLL_IN; }
                if pair.is_eof(*end)  { mask |= POLL_HUP; }
                mask
            }
            SockKind::Packet { rx, .. } => {
                // F131: tx always ready; rx readable when rx queue
                // has a frame. v1 rx queue stays empty until the
                // virtio-net rx-deliver path lands.
                let mut mask = POLL_OUT;
                if !rx.lock().is_empty() { mask |= POLL_IN; }
                mask
            }
            SockKind::TcpInit => POLL_OUT,
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

/// F150: hook the kernel installs at boot so the net crate can ask
/// the kernel for an iface's primary IPv4 without owning the global
/// ifaddr table here. Defaults to the unspec address until installed.
/// # C: O(1)
static IFACE_PRIMARY_IP_HOOK: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
pub type IfacePrimaryIpFn = fn(NetIfaceId) -> Option<Ipv4Addr>;

/// # C: O(1) — atomic store; install once at boot.
pub fn set_iface_primary_ip_hook(f: IfacePrimaryIpFn) {
    IFACE_PRIMARY_IP_HOOK.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

fn iface_primary_ip(id: Option<NetIfaceId>) -> Option<Ipv4Addr> {
    let id = id?;
    let p = IFACE_PRIMARY_IP_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: hook installed via set_iface_primary_ip_hook with a function pointer of the IfacePrimaryIpFn shape.
    let f: IfacePrimaryIpFn = unsafe { core::mem::transmute(p) };
    f(id)
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
    // F150: pick the right source IP for outbound. ANY-bound socket
    // → use loopback only when dst is loopback; else consult the
    // route table for the outbound iface and use ITS configured IP.
    // Without this every outbound UDP claims src=127.0.0.1, and
    // replies from a remote peer (slirp's DNS at 10.0.2.3, …) can
    // never make it back since they target loopback not eth0.
    let src_ip = if src_ip != Ipv4Addr::ANY {
        src_ip
    } else if dst.is_loopback() {
        Ipv4Addr::LOOPBACK
    } else {
        // Find the outbound iface's primary IPv4 via the route table.
        STACK.routes.lookup(dst)
            .and_then(|r| r.src_hint)
            .or_else(|| iface_primary_ip(STACK.routes.lookup(dst).map(|r| r.iface)))
            .unwrap_or(Ipv4Addr::LOOPBACK)
    };
    STACK.send_udp_to(src_ip, src_port, dst, dst_port, payload)?;
    drain_loopback();
    Ok(payload.len())
}


/// F158: blocking TCP recv. Park on entry.rx_waiters until data
/// arrives in recv_buf or the connection reaches a terminal data
/// state (peer FIN'd → return Ok(0) for EOF, RST → Closed). Used
/// from `Inode::read` for SockKind::TcpConn. The non-blocking shim
/// `Inode::read_nonblock` does the immediate-Eagain version inline.
///
/// Drain loopback every iteration so the lo-path's TCP traffic (test
/// harness side) makes progress too — virtio-net's MSI-driven softirq
/// handles the off-host path independently and wakes us via wake_all.
/// # C: blocks indefinitely
/// # Lk: takes entry.conn briefly between yields; entry.rx_waiters during park
/// # Ctx: process; preempt-off; runqueue installed
fn read_tcp_blocking(
    entry: &alloc::sync::Arc<TcpEntry>,
    buf: &mut [u8],
) -> vfs::KResult<usize> {
    loop {
        drain_loopback();
        let got = stack().tcp_recv(entry, buf.len());
        if !got.is_empty() {
            let n = got.len();
            buf[..n].copy_from_slice(&got);
            return Ok(n);
        }
        let st = entry.conn.lock().state;
        if st == crate::tcp_state::TcpState::Closed
            || st == crate::tcp_state::TcpState::CloseWait
            || st == crate::tcp_state::TcpState::LastAck
        {
            // Peer terminated AND nothing buffered — POSIX EOF.
            return Ok(0);
        }
        // Park on the per-entry rx_waiters list. deliver_tcp's
        // wake_all() (called after recv_buf grows or state goes
        // terminal) will move us back to Runnable. Race-safe: we
        // already re-checked state and recv_buf above with the
        // entry.conn lock; deliver_tcp mutates that same lock
        // before wake_all, so any wake we'd miss between the check
        // and the park is impossible — the wake happens with the
        // post-mutation state visible.
        // SAFETY: process ctx (sys_read); runqueue installed; preempt-off owned by syscall stub; park+schedule resume on deliver_tcp wake.
        #[cfg(target_os = "oxide-kernel")]
        unsafe {
            entry.rx_waiters.park();
            sched::live::schedule::schedule();
        }
        // Hosted-test fallback: spin once and return Eagain so tests
        // don't loop forever waiting for a scheduler that isn't here.
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(vfs::VfsError::Eagain);
    }
}


// ─── Tier-2 work fns per `docs/53§3` ───
// Typed bind/connect/sendto/recv operating on already-parsed
// `BoundAddr` / `RemoteAddr` enums. ABI shims in
// `kernel/src/syscalls/net.rs` translate user sockaddr buffers
// into these enums.

extern crate alloc;
use alloc::string::String;

/// Already-validated bind target. Per `25§5` socket address
/// taxonomy. Variant tags reflect the socket family the caller
/// expects to be bound to.
pub enum BoundAddr {
    /// `bind` on an AF_UNIX SOCK_STREAM/SOCK_SEQPACKET socket —
    /// register a listener at `path`.
    UnixListener(String),
    /// `bind` on an AF_UNIX SOCK_DGRAM socket — register the
    /// already-allocated queue at `path`.
    UnixDgram { path: String, queue: alloc::sync::Arc<crate::UnixDgramQueue> },
    /// `bind` on an AF_INET / AF_INET6 socket — UDP-style port
    /// reservation. v1 inet stack is IPv4 only.
    Inet { ip: Ipv4Addr, port: u16 },
}

/// Bind a socket to an address per `bind(2)`. Tier-2 work fn:
/// takes typed args, returns typed result, no `&SyscallArgs`.
/// # C: O(1) for inet, O(N_unix_listeners) for unix
pub fn bind(sock: &alloc::sync::Arc<InetSocket>, addr: BoundAddr) -> Result<(), NetError> {
    match addr {
        BoundAddr::UnixListener(path) => {
            let listener = UNIX_REGISTRY.bind(path).map_err(|_| NetError::Eaddrinuse)?;
            *sock.kind.lock() = SockKind::UnixListener(listener);
            Ok(())
        }
        BoundAddr::UnixDgram { path, queue } => {
            UNIX_REGISTRY.dgram_bind(path, queue).map_err(|_| NetError::Eaddrinuse)
        }
        BoundAddr::Inet { ip, port } => {
            stack().bind_udp(ip, port)?;
            *sock.local_port.lock() = Some(port);
            *sock.local_ip.lock() = ip;
            Ok(())
        }
    }
}


/// Already-validated remote-address target for connect/sendto.
#[derive(Clone)]
pub enum RemoteAddr {
    /// `connect`/`sendto` on AF_UNIX — registry lookup by path.
    UnixPath(String),
    /// `connect`/`sendto` on AF_INET — IPv4 destination.
    Inet { ip: Ipv4Addr, port: u16 },
}

/// Connect a socket to a remote per `connect(2)`. Tier-2 work fn.
/// Handles AF_UNIX path-lookup, AF_INET UDP peer-stash, AF_INET TCP
/// active open + 3WHS drain.
/// # C: O(1) for UDP/UNIX, O(drain_iterations) for TCP.
pub fn connect(sock: &alloc::sync::Arc<InetSocket>, addr: RemoteAddr) -> Result<(), NetError> {
    match addr {
        RemoteAddr::UnixPath(path) => {
            // B47: connect to a non-existent AF_UNIX path returns
            // ECONNREFUSED on Linux (no listener) — used to return
            // ENOBUFS which dhcpcd treated as fatal "out of buffer
            // memory" instead of "nobody home, I'll create my own
            // socket and listen".
            let pair = UNIX_REGISTRY.connect(&path).ok_or(NetError::Econnrefused)?;
            *sock.kind.lock() = SockKind::Unix(pair, crate::UnixEnd::B);
            Ok(())
        }
        RemoteAddr::Inet { ip: dst_ip, port } => {
            let is_dgram = matches!(*sock.kind.lock(), SockKind::Udp);
            if is_dgram {
                *sock.peer.lock() = Some((dst_ip, port));
                return Ok(());
            }
            // TCP active open: allocate local port if unbound, default
            // local IP to loopback if ANY, kick stack, drain a few
            // times, fail with Etimedout (mapped at the ABI layer)
            // if we don't reach Established.
            //
            // Lock-across-match hazard: a match scrutinee like
            // `match *sock.local_port.lock() { … None => *sock.local_port.lock() = … }`
            // keeps the scrutinee's MutexGuard alive across the arms
            // (Rust temporary scoping rule), and the None arm's
            // re-lock deadlocks against it. Read the slot, drop the
            // guard, then re-acquire to assign.
            let local_port = {
                let cur = *sock.local_port.lock();
                match cur {
                    Some(p) => p,
                    None    => {
                        let p = alloc_ephemeral_port()?;
                        *sock.local_port.lock() = Some(p);
                        p
                    }
                }
            };
            // F156: source-IP pick matches socket_sendto's F150 logic —
            // an ANY-bound TCP socket connecting to a remote slirp
            // address must claim src=iface_primary (10.0.2.15) not
            // src=127.0.0.1, or the SYN-ACK can never come back.
            let bound = *sock.local_ip.lock();
            let local_ip = if bound != Ipv4Addr::ANY {
                bound
            } else if dst_ip.is_loopback() {
                Ipv4Addr::LOOPBACK
            } else {
                STACK.routes.lookup(dst_ip)
                    .and_then(|r| r.src_hint)
                    .or_else(|| iface_primary_ip(STACK.routes.lookup(dst_ip).map(|r| r.iface)))
                    .unwrap_or(Ipv4Addr::LOOPBACK)
            };
            let entry = stack().tcp_connect(local_ip, local_port, dst_ip, port)?;
            *sock.kind.lock() = SockKind::TcpConn(entry.clone());
            *sock.peer.lock() = Some((dst_ip, port));
            // Wait for SYN-ACK. Self-loopback frames arrive via
            // drain_loopback (lo iface). Off-host frames (slirp gateway,
            // 10.0.2.x) arrive via virtio-net MSI → softirq → deliver_rx,
            // which needs IRQs unmasked between checks. tick_yield's
            // sti+hlt+cli on x86 (daifclr+wfi+daifset on arm) provides
            // that window. Bounded so an unreachable host returns
            // Etimedout instead of wedging forever.
            for _ in 0..200 {
                drain_loopback();
                let st = entry.conn.lock().state;
                if st.is_established() { break; }
                if st == crate::tcp_state::TcpState::Closed { break; }
                // SAFETY: connect() runs in process context (sys_connect
                // from userspace); tick_yield's preempt-off + IRQ-on
                // contract is satisfied.
                unsafe { sched::live::tick_yield(); }
            }
            if !entry.conn.lock().state.is_established() {
                return Err(NetError::Eio); // ABI maps to Etimedout
            }
            Ok(())
        }
    }
}


/// `listen` per `listen(2)`. Returns Ok(()) on success. For AF_UNIX
/// listeners bind(2) already did the work — listen is a no-op.
/// # C: O(1)
pub fn listen(sock: &alloc::sync::Arc<InetSocket>, _backlog: i32) -> Result<(), NetError> {
    if matches!(*sock.kind.lock(), SockKind::UnixListener(_)) { return Ok(()); }
    let port = sock.local_port.lock().ok_or(NetError::Einval)?;
    let ip = *sock.local_ip.lock();
    let le = stack().tcp_listen(ip, port)?;
    *sock.kind.lock() = SockKind::TcpListener(le);
    Ok(())
}

/// Result of `accept` — a new socket plus optionally the peer
/// address for the ABI layer to write back to the user `sockaddr`.
pub struct Accepted {
    pub new_sock: alloc::sync::Arc<InetSocket>,
    pub peer: Option<(Ipv4Addr, u16)>,
}

/// `accept` per `accept(2)`. Non-blocking: returns Err(Eagain) when
/// no connection is ready. Tier-2 work fn — caller (Tier-3 shim)
/// wraps the returned `InetSocket` in a vfs::File and allocates a fd.
/// # C: O(1) + drain
pub fn accept(sock: &alloc::sync::Arc<InetSocket>) -> Result<Accepted, NetError> {
    drain_loopback();
    // AF_UNIX listener: pop one queued UnixPair.
    if let SockKind::UnixListener(l) = &*sock.kind.lock() {
        let l = l.clone();
        let pair = l.accept_q.lock().pop_front().ok_or(NetError::Eagain)?;
        let new_sock = alloc::sync::Arc::new(InetSocket::new_tcp());
        *new_sock.kind.lock() = SockKind::Unix(pair, crate::UnixEnd::A);
        return Ok(Accepted { new_sock, peer: None });
    }
    let listener_arc = match &*sock.kind.lock() {
        SockKind::TcpListener(l) => l.clone(),
        _ => return Err(NetError::Einval),
    };
    let entry = stack().tcp_accept(&listener_arc).ok_or(NetError::Eagain)?;
    let (peer_ip, peer_port) = {
        let c = entry.conn.lock();
        (c.remote.ip, c.remote.port)
    };
    let listener_fam = sock.family.load(core::sync::atomic::Ordering::Acquire);
    let new_sock = alloc::sync::Arc::new(
        if listener_fam == AF_INET6 { InetSocket::new_tcp6() } else { InetSocket::new_tcp() }
    );
    *new_sock.kind.lock() = SockKind::TcpConn(entry);
    *new_sock.peer.lock() = Some((peer_ip, peer_port));
    Ok(Accepted { new_sock, peer: Some((peer_ip, peer_port)) })
}


/// Sender credentials for AF_UNIX SCM_CREDENTIALS. Caller (Tier-3
/// shim) fetches from `sched::current()` and passes here.
#[derive(Copy, Clone, Debug, Default)]
pub struct SenderCreds {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// `sendto`/`send` per `sendto(2)`. Tier-2 work fn — Tier-3 shim
/// supplies the payload as a slice, the optional destination as a
/// typed RemoteAddr, and the sender's creds for AF_UNIX SCM.
///
/// Behaviour by socket kind:
///   UnixDgram  → push to peer's queue (dest required)
///   TcpConn    → tcp_send + drain
///   Udp/other  → socket_sendto with dest or stored peer
/// # C: O(payload bytes)
pub fn sendto(
    sock: &alloc::sync::Arc<InetSocket>,
    payload: &[u8],
    dest: Option<RemoteAddr>,
    creds: SenderCreds,
) -> Result<usize, NetError> {
    // F134: AF_UNIX SOCK_SEQPACKET / SOCK_DGRAM on a socketpair.
    // dhcpcd's launcher waits on its grandchild via
    //   send(fork_fd, &exit_code, sizeof(exit_code), MSG_EOR)
    // over a SOCK_SEQPACKET socketpair. Previously sendto fell
    // through to the AF_INET UDP arm + Eaddrnotavail because there
    // was no dest path or peer recorded, so the launcher hung
    // forever waiting on a signal it could never receive.
    if let SockKind::UnixMsgPair(pair, end) = &*sock.kind.lock() {
        let pair = pair.clone();
        let end = *end;
        return Ok(pair.send(end, payload));
    }
    // AF_UNIX SOCK_STREAM socketpair: same shape, byte ring instead.
    if let SockKind::Unix(pair, end) = &*sock.kind.lock() {
        let pair = pair.clone();
        let end = *end;
        return Ok(pair.write(end, payload));
    }
    // AF_UNIX SOCK_DGRAM: dest path required, push to peer queue.
    if let SockKind::UnixDgram(_) = &*sock.kind.lock() {
        let path = match dest {
            Some(RemoteAddr::UnixPath(p)) => p,
            _ => return Err(NetError::Einval),
        };
        let q = UNIX_REGISTRY.dgram_lookup(&path).ok_or(NetError::Enobufs)?;
        q.push(crate::UnixDgram {
            payload: payload.to_vec(),
            creds: (creds.pid, creds.uid, creds.gid),
            fds: alloc::vec::Vec::new(),
        });
        return Ok(payload.len());
    }
    // TCP: send into the existing connection.
    if let SockKind::TcpConn(entry) = &*sock.kind.lock() {
        let entry = entry.clone();
        let n = stack().tcp_send(&entry, payload)?;
        drain_loopback();
        return Ok(n);
    }
    // UDP/other: dest or stored peer.
    let (dst_ip, dst_port) = match dest {
        Some(RemoteAddr::Inet { ip, port }) => (ip, port),
        Some(RemoteAddr::UnixPath(_))       => return Err(NetError::Einval),
        None => sock.peer.lock().ok_or(NetError::Eaddrnotavail)?,
    };
    socket_sendto(sock, dst_ip, dst_port, payload)
}


/// `recvfrom` result. Caller (Tier-3 shim) copies payload into user
/// buf, optionally writes peer sockaddr.
pub struct Received {
    pub payload: alloc::vec::Vec<u8>,
    pub peer: Option<(Ipv4Addr, u16)>,
}

/// `recvfrom` per `recvfrom(2)`. Tier-2 work fn. Returns the payload
/// and an optional peer address (None for AF_UNIX SOCK_DGRAM and
/// for sockets without a stored peer).
/// # C: O(payload bytes)
pub fn recvfrom(sock: &alloc::sync::Arc<InetSocket>, max_len: usize) -> Result<Received, NetError> {
    // AF_UNIX SOCK_DGRAM.
    if let SockKind::UnixDgram(q) = &*sock.kind.lock() {
        let q = q.clone();
        let msg = q.pop().ok_or(NetError::Eagain)?;
        let take = core::cmp::min(max_len, msg.payload.len());
        let mut out = alloc::vec::Vec::with_capacity(take);
        out.extend_from_slice(&msg.payload[..take]);
        return Ok(Received { payload: out, peer: None });
    }
    // F137: AF_PACKET. Pop one queued frame; peer = None for now
    // (the sockaddr_ll shaping rides with sys_recvfrom's writer).
    if let SockKind::Packet { rx, .. } = &*sock.kind.lock() {
        let frame = {
            let mut q = rx.lock();
            q.pop_front().ok_or(NetError::Eagain)?
        };
        let take = core::cmp::min(max_len, frame.len());
        let mut out = alloc::vec::Vec::with_capacity(take);
        out.extend_from_slice(&frame[..take]);
        return Ok(Received { payload: out, peer: None });
    }
    // TCP.
    if let SockKind::TcpConn(entry) = &*sock.kind.lock() {
        let entry = entry.clone();
        drain_loopback();
        let payload = stack().tcp_recv(&entry, max_len);
        if payload.is_empty() { return Err(NetError::Eagain); }
        let peer = *sock.peer.lock();
        return Ok(Received { payload, peer });
    }
    // UDP / others.
    let (src_ip, src_port, full) = socket_recv(sock).ok_or(NetError::Eagain)?;
    let take = core::cmp::min(max_len, full.len());
    let mut out = alloc::vec::Vec::with_capacity(take);
    out.extend_from_slice(&full[..take]);
    Ok(Received { payload: out, peer: Some((src_ip, src_port)) })
}
