// ifaddrs.h — getifaddrs/freeifaddrs (docs/59§6 G13). Enumerate interface
// addresses via NETLINK_ROUTE: an RTM_GETLINK dump builds the index→(name,
// flags,L2-addr) table and yields one AF_PACKET entry per link; an RTM_GETADDR
// dump yields one entry per assigned IPv4/IPv6 address (ifa_addr + synthesized
// ifa_netmask from the prefix length + ifa_broadaddr). The whole linked list is
// laid out in ONE heap block so freeifaddrs frees it with a single free(head),
// matching glibc. Freestanding only; thin over socket/bind/sendto/recvfrom.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys3, sys6};
use crate::internal::errno::{ret, set};
use crate::internal::nr;
use crate::net::socket::{AF_INET, AF_INET6, SOCK_RAW, SOCK_CLOEXEC};
use alloc::vec::Vec;

const AF_NETLINK: u16 = 16;
const AF_PACKET: u16 = 17;
const NETLINK_ROUTE: usize = 0;

// nlmsghdr types/flags
const RTM_GETLINK: u16 = 18;
const RTM_NEWLINK: u16 = 16;
const RTM_GETADDR: u16 = 22;
const RTM_NEWADDR: u16 = 20;
const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_DUMP: u16 = 0x300; // ROOT|MATCH
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

// rtattr types
const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_BROADCAST: u16 = 4;

const EINVAL: i32 = 22;
const ENOBUFS: i32 = 105;

// glibc struct ifaddrs (56 bytes on LP64).
#[repr(C)]
pub struct Ifaddrs {
    pub ifa_next: *mut Ifaddrs,
    pub ifa_name: *mut u8,
    pub ifa_flags: u32,
    _pad: u32,
    pub ifa_addr: *mut u8,
    pub ifa_netmask: *mut u8,
    pub ifa_ifu: *mut u8, // broadaddr/dstaddr union
    pub ifa_data: *mut u8,
}
const _: () = assert!(core::mem::size_of::<Ifaddrs>() == 56);

#[inline] fn nlalign(n: usize) -> usize { (n + 3) & !3 }

// One parsed link: index, flags, name, L2 address + L2 broadcast (AF_PACKET).
struct Link { index: u32, flags: u32, hatype: u16, name: Vec<u8>, l2: Vec<u8>, l2bc: Vec<u8> }

// Intermediate entry before the single-block layout: name, flags, and up to
// three sockaddr blobs (addr/netmask/broad). Empty blob = absent.
struct Ent { name: Vec<u8>, flags: u32, addr: Vec<u8>, netmask: Vec<u8>, broad: Vec<u8> }

unsafe fn nl_socket() -> Result<i32, i32> {
    // SAFETY: socket(2) reads no memory; AF_NETLINK/SOCK_RAW|CLOEXEC over the
    // NETLINK_ROUTE protocol is glibc's exact carrier for interface dumps.
    let fd = ret(unsafe { sys3(nr::SOCKET, AF_NETLINK as usize, (SOCK_RAW | SOCK_CLOEXEC) as usize, NETLINK_ROUTE) })? as i32;
    // bind sockaddr_nl{family, pad, pid=0(auto), groups=0} = 12 bytes
    let sa: [u8; 12] = {
        let mut b = [0u8; 12];
        b[0..2].copy_from_slice(&AF_NETLINK.to_ne_bytes());
        b
    };
    // SAFETY: sa is a 12-byte sockaddr_nl on our stack; bind reads exactly len.
    match ret(unsafe { sys3(nr::BIND, fd as usize, sa.as_ptr() as usize, sa.len()) }) {
        Ok(_) => Ok(fd),
        // SAFETY: fd is the netlink socket just opened; close it on bind failure.
        Err(e) => { unsafe { close_fd(fd); } Err(e) }
    }
}

unsafe fn close_fd(fd: i32) {
    // SAFETY: fd is a netlink socket we opened; close(2) takes a scalar fd.
    unsafe { crate::arch::syscall::sys1(nr::CLOSE, fd as usize); }
}

// Send a dump request of the given RTM_GET* type. The body after nlmsghdr is an
// rtgenmsg (1 byte family + pad to 4) — sufficient for GETLINK/GETADDR dumps.
unsafe fn send_dump(fd: i32, rtype: u16, seq: u32) -> Result<(), i32> {
    let mut buf = [0u8; 20]; // 16 nlmsghdr + 4 rtgenmsg(aligned)
    let len: u32 = 20;
    buf[0..4].copy_from_slice(&len.to_ne_bytes());
    buf[4..6].copy_from_slice(&rtype.to_ne_bytes());
    buf[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    buf[8..12].copy_from_slice(&seq.to_ne_bytes());
    // nlmsg_pid (12..16) = 0; rtgenmsg.rtgen_family (16) = AF_UNSPEC = 0.
    let dst: [u8; 12] = { let mut b = [0u8; 12]; b[0..2].copy_from_slice(&AF_NETLINK.to_ne_bytes()); b };
    // SAFETY: buf is a fully-initialized 20-byte netlink request; dst is a
    // 12-byte sockaddr_nl naming the kernel (pid 0). sendto reads exactly these.
    ret(unsafe { sys6(nr::SENDTO, fd as usize, buf.as_ptr() as usize, len as usize, 0, dst.as_ptr() as usize, dst.len()) }).map(|_| ())
}

// Receive the full dump into one byte vector (concatenated datagrams) up to the
// terminating NLMSG_DONE. Returns the raw message stream for the caller to walk.
unsafe fn recv_dump(fd: i32, seq: u32) -> Result<Vec<u8>, i32> {
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        // SAFETY: buf is an 8192-byte stack buffer; recvfrom writes ≤ len bytes
        // and returns the count, which we treat as the valid prefix.
        let n = ret(unsafe { sys6(nr::RECVFROM, fd as usize, buf.as_mut_ptr() as usize, buf.len(), 0, 0, 0) })? as usize;
        if n == 0 { break; }
        // Scan this datagram's messages; detect DONE/ERROR before appending so a
        // trailing DONE-only datagram terminates the loop.
        let mut off = 0; let mut done = false;
        while off + 16 <= n {
            let mlen = u32::from_ne_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]) as usize;
            let mtype = u16::from_ne_bytes([buf[off+4], buf[off+5]]);
            let mseq = u32::from_ne_bytes([buf[off+8], buf[off+9], buf[off+10], buf[off+11]]);
            if mlen < 16 || off + mlen > n { break; }
            if mseq == seq {
                if mtype == NLMSG_ERROR {
                    // errno field is the first i32 of the payload (0 = ack).
                    let e = i32::from_ne_bytes([buf[off+16], buf[off+17], buf[off+18], buf[off+19]]);
                    if e != 0 { return Err(-e); }
                    done = true;
                } else if mtype == NLMSG_DONE { done = true; }
            }
            off += nlalign(mlen);
        }
        out.extend_from_slice(&buf[..n]);
        if done { break; }
    }
    Ok(out)
}

// Walk rtattrs in `payload`, calling f(rta_type, value) for each.
fn walk_attrs(payload: &[u8], mut f: impl FnMut(u16, &[u8])) {
    let mut off = 0;
    while off + 4 <= payload.len() {
        let rlen = u16::from_ne_bytes([payload[off], payload[off+1]]) as usize;
        let rtype = u16::from_ne_bytes([payload[off+2], payload[off+3]]);
        if rlen < 4 || off + rlen > payload.len() { break; }
        f(rtype, &payload[off+4..off+rlen]);
        off += nlalign(rlen);
    }
}

// Parse the RTM_GETLINK stream into the link table.
fn parse_links(stream: &[u8]) -> Vec<Link> {
    let mut links: Vec<Link> = Vec::new();
    let mut off = 0;
    while off + 16 <= stream.len() {
        let mlen = u32::from_ne_bytes([stream[off], stream[off+1], stream[off+2], stream[off+3]]) as usize;
        let mtype = u16::from_ne_bytes([stream[off+4], stream[off+5]]);
        if mlen < 16 || off + mlen > stream.len() { break; }
        if mtype == RTM_NEWLINK {
            // ifinfomsg: u8 family, u8 pad, u16 type(hatype), i32 index, u32 flags, u32 change
            let b = &stream[off+16..off+mlen];
            if b.len() >= 16 {
                let hatype = u16::from_ne_bytes([b[2], b[3]]);
                let index = u32::from_ne_bytes([b[4], b[5], b[6], b[7]]);
                let flags = u32::from_ne_bytes([b[8], b[9], b[10], b[11]]);
                let mut name: Vec<u8> = Vec::new();
                let mut l2: Vec<u8> = Vec::new();
                let mut l2bc: Vec<u8> = Vec::new();
                walk_attrs(&b[16..], |t, v| match t {
                    IFLA_IFNAME => { name = v.iter().take_while(|&&c| c != 0).cloned().collect(); }
                    IFLA_ADDRESS => { l2 = v.to_vec(); }
                    IFLA_BROADCAST => { l2bc = v.to_vec(); }
                    _ => {}
                });
                links.push(Link { index, flags, hatype, name, l2, l2bc });
            }
        }
        off += nlalign(mlen);
    }
    links
}

// Build the AF_PACKET sockaddr_ll (20 bytes) carrying `hw` for a link. Empty
// `hw` yields no sockaddr (glibc leaves ifa_addr NULL when IFLA_ADDRESS absent).
fn build_sll(index: u32, hatype: u16, hw: &[u8]) -> Vec<u8> {
    if hw.is_empty() { return Vec::new(); }
    let mut b = [0u8; 20];
    b[0..2].copy_from_slice(&AF_PACKET.to_ne_bytes());     // sll_family
    // sll_protocol(2..4)=0; sll_ifindex(4..8)
    b[4..8].copy_from_slice(&(index as i32).to_ne_bytes());
    b[8..10].copy_from_slice(&hatype.to_ne_bytes());       // sll_hatype
    // sll_pkttype(10)=0
    let halen = core::cmp::min(hw.len(), 8);
    b[11] = halen as u8;                                    // sll_halen
    b[12..12+halen].copy_from_slice(&hw[..halen]);         // sll_addr[8]
    b.to_vec()
}

// Build an IPv4 netmask sockaddr_in (16 bytes) from a prefix length.
fn netmask_v4(prefix: u8) -> Vec<u8> {
    let mut b = [0u8; 16];
    b[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
    let mask: u32 = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix.min(32)) };
    b[4..8].copy_from_slice(&mask.to_be_bytes()); // sin_addr (network order)
    b.to_vec()
}

// Build an IPv6 netmask sockaddr_in6 (28 bytes) from a prefix length.
fn netmask_v6(prefix: u8) -> Vec<u8> {
    let mut b = [0u8; 28];
    b[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
    let mut bits = prefix.min(128) as usize;
    for i in 0..16 { // sin6_addr at offset 8
        let byte = if bits >= 8 { 0xff } else if bits == 0 { 0 } else { (0xffu16 << (8 - bits)) as u8 };
        b[8 + i] = byte;
        bits = bits.saturating_sub(8);
    }
    b.to_vec()
}

// Wrap a raw IPv4/IPv6 address payload (from IFA_*) into a sockaddr blob.
fn build_inet(family: u16, raw: &[u8]) -> Vec<u8> {
    if family == AF_INET && raw.len() >= 4 {
        let mut b = [0u8; 16];
        b[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        b[4..8].copy_from_slice(&raw[..4]); // sin_addr (already network order)
        b.to_vec()
    } else if family == AF_INET6 && raw.len() >= 16 {
        let mut b = [0u8; 28];
        b[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        b[8..24].copy_from_slice(&raw[..16]); // sin6_addr
        b.to_vec()
    } else { Vec::new() }
}

// Parse RTM_GETADDR into address entries, resolving names via the link table.
fn parse_addrs(stream: &[u8], links: &[Link]) -> Vec<Ent> {
    let mut ents: Vec<Ent> = Vec::new();
    let mut off = 0;
    while off + 16 <= stream.len() {
        let mlen = u32::from_ne_bytes([stream[off], stream[off+1], stream[off+2], stream[off+3]]) as usize;
        let mtype = u16::from_ne_bytes([stream[off+4], stream[off+5]]);
        if mlen < 16 || off + mlen > stream.len() { break; }
        if mtype == RTM_NEWADDR {
            // ifaddrmsg: u8 family, u8 prefixlen, u8 flags, u8 scope, u32 index
            let b = &stream[off+16..off+mlen];
            if b.len() >= 8 {
                let family = b[0] as u16;
                let prefix = b[1];
                let index = u32::from_ne_bytes([b[4], b[5], b[6], b[7]]);
                let link = links.iter().find(|l| l.index == index);
                let name = link.map(|l| l.name.clone()).unwrap_or_default();
                let flags = link.map(|l| l.flags).unwrap_or(0);
                let (mut local, mut addr, mut bcast) = (Vec::new(), Vec::new(), Vec::new());
                walk_attrs(&b[8..], |t, v| match t {
                    IFA_LOCAL => local = build_inet(family, v),
                    IFA_ADDRESS => addr = build_inet(family, v),
                    IFA_BROADCAST => bcast = build_inet(family, v),
                    _ => {}
                });
                // glibc union: ifa_addr = IFA_LOCAL if present else IFA_ADDRESS;
                // ifa_ifu = IFA_BROADCAST if present, else (when IFA_LOCAL gave
                // ifa_addr) the leftover IFA_ADDRESS as the peer/dst.
                let (primary, broad) = if !local.is_empty() {
                    let b = if !bcast.is_empty() { bcast } else { addr };
                    (local, b)
                } else {
                    (addr, bcast)
                };
                if primary.is_empty() { off += nlalign(mlen); continue; }
                let netmask = if family == AF_INET { netmask_v4(prefix) } else { netmask_v6(prefix) };
                ents.push(Ent { name, flags, addr: primary, netmask, broad });
            }
        }
        off += nlalign(mlen);
    }
    ents
}

// # C: int getifaddrs(struct ifaddrs **ifap)
#[no_mangle]
pub unsafe extern "C" fn getifaddrs(ifap: *mut *mut Ifaddrs) -> i32 {
    // SAFETY: ifap is a caller out-pointer; on success it receives the head of a
    // single-block linked list, on error *ifap=NULL and errno is set. All netlink
    // I/O stays within stack buffers sized above; the heap block is laid out from
    // exact per-entry sizes computed before the single malloc.
    unsafe {
        if ifap.is_null() { set(EINVAL); return -1; }
        *ifap = core::ptr::null_mut();
        let fd = match nl_socket() { Ok(f) => f, Err(e) => { set(e); return -1; } };
        // RTM_GETLINK (seq 1), then RTM_GETADDR (seq 2).
        let links = match send_dump(fd, RTM_GETLINK, 1).and_then(|_| recv_dump(fd, 1)) {
            Ok(s) => parse_links(&s), Err(e) => { close_fd(fd); set(e); return -1; }
        };
        let addr_stream = match send_dump(fd, RTM_GETADDR, 2).and_then(|_| recv_dump(fd, 2)) {
            Ok(s) => s, Err(e) => { close_fd(fd); set(e); return -1; }
        };
        close_fd(fd);
        let addr_ents = parse_addrs(&addr_stream, &links);

        // Entry order matching glibc: one AF_PACKET entry per link, then the
        // address entries.
        let mut entries: Vec<Ent> = Vec::new();
        for l in &links {
            let addr = build_sll(l.index, l.hatype, &l.l2);
            let broad = build_sll(l.index, l.hatype, &l.l2bc);
            entries.push(Ent { name: l.name.clone(), flags: l.flags, addr, netmask: Vec::new(), broad });
        }
        entries.extend(addr_ents);
        if entries.is_empty() { return 0; } // *ifap stays NULL, success

        // Size the single block: per entry = ifaddrs + name(+NUL) + addr + netmask + broad.
        let isz = core::mem::size_of::<Ifaddrs>();
        let mut total = 0usize;
        for e in &entries { total += isz + e.name.len() + 1 + e.addr.len() + e.netmask.len() + e.broad.len(); }
        let base = crate::malloc::heap::malloc(total);
        if base.is_null() { set(ENOBUFS); return -1; }
        // Pointers region first (all ifaddrs structs), then the byte pools.
        let arr = base as *mut Ifaddrs;
        let mut boff = entries.len() * isz;
        let put = |base: *mut u8, boff: &mut usize, src: &[u8]| -> *mut u8 {
            if src.is_empty() { return core::ptr::null_mut(); }
            let p = base.add(*boff);
            core::ptr::copy_nonoverlapping(src.as_ptr(), p, src.len());
            *boff += src.len(); p
        };
        for (i, e) in entries.iter().enumerate() {
            let cur = arr.add(i);
            // name (NUL-terminated)
            let np = base.add(boff);
            core::ptr::copy_nonoverlapping(e.name.as_ptr(), np, e.name.len());
            *np.add(e.name.len()) = 0; boff += e.name.len() + 1;
            let ap = put(base, &mut boff, &e.addr);
            let mp = put(base, &mut boff, &e.netmask);
            let bp = put(base, &mut boff, &e.broad);
            (*cur).ifa_next = if i + 1 < entries.len() { arr.add(i + 1) } else { core::ptr::null_mut() };
            (*cur).ifa_name = np;
            (*cur).ifa_flags = e.flags;
            (*cur)._pad = 0;
            (*cur).ifa_addr = ap;
            (*cur).ifa_netmask = mp;
            (*cur).ifa_ifu = bp;
            (*cur).ifa_data = core::ptr::null_mut();
        }
        *ifap = arr;
        0
    }
}

// # C: void freeifaddrs(struct ifaddrs *ifa)
#[no_mangle]
pub unsafe extern "C" fn freeifaddrs(ifa: *mut Ifaddrs) {
    // SAFETY: ifa is the single allocation head returned by getifaddrs (whole
    // list + names + sockaddrs in one block), or null. free() handles null.
    unsafe { crate::malloc::heap::free(ifa as *mut u8); }
}
