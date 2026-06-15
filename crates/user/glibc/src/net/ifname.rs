// net/if.h — interface name<->index mapping (docs/59§6 G13). if_nametoindex
// and if_indextoname use the SIOCGIFINDEX / SIOCGIFNAME ioctls on a throwaway
// AF_INET datagram socket (the canonical glibc path); if_nameindex enumerates
// every interface by reading the /sys/class/net directory (one entry per
// iface), pairing each name with its index. if_freenameindex releases that
// array. Freestanding only; thin over raw socket/ioctl/open/getdents/close.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys3};
use crate::internal::errno::{ret, set};
use crate::internal::nr;
use alloc::vec::Vec;

const IF_NAMESIZE: usize = 16;
const SIOCGIFINDEX: usize = 0x8933;
const SIOCGIFNAME: usize = 0x8910;
const AF_INET: usize = 2;
const SOCK_DGRAM: usize = 2;
const ENXIO: i32 = 6;
const EINVAL: i32 = 22;

// struct ifreq: char ifr_name[16]; then a 24-byte union; int ifr_ifindex
// overlaps the union start (offset 16). 40 bytes total (size-asserted below).
#[repr(C)]
struct Ifreq { name: [u8; IF_NAMESIZE], ifindex: i32, _pad: [u8; 20] }
const _: () = assert!(core::mem::size_of::<Ifreq>() == 40);

// Open an AF_INET datagram socket (ioctl carrier); -1 on failure.
unsafe fn dummy_socket() -> i32 {
    // SAFETY: socket(2) reads no memory; AF_INET/SOCK_DGRAM is the standard
    // ioctl-carrier socket glibc opens for these interface queries.
    match ret(unsafe { sys3(nr::SOCKET, AF_INET, SOCK_DGRAM, 0) }) {
        Ok(fd) => fd as i32,
        Err(e) => { set(e); -1 }
    }
}
unsafe fn close_fd(fd: i32) {
    // SAFETY: fd is a socket we opened above; close(2) takes a scalar fd.
    unsafe { crate::arch::syscall::sys1(nr::CLOSE, fd as usize); }
}
unsafe fn do_ioctl(fd: i32, req: usize, ifr: *mut Ifreq) -> Result<(), i32> {
    // SAFETY: ifr points at a 40-byte struct ifreq the kernel reads/writes per
    // the request; fd is our datagram socket.
    ret(unsafe { sys3(nr::IOCTL, fd as usize, req, ifr as usize) }).map(|_| ())
}

// # C: unsigned int if_nametoindex(const char *ifname)
#[no_mangle]
pub unsafe extern "C" fn if_nametoindex(ifname: *const u8) -> u32 {
    // SAFETY: ifname is a NUL-terminated interface name (≤ IFNAMSIZ-1); copied
    // into the ifreq name field, then SIOCGIFINDEX fills ifr_ifindex. 0 on error.
    unsafe {
        if ifname.is_null() { set(EINVAL); return 0; }
        let mut ifr = Ifreq { name: [0; IF_NAMESIZE], ifindex: 0, _pad: [0; 20] };
        let mut i = 0;
        while i < IF_NAMESIZE - 1 && *ifname.add(i) != 0 { ifr.name[i] = *ifname.add(i); i += 1; }
        if *ifname.add(i) != 0 { set(EINVAL); return 0; } // name too long
        let fd = dummy_socket();
        if fd < 0 { return 0; }
        let r = do_ioctl(fd, SIOCGIFINDEX, &mut ifr);
        close_fd(fd);
        match r { Ok(()) => ifr.ifindex as u32, Err(e) => { set(e); 0 } }
    }
}

// # C: char *if_indextoname(unsigned int ifindex, char *ifname)
#[no_mangle]
pub unsafe extern "C" fn if_indextoname(ifindex: u32, ifname: *mut u8) -> *mut u8 {
    // SAFETY: ifname is a caller buffer ≥ IFNAMSIZ bytes; SIOCGIFNAME fills the
    // ifreq name from ifr_ifindex, then we copy it out NUL-terminated. NULL +
    // ENXIO when no interface has that index.
    unsafe {
        if ifname.is_null() { set(EINVAL); return core::ptr::null_mut(); }
        let mut ifr = Ifreq { name: [0; IF_NAMESIZE], ifindex: ifindex as i32, _pad: [0; 20] };
        let fd = dummy_socket();
        if fd < 0 { return core::ptr::null_mut(); }
        let r = do_ioctl(fd, SIOCGIFNAME, &mut ifr);
        close_fd(fd);
        match r {
            Ok(()) => {
                let mut i = 0;
                while i < IF_NAMESIZE && ifr.name[i] != 0 { *ifname.add(i) = ifr.name[i]; i += 1; }
                *ifname.add(i) = 0;
                ifname
            }
            Err(_) => { set(ENXIO); core::ptr::null_mut() }
        }
    }
}

// glibc struct if_nameindex { unsigned int if_index; char *if_name; }.
#[repr(C)]
pub struct IfNameindex { pub if_index: u32, _pad: u32, pub if_name: *mut u8 }
const _: () = assert!(core::mem::size_of::<IfNameindex>() == 16);

// # C: struct if_nameindex *if_nameindex(void)
#[no_mangle]
pub unsafe extern "C" fn if_nameindex() -> *mut IfNameindex {
    // SAFETY: enumerates /sys/class/net, resolving each entry's index via
    // if_nametoindex, into a single heap block: [IfNameindex array | name
    // strings], NUL-terminated by a zero entry. NULL on error. The block is one
    // allocation so if_freenameindex frees it with a single free().
    unsafe {
        let names = match read_net_names() { Some(n) => n, None => return core::ptr::null_mut() };
        // Layout: (count+1) entries, then the name bytes.
        let nentry = names.len() + 1;
        let mut names_bytes = 0usize;
        for n in &names { names_bytes += n.len() + 1; }
        let total = nentry * core::mem::size_of::<IfNameindex>() + names_bytes;
        let base = crate::malloc::heap::malloc(total);
        if base.is_null() { return core::ptr::null_mut(); }
        let arr = base as *mut IfNameindex;
        let mut str_off = nentry * core::mem::size_of::<IfNameindex>();
        for (i, n) in names.iter().enumerate() {
            let np = base.add(str_off);
            for (j, &b) in n.iter().enumerate() { *np.add(j) = b; }
            *np.add(n.len()) = 0;
            // resolve the index via a tmp NUL-terminated copy already in np
            let idx = if_nametoindex(np);
            (*arr.add(i)).if_index = idx;
            (*arr.add(i)).if_name = np;
            str_off += n.len() + 1;
        }
        (*arr.add(names.len())).if_index = 0;
        (*arr.add(names.len())).if_name = core::ptr::null_mut();
        arr
    }
}

// # C: void if_freenameindex(struct if_nameindex *ptr)
#[no_mangle]
pub unsafe extern "C" fn if_freenameindex(ptr: *mut IfNameindex) {
    // SAFETY: ptr is the single allocation returned by if_nameindex (array +
    // names in one block), or null. free() handles null.
    unsafe { crate::malloc::heap::free(ptr as *mut u8); }
}

// Read interface names from /sys/class/net via getdents64. Returns the list of
// names, or None on error.
unsafe fn read_net_names() -> Option<Vec<Vec<u8>>> {
    // SAFETY: opens the sysfs dir read-only and walks its linux_dirent64 records;
    // all buffer reads stay within the kernel-reported byte count.
    unsafe {
        const O_RDONLY: usize = 0;
        const O_DIRECTORY: usize = 0o200000;
        let path = b"/sys/class/net\0";
        let fd = match ret(crate::arch::syscall::sys4(nr::OPENAT, AT_FDCWD, path.as_ptr() as usize, O_RDONLY | O_DIRECTORY, 0)) {
            Ok(fd) => fd as i32, Err(_) => return None,
        };
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = match ret(sys3(nr::GETDENTS64, fd as usize, buf.as_mut_ptr() as usize, buf.len())) {
                Ok(n) => n as usize, Err(_) => { close_fd(fd); return None }
            };
            if n == 0 { break; }
            let mut off = 0;
            while off < n {
                // linux_dirent64: u64 ino; i64 off; u16 reclen; u8 type; char name[].
                let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
                let name_off = off + 19;
                let mut ln = 0;
                while name_off + ln < n && buf[name_off + ln] != 0 { ln += 1; }
                let nm = &buf[name_off..name_off + ln];
                if nm != b"." && nm != b".." && !nm.is_empty() { out.push(nm.to_vec()); }
                if reclen == 0 { break; }
                off += reclen;
            }
        }
        close_fd(fd);
        Some(out)
    }
}
const AT_FDCWD: usize = (-100i64) as usize;
