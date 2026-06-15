// System info (docs/59§6 G8): uname, sysinfo(2), get_nprocs[_conf],
// get_phys_pages, get_avphys_pages, getloadavg. struct utsname (6×65 B = 390)
// and struct sysinfo (112 B, mem_unit at offset 104) match host headers.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys1, sys3};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

// _UTSNAME_LENGTH = 65 each member; 6 members + no padding → 390 bytes.
const UTS_LEN: usize = 65;
#[repr(C)]
pub struct utsname {
    pub sysname: [u8; UTS_LEN],
    pub nodename: [u8; UTS_LEN],
    pub release: [u8; UTS_LEN],
    pub version: [u8; UTS_LEN],
    pub machine: [u8; UTS_LEN],
    pub domainname: [u8; UTS_LEN],
}

// struct sysinfo (<sys/sysinfo.h>): 112 bytes, mem_unit (u32) at offset 104,
// then 8 bytes pad. loads at 8, totalram at 32, freeram at 40.
#[repr(C)]
pub struct sysinfo {
    pub uptime: i64,
    pub loads: [u64; 3],
    pub totalram: u64,
    pub freeram: u64,
    pub sharedram: u64,
    pub bufferram: u64,
    pub totalswap: u64,
    pub freeswap: u64,
    pub procs: u16,
    pub pad: u16,
    pub totalhigh: u64,
    pub freehigh: u64,
    pub mem_unit: u32,
    pub _f: [u8; 0], // _f[20-2*sizeof(long)-sizeof(int)] = 0 on 64-bit
}

// # C: int uname(struct utsname *buf)
#[no_mangle]
pub unsafe extern "C" fn uname(buf: *mut utsname) -> i32 {
    // SAFETY: uname(2); buf is a valid 390-byte utsname out-pointer.
    ret_isize(unsafe { sys1(nr::UNAME, buf as usize) }) as i32
}

// # C: int sysinfo(struct sysinfo *info)
#[no_mangle]
pub unsafe extern "C" fn sysinfo(info: *mut sysinfo) -> i32 {
    // SAFETY: sysinfo(2); info is a valid 112-byte sysinfo out-pointer.
    ret_isize(unsafe { sys1(nr::SYSINFO, info as usize) }) as i32
}

// Read sysinfo into a zeroed struct; None on failure.
unsafe fn read_sysinfo() -> Option<sysinfo> {
    // SAFETY: si is fully written by the kernel on success; pointer is valid.
    unsafe {
        let mut si: sysinfo = core::mem::zeroed();
        if sysinfo(&mut si) == 0 { Some(si) } else { None }
    }
}

// page bytes (4096 on both arches we ship); phys_pages = totalram/PAGE_SIZE.
const PAGE_SIZE: u64 = 4096;

// # C: long get_phys_pages(void)
#[no_mangle]
pub unsafe extern "C" fn get_phys_pages() -> i64 {
    // SAFETY: sysinfo(2)-derived; totalram*mem_unit / page-size, 0 on failure.
    unsafe {
        match read_sysinfo() {
            Some(si) => (si.totalram.saturating_mul(si.mem_unit.max(1) as u64) / PAGE_SIZE) as i64,
            None => 0,
        }
    }
}
// # C: long get_avphys_pages(void)
#[no_mangle]
pub unsafe extern "C" fn get_avphys_pages() -> i64 {
    // SAFETY: sysinfo(2)-derived; freeram*mem_unit / page-size, 0 on failure.
    unsafe {
        match read_sysinfo() {
            Some(si) => (si.freeram.saturating_mul(si.mem_unit.max(1) as u64) / PAGE_SIZE) as i64,
            None => 0,
        }
    }
}

// CPU_SETSIZE bits / sched_getaffinity mask word count (1024 cpus / 64).
const AFF_WORDS: usize = 1024 / 64;

// Count online CPUs via sched_getaffinity (glibc's primary path).
unsafe fn nprocs_affinity() -> i32 {
    // SAFETY: getaffinity writes up to AFF_WORDS u64 into mask; we popcount the
    // returned byte length's worth of words. pid 0 = the calling thread.
    unsafe {
        let mut mask = [0u64; AFF_WORDS];
        let n = sys3(nr::SCHED_GETAFFINITY, 0, AFF_WORDS * 8, mask.as_mut_ptr() as usize);
        if n <= 0 { return -1; }
        let words = (n as usize / 8).min(AFF_WORDS);
        let mut c = 0u32;
        for w in &mask[..words] { c += w.count_ones(); }
        c as i32
    }
}

// # C: int get_nprocs(void) — online CPUs.
#[no_mangle]
pub unsafe extern "C" fn get_nprocs() -> i32 {
    // SAFETY: sched_getaffinity popcount; falls back to 1 if it fails.
    let n = unsafe { nprocs_affinity() };
    if n > 0 { n } else { 1 }
}
// # C: int get_nprocs_conf(void) — configured CPUs.
#[no_mangle]
pub unsafe extern "C" fn get_nprocs_conf() -> i32 {
    // SAFETY: affinity gives online ⊆ configured; we report the same count as
    // the affinity-derived online figure, falling back to 1.
    let n = unsafe { nprocs_affinity() };
    if n > 0 { n } else { 1 }
}

// FSCALE = 1<<16: /proc/loadavg fixed-point base for sysinfo loads[].
const FSCALE: f64 = 65536.0;

// # C: int getloadavg(double loadavg[], int nelem)
#[no_mangle]
pub unsafe extern "C" fn getloadavg(loadavg: *mut f64, nelem: i32) -> i32 {
    // SAFETY: loadavg holds `nelem` doubles; derived from sysinfo loads[] (the
    // same 1/2/15-min figures /proc/loadavg exposes) without parsing /proc.
    unsafe {
        if loadavg.is_null() || nelem <= 0 { return -1; }
        let si = match read_sysinfo() { Some(s) => s, None => return -1 };
        let n = (nelem as usize).min(3);
        for i in 0..n { *loadavg.add(i) = si.loads[i] as f64 / FSCALE; }
        n as i32
    }
}

// # C: int getpagesize(void)
#[no_mangle]
pub unsafe extern "C" fn getpagesize() -> i32 {
    // SAFETY: fixed 4096 page on the arches we ship; no syscall, no memory.
    PAGE_SIZE as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn struct_sizes_match_host() {
        assert_eq!(core::mem::size_of::<utsname>(), 390);
        assert_eq!(core::mem::size_of::<sysinfo>(), 112);
        assert_eq!(core::mem::offset_of!(sysinfo, mem_unit), 104);
        assert_eq!(core::mem::offset_of!(sysinfo, totalram), 32);
        assert_eq!(core::mem::offset_of!(sysinfo, loads), 8);
    }
}
