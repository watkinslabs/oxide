// sysinfo(2) wire ABI — `struct sysinfo` layout + the page→byte scaling Linux
// `do_sysinfo` performs. Pure logic, no user-memory access and no target gate,
// so the layout and the scaling rule are hosted-testable.

/// `sizeof(struct sysinfo)` on LP64 (include/uapi/linux/sysinfo.h).
pub const SYSINFO_BYTES: usize = 112;

/// Field byte offsets in `struct sysinfo` (LP64).
pub const OFF_UPTIME:    usize = 0;
pub const OFF_LOADS:     usize = 8;
pub const OFF_TOTALRAM:  usize = 32;
pub const OFF_FREERAM:   usize = 40;
pub const OFF_SHAREDRAM: usize = 48;
pub const OFF_BUFFERRAM: usize = 56;
pub const OFF_TOTALSWAP: usize = 64;
pub const OFF_FREESWAP:  usize = 72;
pub const OFF_PROCS:     usize = 80;
pub const OFF_PAD:       usize = 82;
pub const OFF_TOTALHIGH: usize = 88;
pub const OFF_FREEHIGH:  usize = 96;
pub const OFF_MEM_UNIT:  usize = 104;
/// `char _f[]` — the libc5 padding tail Linux leaves zeroed.
pub const OFF_F:         usize = 108;

/// `SI_LOAD_SHIFT` (include/uapi/linux/sysinfo.h) — the fixed-point shift the
/// `loads[]` array uses. NOT the scheduler's `FSHIFT`: `do_sysinfo` calls
/// `get_avenrun(info->loads, 0, SI_LOAD_SHIFT - FSHIFT)`, which shifts the
/// scheduler's FSHIFT-scaled averages LEFT by 5.
pub const SI_LOAD_SHIFT: u32 = 16;

/// `mem_unit` after `do_sysinfo`'s rescale: on any 64-bit host the page→byte
/// shift never overflows, so Linux converts every memory field to BYTES and
/// reports a unit of 1.
pub const MEM_UNIT_BYTES: u32 = 1;

/// The values `do_sysinfo` gathers, already in the units the wire carries:
/// seconds, `SI_LOAD_SHIFT` fixed point, and bytes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SysInfo {
    pub uptime_sec: i64,
    pub loads: [u64; 3],
    pub totalram: u64,
    pub freeram: u64,
    pub sharedram: u64,
    pub bufferram: u64,
    pub totalswap: u64,
    pub freeswap: u64,
    pub procs: u16,
    pub totalhigh: u64,
    pub freehigh: u64,
}

/// Linux `info->uptime = tp.tv_sec + (tp.tv_nsec ? 1 : 0)` — boot time rounded
/// UP to the next whole second whenever any sub-second remainder exists, so a
/// freshly booted system never reports 0 s of uptime. # C: O(1)
pub fn uptime_secs(ns: u64) -> i64 {
    const NSEC_PER_SEC: u64 = 1_000_000_000;
    let (sec, rem) = (ns / NSEC_PER_SEC, ns % NSEC_PER_SEC);
    (sec + if rem != 0 { 1 } else { 0 }) as i64
}

/// Rescale a scheduler `FSHIFT` fixed-point load average to the `SI_LOAD_SHIFT`
/// the `sysinfo` ABI carries (Linux `get_avenrun(..., SI_LOAD_SHIFT - FSHIFT)`).
/// # C: O(1)
pub fn load_to_si(load_fshift: u64, fshift: u32) -> u64 {
    load_fshift << (SI_LOAD_SHIFT - fshift)
}

/// Encode one gathered `SysInfo` into the wire image the caller copies out.
/// # C: O(1)
pub fn encode_sysinfo(si: &SysInfo) -> [u8; SYSINFO_BYTES] {
    let mut b = [0u8; SYSINFO_BYTES];
    {
        let mut put = |off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());
        put(OFF_UPTIME,    si.uptime_sec as u64);
        for (i, l) in si.loads.iter().enumerate() { put(OFF_LOADS + i * 8, *l); }
        put(OFF_TOTALRAM,  si.totalram);
        put(OFF_FREERAM,   si.freeram);
        put(OFF_SHAREDRAM, si.sharedram);
        put(OFF_BUFFERRAM, si.bufferram);
        put(OFF_TOTALSWAP, si.totalswap);
        put(OFF_FREESWAP,  si.freeswap);
        put(OFF_TOTALHIGH, si.totalhigh);
        put(OFF_FREEHIGH,  si.freehigh);
    }
    b[OFF_PROCS..OFF_PROCS + 2].copy_from_slice(&si.procs.to_le_bytes());
    b[OFF_MEM_UNIT..OFF_MEM_UNIT + 4].copy_from_slice(&MEM_UNIT_BYTES.to_le_bytes());
    b
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
