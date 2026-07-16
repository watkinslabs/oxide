// /proc/cpuinfo — one block per online CPU, the Linux way. x86 fields come
// from CPUID (vendor leaf 0, brand-string leaves 0x80000002..4, family/model
// from leaf 1); aarch64 from MIDR_EL1 (ARM ARM D11.2.83). Replaces the old
// single static block that hid every AP behind `processor : 0`.
#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use vfs::{Ino, InodeRef};

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// Trim trailing NULs/spaces from a fixed CPUID byte array → &str.
fn trim(b: &[u8]) -> &str {
    crate::util::ascii_field_trimmed(b)
}

fn body() -> Vec<u8> {
    let ncpu = (cpu::smp::online_count() as usize).clamp(1, cpu::MAX_CPUS);
    let mut out: Vec<u8> = Vec::with_capacity(ncpu * 256);
    for i in 0..ncpu {
        block(&mut out, i);
    }
    out
}

    #[cfg(target_arch = "x86_64")]
    fn block(out: &mut Vec<u8>, i: usize) {
        use core::fmt::Write;
        let vendor = hal_x86_64::cpuid_vendor();
        let brand  = hal_x86_64::cpuid_brand();
        let (fam, model, stepping) = hal_x86_64::cpuid_family_model();
        let mhz = hal_x86_64::tsc_khz_from_cpuid() / 1000;
        let _ = write!(VecFmt(out),
            "processor\t: {i}\n\
             vendor_id\t: {v}\n\
             cpu family\t: {fam}\n\
             model\t\t: {model}\n\
             model name\t: {b}\n\
             stepping\t: {stepping}\n\
             cpu MHz\t\t: {mhz}\n\
             cache size\t: 0 KB\n\
             physical id\t: 0\n\
             siblings\t: {n}\n\
             core id\t\t: {i}\n\
             cpu cores\t: {n}\n\
             apicid\t\t: {i}\n\
             fpu\t\t: yes\n\
             flags\t\t: fpu tsc msr pae cx8 apic sep mtrr cmov pat sse sse2 syscall lm\n\
             \n",
            v = trim(&vendor), b = trim(&brand),
            n = (cpu::smp::online_count() as usize).clamp(1, cpu::MAX_CPUS));
    }

    #[cfg(target_arch = "aarch64")]
    fn block(out: &mut Vec<u8>, i: usize) {
        use core::fmt::Write;
        let midr = hal_aarch64::midr_el1();
        let implementer = (midr >> 24) & 0xff;
        let variant     = (midr >> 20) & 0xf;
        let arch        = (midr >> 16) & 0xf;
        let part        = (midr >>  4) & 0xfff;
        let revision    = midr & 0xf;
        let _ = write!(VecFmt(out),
            "processor\t: {i}\n\
             BogoMIPS\t: 0.00\n\
             Features\t: fp asimd\n\
             CPU implementer\t: {implementer:#04x}\n\
             CPU architecture: {arch}\n\
             CPU variant\t: {variant:#x}\n\
             CPU part\t: {part:#05x}\n\
             CPU revision\t: {revision}\n\
             \n");
    }

/// `/proc/cpuinfo` inode (KEYSTONE struct-`Inode`). # C: O(1)
pub fn make_proc_cpuinfo() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::CPUINFO as Ino, body) }
