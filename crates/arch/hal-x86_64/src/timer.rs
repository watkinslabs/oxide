use core::sync::atomic::{AtomicU32, Ordering};

use hal::{Nanos, TimerOps};

// ---------------------------------------------------------------------------
// TimerOps (`20§12`)
// ---------------------------------------------------------------------------

/// TSC frequency in kHz, set by boot calibration (`23§3`). Zero means
/// "not yet calibrated"; `monotonic_ns` returns 0 in that window so
/// callers don't divide by zero.
static TSC_KHZ: AtomicU32 = AtomicU32::new(0);
// Written only by `X86TimerOps::set_oneshot`'s kernel-target arm.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const IA32_TSC_DEADLINE: u32 = 0x6e0;

/// Boot-time hook: stash the TSC frequency in kHz. Calibration code
/// (`23§3`) calls this once `freq` is known.
/// # C: O(1)
pub fn set_tsc_khz(freq: u32) {
    TSC_KHZ.store(freq, Ordering::Relaxed);
}

/// Read TSC. Pure rdtsc — boot-time CR4.TSC handling lands when the
/// kernel starts allowing user CPL=3 reads (see `20§12`).
fn rdtsc() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let lo: u32; let hi: u32;
        // SAFETY: `rdtsc` is unprivileged at CPL=0, returns the
        // 64-bit TSC across edx:eax. No memory effects.
        unsafe {
            core::arch::asm!(
                "rdtsc",
                lateout("eax") lo, lateout("edx") hi,
                options(nomem, nostack, preserves_flags),
            );
        }
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    {
        // Host fallback: a monotonic counter so test sequences see a
        // strictly-non-decreasing `monotonic_ns` if a freq is set.
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        n as u64
    }
}

/// Read legacy I/O port `p` (8-bit). # SAFETY: caller asserts `p` is a
/// real, side-effect-tolerable port (PIT 0x42/0x43, port-B 0x61).
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn pio_in8(p: u16) -> u8 {
    let v: u8;
    // SAFETY: single 8-bit port read; caller asserts `p` is a real port.
    unsafe {
        core::arch::asm!("in al, dx", out("al") v, in("dx") p,
            options(nomem, nostack, preserves_flags));
    }
    v
}

/// Write legacy I/O port `p` (8-bit). # SAFETY: as `pio_in8`.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn pio_out8(p: u16, v: u8) {
    // SAFETY: single 8-bit port write; caller asserts `p` is a real port.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") p, in("al") v,
            options(nomem, nostack, preserves_flags));
    }
}

/// Read the legacy CMOS/RTC wall clock (ports 0x70 index / 0x71 data) and
/// return seconds since the Unix epoch. Used to initialise CLOCK_REALTIME at
/// boot (Linux `read_persistent_clock64` / `mach_get_cmos_time`). Without it
/// the wall clock starts at 1970, so PAM/shadow account checks see every
/// account's password date as "in the future" and TLS/timers/mtimes are wrong.
/// QEMU presents the host time here. Returns 0 if the year reads implausibly.
/// # C: O(1) (a bounded UIP spin)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub fn read_rtc_unix_secs() -> u64 {
    // SAFETY: legacy CMOS RTC index/data ports; side-effect-tolerable byte reads.
    unsafe {
        let rd = |r: u8| -> u8 { pio_out8(0x70, r); pio_in8(0x71) };
        // Wait out an update-in-progress for a torn-read-free snapshot (bounded).
        let mut spins = 0u32;
        while rd(0x0A) & 0x80 != 0 { spins += 1; if spins > 2_000_000 { break; } }
        let statusb = rd(0x0B);
        let (mut sec, mut min, mut hour) = (rd(0x00), rd(0x02), rd(0x04));
        let (mut day, mut mon, mut yr) = (rd(0x07), rd(0x08), rd(0x09));
        let mut cent = rd(0x32);
        let is_bcd = (statusb & 0x04) == 0;
        let is_12h = (statusb & 0x02) == 0;
        let pm = is_12h && (hour & 0x80) != 0;
        hour &= 0x7F;
        if is_bcd {
            let c = |v: u8| (v & 0x0F) + ((v >> 4) * 10);
            sec = c(sec); min = c(min); hour = c(hour);
            day = c(day); mon = c(mon); yr = c(yr);
            cent = if cent != 0 { c(cent) } else { 0 };
        }
        let mut hour = hour as u64;
        if is_12h { if pm && hour != 12 { hour += 12; } else if !pm && hour == 12 { hour = 0; } }
        let year: u64 = if cent >= 19 { cent as u64 * 100 + yr as u64 }
                        else { 2000 + yr as u64 };
        if !(1971..=2200).contains(&year) { return 0; }
        // days_from_civil (Hinnant): days since 1970-01-01.
        let m = mon as u64;
        let y = if m <= 2 { year - 1 } else { year };
        let era = y / 400;
        let yoe = y - era * 400;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as u64 - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146097 + doe - 719468;
        days * 86400 + hour * 3600 + min as u64 * 60 + sec as u64
    }
}

/// Calibrate the TSC frequency in kHz against PIT channel 2 — the
/// standard one-shot gate method (Linux `pit_calibrate_tsc`, `23§3`).
/// Programs channel 2 in mode 0 for the full 65535-tick (~54.9 ms)
/// window, brackets it with `rdtsc`, and derives
/// `kHz = tsc_delta * PIT_HZ / count / 1000`. Replaces the boot
/// hard-coded 2.4 GHz so CLOCK_MONOTONIC tracks real wall-clock (under
/// KVM the host TSC rate; the hard-coded guess broke systemd's
/// deadline math). Returns 0 if the count never elapses (caller keeps
/// a fallback).
/// # SAFETY: boot-only, single-CPU, IRQs masked. Legacy PIT (0x42/0x43)
/// + port-B (0x61) are always present on PC-class (q35) machines; the
/// speaker bit is forced off so no audible side effect.
/// # C: O(1) — one ~55 ms PIT gate window, bounded spin.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn calibrate_tsc_khz() -> u32 {
    const PIT_HZ: u64 = 1_193_182;
    const COUNT:  u16 = 0xFFFF; // ~54.925 ms
    // SAFETY: boot-only single-CPU; legacy PIT (0x42/0x43) + port-B (0x61)
    // always present on q35; speaker-data bit forced off (no sound).
    unsafe {
        // Port-B (0x61): clear speaker-data (bit1), set timer-2 gate (bit0).
        let p61 = (pio_in8(0x61) & !0x02) | 0x01;
        pio_out8(0x61, p61);
        // Channel 2, lobyte+hibyte, mode 0 (interrupt-on-terminal-count),
        // binary counting: 0b1011_0000 = 0xB0.
        pio_out8(0x43, 0xB0);
        pio_out8(0x42, (COUNT & 0xFF) as u8);
        pio_out8(0x42, (COUNT >> 8) as u8);    // loading count starts mode-0
        let start = rdtsc();
        // Mode 0 drives OUT (port-B bit5) high when the count reaches 0.
        // Bound the spin so a non-counting PIT can't hang boot.
        let mut guard: u64 = 0;
        while pio_in8(0x61) & 0x20 == 0 {
            guard += 1;
            if guard > 1_000_000_000 { return 0; }
        }
        let delta = rdtsc().wrapping_sub(start);
        (delta.saturating_mul(PIT_HZ) / COUNT as u64 / 1000) as u32
    }
}

pub struct X86TimerOps;

impl TimerOps for X86TimerOps {
    /// # C: O(1)
    fn monotonic_ns() -> Nanos {
        let khz = TSC_KHZ.load(Ordering::Relaxed);
        if khz == 0 { return Nanos(0); }
        Nanos(hal::time::counter_ns(rdtsc(), khz))
    }

    /// # SAFETY: writes `IA32_TSC_DEADLINE` MSR via `wrmsr`; caller
    /// owns LVT timer setup per `23§4` (one-shot, vector pre-bound).
    /// # C: O(1)
    unsafe fn set_oneshot(deadline_ns: Nanos) {
        let khz = TSC_KHZ.load(Ordering::Relaxed);
        if khz == 0 { return; }
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
        let cycles = ((deadline_ns.0 as u128).saturating_mul(khz as u128)
            / 1_000_000).min(u64::MAX as u128) as u64;
        let target = cycles.max(rdtsc().saturating_add(1));
        let lo = target as u32;
        let hi = (target >> 32) as u32;
        // SAFETY: IA32_TSC_DEADLINE is valid after LAPIC LVT enters deadline mode.
        unsafe {
            core::arch::asm!("wrmsr", in("ecx") IA32_TSC_DEADLINE,
                in("eax") lo, in("edx") hi,
                options(nomem, nostack, preserves_flags));
        }
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        let _ = deadline_ns;
    }

    /// # C: O(1)
    fn freq_khz() -> u32 { TSC_KHZ.load(Ordering::Relaxed) }
}
