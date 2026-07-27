// NTP / `adjtimex(2)` UAPI numbers and discipline-loop scaling constants.
// Transcribed from `include/uapi/linux/timex.h` and `include/linux/timex.h`
// (Linux v7.2.0-rc4). Numbers only — no policy (`docs/52`).

/// `timex.modes` selectors.
pub const ADJ_OFFSET:     u32 = 0x0001;
pub const ADJ_FREQUENCY:  u32 = 0x0002;
pub const ADJ_MAXERROR:   u32 = 0x0004;
pub const ADJ_ESTERROR:   u32 = 0x0008;
pub const ADJ_STATUS:     u32 = 0x0010;
pub const ADJ_TIMECONST:  u32 = 0x0020;
pub const ADJ_TAI:        u32 = 0x0080;
pub const ADJ_SETOFFSET:  u32 = 0x0100;
pub const ADJ_MICRO:      u32 = 0x1000;
pub const ADJ_NANO:       u32 = 0x2000;
pub const ADJ_TICK:       u32 = 0x4000;

/// Kernel-internal `modes` bits (`include/linux/timex.h`): the legacy
/// `adjtime(3)` single-shot channel, which userspace spells
/// `ADJ_OFFSET_SINGLESHOT == 0x8001` and `ADJ_OFFSET_SS_READ == 0xa001`.
pub const ADJ_ADJTIME:          u32 = 0x8000;
pub const ADJ_OFFSET_SINGLESHOT: u32 = 0x0001;
pub const ADJ_OFFSET_READONLY:  u32 = 0x2000;

/// `timex.status` bits.
pub const STA_PLL:       i32 = 0x0001;
pub const STA_PPSFREQ:   i32 = 0x0002;
pub const STA_PPSTIME:   i32 = 0x0004;
pub const STA_FLL:       i32 = 0x0008;
pub const STA_INS:       i32 = 0x0010;
pub const STA_DEL:       i32 = 0x0020;
pub const STA_UNSYNC:    i32 = 0x0040;
pub const STA_FREQHOLD:  i32 = 0x0080;
pub const STA_PPSSIGNAL: i32 = 0x0100;
pub const STA_PPSJITTER: i32 = 0x0200;
pub const STA_PPSWANDER: i32 = 0x0400;
pub const STA_PPSERROR:  i32 = 0x0800;
pub const STA_CLOCKERR:  i32 = 0x1000;
pub const STA_NANO:      i32 = 0x2000;
pub const STA_MODE:      i32 = 0x4000;
pub const STA_CLK:       i32 = 0x8000u32 as i32;

/// Bits `ADJ_STATUS` may not write (`STA_RONLY`).
pub const STA_RONLY: i32 = STA_PPSSIGNAL | STA_PPSJITTER | STA_PPSWANDER
    | STA_PPSERROR | STA_CLOCKERR | STA_NANO | STA_MODE | STA_CLK;

/// `time_state` values, which are also `adjtimex`'s success return.
pub const TIME_OK:    i32 = 0;
pub const TIME_INS:   i32 = 1;
pub const TIME_DEL:   i32 = 2;
pub const TIME_OOP:   i32 = 3;
pub const TIME_WAIT:  i32 = 4;
pub const TIME_ERROR: i32 = 5;

pub const NSEC_PER_USEC: i64 = 1_000;
pub const USEC_PER_SEC:  i64 = 1_000_000;
pub const NSEC_PER_SEC:  i64 = 1_000_000_000;

/// PLL/FLL dampening and the maximum PLL time constant.
pub const SHIFT_PLL: i32 = 2;
pub const SHIFT_FLL: i32 = 2;
pub const MAXTC:     i64 = 10;

/// `time_freq` / `tick_length` fixed-point scale.
pub const NTP_SCALE_SHIFT: u32 = 32;
const SHIFT_USEC: u32 = 16;
/// `PPM_SCALE` — scaled-ppm to internal ns/s conversion.
pub const PPM_SCALE: i64 = NSEC_PER_USEC << (NTP_SCALE_SHIFT - SHIFT_USEC);
pub const PPM_SCALE_INV_SHIFT: u32 = 19;
pub const PPM_SCALE_INV: i64 =
    ((1i128 << (PPM_SCALE_INV_SHIFT + NTP_SCALE_SHIFT)) / PPM_SCALE as i128 + 1) as i64;

/// Maximum phase error (ns) and frequency error (ns/s).
pub const MAXPHASE: i64 = 500_000_000;
pub const MAXFREQ:  i64 = 500_000;
pub const MAXFREQ_SCALED: i64 = MAXFREQ << NTP_SCALE_SHIFT;
/// Minimum / maximum PLL update interval before FLL mode engages (s).
pub const MINSEC: i64 = 256;
pub const MAXSEC: i64 = 2048;
/// `NTP_PHASE_LIMIT` — beyond maximum dispersion (us).
pub const NTP_PHASE_LIMIT: i64 = (MAXPHASE / NSEC_PER_USEC) << 5;

/// `HZ`, and `USER_HZ` as reported through the `timex.tick` ABI. Both are 100
/// here; `TICK_NSEC` in `sched::posix_clock` is the same rate expressed in ns
/// and is what the scheduler actually programs.
pub const NTP_INTERVAL_FREQ: i64 = 100;
pub const USER_HZ: i64 = 100;
/// Nominal length of one NTP interval, in ns and in the scaled domain.
pub const NTP_INTERVAL_LENGTH: i64 = NSEC_PER_SEC / NTP_INTERVAL_FREQ;
pub const NTP_INTERVAL_LENGTH_SCALED: i64 = NTP_INTERVAL_LENGTH << NTP_SCALE_SHIFT;

/// `USER_TICK_USEC` — the `timex.tick` value of an undisciplined clock.
pub const USER_TICK_USEC: i64 = (USEC_PER_SEC + USER_HZ / 2) / USER_HZ;
/// `ADJ_TICK`'s accepted band: within 10% of nominal, or "the quartz is off by
/// more than 10% and something is VERY wrong".
pub const MIN_TICK_USEC: i64 = 900_000 / USER_HZ;
pub const MAX_TICK_USEC: i64 = 1_100_000 / USER_HZ;

pub const SECS_PER_DAY: i64 = 86_400;
/// `MAX_TICKADJ` — per-second cap on legacy `adjtime()` slew (us).
pub const MAX_TICKADJ: i64 = 500;
pub const MAX_TICKADJ_SCALED: i64 =
    ((MAX_TICKADJ * NSEC_PER_USEC) << NTP_SCALE_SHIFT) / NTP_INTERVAL_FREQ;
/// `MAX_TAI_OFFSET` — `ADJ_TAI`'s accepted band is `0 ..= MAX_TAI_OFFSET`.
pub const MAX_TAI_OFFSET: i64 = 100_000;

/// `time64_t` sentinel for "no leap second pending" (`TIME64_MAX`).
pub const TIME64_MAX: i64 = i64::MAX;
