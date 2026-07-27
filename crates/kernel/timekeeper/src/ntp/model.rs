// NTP discipline state and the `adjtimex(2)` transaction, transcribed from
// `kernel/time/ntp.c` (`struct ntp_data`, `ntp_adjtimex`, `second_overflow`,
// `ntp_update_offset`, `ntp_update_frequency`) and the validation half of
// `kernel/time/timekeeping.c` `timekeeping_validate_timex`, Linux v7.2.0-rc4.
//
// CONFIG_NTP_PPS is off, matching the `#else` arms in ntp.c: `ntp_offset_chunk`
// is the plain `shift_right(offset, SHIFT_PLL + time_constant)`, the PPS status
// bits are never raised, and `pps_fill_timex` reports zeros.

use super::uapi::*;

/// `struct __kernel_timex` in decoded form. Wire encoding is the syscall
/// layer's job (`syscalls::timex_abi`); this is what the discipline loop reads
/// and writes.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Timex {
    pub modes: u32,
    pub offset: i64,
    pub freq: i64,
    pub maxerror: i64,
    pub esterror: i64,
    pub status: i32,
    pub constant: i64,
    pub precision: i64,
    pub tolerance: i64,
    pub time_sec: i64,
    pub time_usec: i64,
    pub tick: i64,
    pub ppsfreq: i64,
    pub jitter: i64,
    pub shift: i32,
    pub stabil: i64,
    pub jitcnt: i64,
    pub calcnt: i64,
    pub errcnt: i64,
    pub stbcnt: i64,
    pub tai: i32,
}

/// Why `validate` rejected a `timex`. Kept crate-local rather than reusing
/// `syscall::Errno` so the timekeeper stays free of the syscall ABI crate.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AdjError { Perm, Inval }

/// `shift_right()` — arithmetic shift that rounds toward zero, unlike Rust's
/// `>>` on a negative value, which rounds toward negative infinity. The
/// discipline loop's convergence depends on the symmetry.
/// # C: O(1)
fn shift_right(x: i64, s: i64) -> i64 {
    if s <= 0 { return x; }
    if x < 0 { -((-x) >> s) } else { x >> s }
}

fn clamp_i64(v: i64, lo: i64, hi: i64) -> i64 { if v < lo { lo } else if v > hi { hi } else { v } }

/// `struct ntp_data` — all NTP state, protected by the timekeeper lock.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtpState {
    /// `tick_usec` — `USER_HZ` period in microseconds.
    pub tick_usec: i64,
    /// `tick_length` — adjusted length of one NTP interval, scaled.
    pub tick_length: i64,
    /// `tick_length_base` — the same before this second's phase adjustment.
    pub tick_length_base: i64,
    pub time_state: i32,
    pub time_status: i32,
    /// `time_offset` — pending phase adjustment, scaled ns.
    pub time_offset: i64,
    pub time_constant: i64,
    /// `time_maxerror` / `time_esterror` — NTP sync distance / dispersion (us).
    pub time_maxerror: i64,
    pub time_esterror: i64,
    /// `time_freq` — frequency offset, scaled ns/s.
    pub time_freq: i64,
    /// `time_reftime` — wall seconds at the last PLL update.
    pub time_reftime: i64,
    /// `time_adjust` — legacy `adjtime()` residual (us).
    pub time_adjust: i64,
    /// `ntp_next_leap_sec` — wall second of the pending leap, or `TIME64_MAX`.
    pub ntp_next_leap_sec: i64,
    /// Whether `last_mono_ns` / `last_wall_sec` hold a real baseline yet. An
    /// explicit flag rather than a zero sentinel: monotonic zero is a legal
    /// timestamp, and treating it as "unseeded" silently swallows the first
    /// interval forever.
    pub advance_seeded: bool,
    /// Monotonic timestamp of the last `advance()`.
    pub last_mono_ns: u64,
    /// Wall second the last `second_overflow()` accounted for.
    pub last_wall_sec: i64,
    /// Sub-nanosecond slew carry, in `tick_length`'s scaled domain.
    pub slew_rem: i128,
    /// Set once any mutating mode lands, so an undisciplined system pays only
    /// one relaxed load per tick.
    pub armed: bool,
}

impl NtpState {
    /// Boot state, `tk_ntp_data[]`'s initialiser: unsynchronised, nominal tick,
    /// maximum dispersion, no leap pending.
    pub const INIT: Self = Self {
        tick_usec: USER_TICK_USEC,
        tick_length: 0,
        tick_length_base: 0,
        time_state: TIME_OK,
        time_status: STA_UNSYNC,
        time_offset: 0,
        time_constant: 2,
        time_maxerror: NTP_PHASE_LIMIT,
        time_esterror: NTP_PHASE_LIMIT,
        time_freq: 0,
        time_reftime: 0,
        time_adjust: 0,
        ntp_next_leap_sec: TIME64_MAX,
        advance_seeded: false,
        last_mono_ns: 0,
        last_wall_sec: 0,
        slew_rem: 0,
        armed: false,
    };

    /// `is_error_status()` without PPS.
    /// # C: O(1)
    pub fn is_error_status(&self) -> bool { self.time_status & (STA_UNSYNC | STA_CLOCKERR) != 0 }

    /// `ntp_offset_chunk()` without PPS.
    /// # C: O(1)
    fn offset_chunk(&self, offset: i64) -> i64 {
        shift_right(offset, i64::from(SHIFT_PLL) + self.time_constant)
    }

    /// `ntp_update_frequency()` — recompute `tick_length_base` from
    /// `tick_usec` and `time_freq`, applying the delta immediately.
    /// # C: O(1)
    pub fn update_frequency(&mut self) {
        let second_length = (self.tick_usec * NSEC_PER_USEC * USER_HZ) << NTP_SCALE_SHIFT;
        let new_base = (second_length + self.time_freq) / NTP_INTERVAL_FREQ;
        self.tick_length += new_base - self.tick_length_base;
        self.tick_length_base = new_base;
    }

    /// `ntp_update_offset_fll()`.
    /// # C: O(1)
    fn update_offset_fll(&mut self, offset: i64, secs: i64) -> i64 {
        self.time_status &= !STA_MODE;
        if secs < MINSEC { return 0; }
        if self.time_status & STA_FLL == 0 && secs <= MAXSEC { return 0; }
        self.time_status |= STA_MODE;
        (offset << (NTP_SCALE_SHIFT - SHIFT_FLL as u32)) / secs
    }

    /// `ntp_update_offset()` — feed one phase sample into the PLL/FLL.
    /// # C: O(1)
    fn update_offset(&mut self, offset: i64, real_secs: i64) {
        if self.time_status & STA_PLL == 0 { return; }
        let mut offset = offset;
        if self.time_status & STA_NANO == 0 {
            offset = clamp_i64(offset, -USEC_PER_SEC, USEC_PER_SEC) * NSEC_PER_USEC;
        }
        offset = clamp_i64(offset, -MAXPHASE, MAXPHASE);

        let mut secs = real_secs - self.time_reftime;
        if self.time_status & STA_FREQHOLD != 0 { secs = 0; }
        self.time_reftime = real_secs;

        let mut freq_adj = self.update_offset_fll(offset, secs);
        let cap = 1i64 << (SHIFT_PLL + 1 + self.time_constant as i32);
        if secs > cap { secs = cap; }
        freq_adj += (offset * secs)
            << (NTP_SCALE_SHIFT - 2 * (SHIFT_PLL as u32 + 2 + self.time_constant as u32));
        freq_adj = core::cmp::min(freq_adj + self.time_freq, MAXFREQ_SCALED);
        self.time_freq = core::cmp::max(freq_adj, -MAXFREQ_SCALED);
        self.time_offset = (offset << NTP_SCALE_SHIFT) / NTP_INTERVAL_FREQ;
    }

    /// `process_adj_status()` — fold a new `txc.status` into `time_status`.
    /// # C: O(1)
    fn process_adj_status(&mut self, txc: &Timex, real_secs: i64) {
        if self.time_status & STA_PLL != 0 && txc.status & STA_PLL == 0 {
            self.time_state = TIME_OK;
            self.time_status = STA_UNSYNC;
            self.ntp_next_leap_sec = TIME64_MAX;
        }
        if self.time_status & STA_PLL == 0 && txc.status & STA_PLL != 0 {
            self.time_reftime = real_secs;
        }
        self.time_status &= STA_RONLY;
        self.time_status |= txc.status & !STA_RONLY;
    }

    /// `process_adjtimex_modes()` — apply every requested mode, in Linux's
    /// order. `tai` is the caller's TAI-offset local, written only by `ADJ_TAI`
    /// and only when in range (Linux silently ignores an out-of-range value
    /// rather than reporting EINVAL).
    /// # C: O(1)
    fn process_modes(&mut self, txc: &Timex, tai: &mut i32, real_secs: i64) {
        if txc.modes & ADJ_STATUS != 0 { self.process_adj_status(txc, real_secs); }
        if txc.modes & ADJ_NANO != 0 { self.time_status |= STA_NANO; }
        if txc.modes & ADJ_MICRO != 0 { self.time_status &= !STA_NANO; }
        if txc.modes & ADJ_FREQUENCY != 0 {
            self.time_freq = clamp_i64(txc.freq * PPM_SCALE, -MAXFREQ_SCALED, MAXFREQ_SCALED);
        }
        if txc.modes & ADJ_MAXERROR != 0 {
            self.time_maxerror = clamp_i64(txc.maxerror, 0, NTP_PHASE_LIMIT);
        }
        if txc.modes & ADJ_ESTERROR != 0 {
            self.time_esterror = clamp_i64(txc.esterror, 0, NTP_PHASE_LIMIT);
        }
        if txc.modes & ADJ_TIMECONST != 0 {
            self.time_constant = clamp_i64(txc.constant, 0, MAXTC);
            if self.time_status & STA_NANO == 0 { self.time_constant += 4; }
            self.time_constant = clamp_i64(self.time_constant, 0, MAXTC);
        }
        if txc.modes & ADJ_TAI != 0 && txc.constant >= 0 && txc.constant <= MAX_TAI_OFFSET {
            *tai = txc.constant as i32;
        }
        if txc.modes & ADJ_OFFSET != 0 { self.update_offset(txc.offset, real_secs); }
        if txc.modes & ADJ_TICK != 0 { self.tick_usec = txc.tick; }
        if txc.modes & (ADJ_TICK | ADJ_FREQUENCY | ADJ_OFFSET) != 0 { self.update_frequency(); }
    }

    /// `ntp_adjtimex()` — apply `txc`, then fill it with the resulting state
    /// and return the `TIME_*` clock state that is `adjtimex`'s success value.
    /// `ts` is the wall clock sampled before the lock; `tai` is the timekeeper's
    /// TAI-UTC offset, which the caller commits if it changed.
    /// # C: O(1)
    pub fn adjtimex(&mut self, txc: &mut Timex, ts_sec: i64, ts_nsec: i64, tai: &mut i32) -> i32 {
        if txc.modes & ADJ_ADJTIME != 0 {
            let save_adjust = self.time_adjust;
            if txc.modes & ADJ_OFFSET_READONLY == 0 {
                self.time_adjust = txc.offset;
                self.update_frequency();
                self.armed = true;
            }
            txc.offset = save_adjust;
        } else {
            if txc.modes != 0 {
                self.process_modes(txc, tai, ts_sec);
                self.armed = true;
            }
            txc.offset = shift_right(self.time_offset * NTP_INTERVAL_FREQ,
                i64::from(NTP_SCALE_SHIFT));
            if self.time_status & STA_NANO == 0 { txc.offset /= NSEC_PER_USEC; }
        }

        let mut result = self.time_state;
        if self.is_error_status() { result = TIME_ERROR; }

        txc.freq = shift_right((self.time_freq >> PPM_SCALE_INV_SHIFT) * PPM_SCALE_INV,
            i64::from(NTP_SCALE_SHIFT));
        txc.maxerror  = self.time_maxerror;
        txc.esterror  = self.time_esterror;
        txc.status    = self.time_status;
        txc.constant  = self.time_constant;
        txc.precision = 1;
        txc.tolerance = MAXFREQ_SCALED / PPM_SCALE;
        txc.tick      = self.tick_usec;
        txc.tai       = *tai;
        // `pps_fill_timex` without CONFIG_NTP_PPS.
        txc.ppsfreq = 0; txc.jitter = 0; txc.shift = 0; txc.stabil = 0;
        txc.jitcnt = 0; txc.calcnt = 0; txc.errcnt = 0; txc.stbcnt = 0;

        txc.time_sec = ts_sec;
        txc.time_usec = if self.time_status & STA_NANO != 0 { ts_nsec }
                        else { ts_nsec / NSEC_PER_USEC };

        if ts_sec >= self.ntp_next_leap_sec {
            if self.time_state == TIME_INS && self.time_status & STA_INS != 0 {
                result = TIME_OOP;
                txc.tai += 1;
                txc.time_sec -= 1;
            }
            if self.time_state == TIME_DEL && self.time_status & STA_DEL != 0 {
                result = TIME_WAIT;
                txc.tai -= 1;
                txc.time_sec += 1;
            }
            if self.time_state == TIME_OOP && ts_sec == self.ntp_next_leap_sec {
                result = TIME_WAIT;
            }
        }
        result
    }

    /// `second_overflow()` — one wall second of leap-state machine, dispersion
    /// growth, phase draining and legacy-`adjtime` slew. Returns the leap
    /// adjustment in seconds (-1 insert, +1 delete, 0 none).
    /// # C: O(1)
    pub fn second_overflow(&mut self, secs: i64) -> i64 {
        let mut leap = 0i64;
        match self.time_state {
            TIME_OK => {
                if self.time_status & STA_INS != 0 {
                    self.time_state = TIME_INS;
                    self.ntp_next_leap_sec = secs + SECS_PER_DAY - secs.rem_euclid(SECS_PER_DAY);
                } else if self.time_status & STA_DEL != 0 {
                    self.time_state = TIME_DEL;
                    self.ntp_next_leap_sec =
                        secs + SECS_PER_DAY - (secs + 1).rem_euclid(SECS_PER_DAY);
                }
            }
            TIME_INS => {
                if self.time_status & STA_INS == 0 {
                    self.ntp_next_leap_sec = TIME64_MAX;
                    self.time_state = TIME_OK;
                } else if secs == self.ntp_next_leap_sec {
                    leap = -1;
                    self.time_state = TIME_OOP;
                }
            }
            TIME_DEL => {
                if self.time_status & STA_DEL == 0 {
                    self.ntp_next_leap_sec = TIME64_MAX;
                    self.time_state = TIME_OK;
                } else if secs == self.ntp_next_leap_sec {
                    leap = 1;
                    self.ntp_next_leap_sec = TIME64_MAX;
                    self.time_state = TIME_WAIT;
                }
            }
            TIME_OOP => {
                self.ntp_next_leap_sec = TIME64_MAX;
                self.time_state = TIME_WAIT;
            }
            TIME_WAIT => {
                if self.time_status & (STA_INS | STA_DEL) == 0 { self.time_state = TIME_OK; }
            }
            _ => {}
        }

        self.time_maxerror += MAXFREQ / NSEC_PER_USEC;
        if self.time_maxerror > NTP_PHASE_LIMIT {
            self.time_maxerror = NTP_PHASE_LIMIT;
            self.time_status |= STA_UNSYNC;
        }

        self.tick_length = self.tick_length_base;
        let delta = self.offset_chunk(self.time_offset);
        self.time_offset -= delta;
        self.tick_length += delta;

        if self.time_adjust == 0 { return leap; }
        if self.time_adjust > MAX_TICKADJ {
            self.time_adjust -= MAX_TICKADJ;
            self.tick_length += MAX_TICKADJ_SCALED;
            return leap;
        }
        if self.time_adjust < -MAX_TICKADJ {
            self.time_adjust += MAX_TICKADJ;
            self.tick_length -= MAX_TICKADJ_SCALED;
            return leap;
        }
        self.tick_length +=
            (self.time_adjust * NSEC_PER_USEC / NTP_INTERVAL_FREQ) << NTP_SCALE_SHIFT;
        self.time_adjust = 0;
        leap
    }

    /// `timekeeping_advance()`'s NTP half, integrated against elapsed monotonic
    /// time rather than a fixed tick count: this kernel programs a one-shot
    /// timer, so ticks are not evenly spaced and counting them would slew by
    /// whatever the scheduler happened to need. Runs `second_overflow()` for
    /// each whole wall second that has passed and returns the nanoseconds to
    /// add to the wall-clock offset (frequency/tick/adjtime slew, plus any leap
    /// step). Idempotent: a second caller in the same instant sees no elapsed
    /// time and gets 0, so every CPU may call it from its own tick.
    /// # C: O(seconds elapsed), bounded
    pub fn advance(&mut self, mono_ns: u64, wall_sec: i64) -> i64 {
        if !self.advance_seeded {
            self.advance_seeded = true;
            self.last_mono_ns = mono_ns;
            self.last_wall_sec = wall_sec;
            return 0;
        }
        // A wall step (settimeofday / ADJ_SETOFFSET) resynchronises the second
        // counter instead of replaying the skipped seconds; Linux likewise
        // reruns the leap machine only over seconds the clock actually crossed.
        const MAX_CATCHUP: i64 = 8;
        if wall_sec < self.last_wall_sec || wall_sec - self.last_wall_sec > MAX_CATCHUP {
            self.last_wall_sec = wall_sec;
        }
        let mut leap = 0i64;
        while self.last_wall_sec < wall_sec {
            self.last_wall_sec += 1;
            leap += self.second_overflow(self.last_wall_sec);
        }

        let elapsed = i128::from(mono_ns.saturating_sub(self.last_mono_ns));
        self.last_mono_ns = mono_ns;
        let correction = i128::from(self.tick_length - NTP_INTERVAL_LENGTH_SCALED);
        self.slew_rem += elapsed * correction;
        let denom = i128::from(NTP_INTERVAL_LENGTH_SCALED);
        let ns = self.slew_rem / denom;
        self.slew_rem -= ns * denom;
        (ns as i64).saturating_add(leap.saturating_mul(NSEC_PER_SEC))
    }
}

/// `timekeeping_validate_timex()` — everything checked before the timekeeper
/// lock is taken, including the capability ladder. `capable` is
/// `capable(CAP_SYS_TIME)`; a read-only query (`modes == 0`, or
/// `ADJ_OFFSET_SS_READ`) needs no privilege at all, which is why an
/// unconditional EPERM breaks every NTP client at startup.
/// # C: O(1)
pub fn validate(txc: &Timex, capable: bool) -> Result<(), AdjError> {
    if txc.modes & ADJ_ADJTIME != 0 {
        if txc.modes & ADJ_OFFSET_SINGLESHOT == 0 { return Err(AdjError::Inval); }
        if txc.modes & ADJ_OFFSET_READONLY == 0 && !capable { return Err(AdjError::Perm); }
    } else {
        if txc.modes != 0 && !capable { return Err(AdjError::Perm); }
        if txc.modes & ADJ_TICK != 0
            && (txc.tick < MIN_TICK_USEC || txc.tick > MAX_TICK_USEC)
        {
            return Err(AdjError::Inval);
        }
    }
    if txc.modes & ADJ_SETOFFSET != 0 {
        if !capable { return Err(AdjError::Perm); }
        if txc.time_usec < 0 { return Err(AdjError::Inval); }
        let limit = if txc.modes & ADJ_NANO != 0 { NSEC_PER_SEC } else { USEC_PER_SEC };
        if txc.time_usec >= limit { return Err(AdjError::Inval); }
    }
    if txc.modes & ADJ_FREQUENCY != 0
        && (i64::MIN / PPM_SCALE > txc.freq || i64::MAX / PPM_SCALE < txc.freq)
    {
        return Err(AdjError::Inval);
    }
    Ok(())
}
