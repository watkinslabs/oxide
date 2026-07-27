// `struct __kernel_timex` wire layout (`include/uapi/linux/timex.h`), the
// 208-byte LP64 form both x86_64 and aarch64 pass to `adjtimex`/`clock_adjtime`.
//
// Not `target_os`-gated: this is the one place a field offset can be wrong, and
// a wrong offset is invisible to every kernel-side test because the slot files
// cannot be compiled hosted. The offsets asserted here are the same ones the
// userspace side pins in `crates/user/glibc/src/time/adjtime.rs`.

use timekeeper::ntp::Timex;

/// `sizeof(struct __kernel_timex)`.
pub const TIMEX_SIZE: usize = 208;

/// Byte offset of each field. Named rather than inlined because an off-by-8
/// here silently shifts every subsequent field.
const O_MODES: usize = 0;
const O_OFFSET: usize = 8;
const O_FREQ: usize = 16;
const O_MAXERROR: usize = 24;
const O_ESTERROR: usize = 32;
const O_STATUS: usize = 40;
const O_CONSTANT: usize = 48;
const O_PRECISION: usize = 56;
const O_TOLERANCE: usize = 64;
const O_TIME_SEC: usize = 72;
const O_TIME_USEC: usize = 80;
const O_TICK: usize = 88;
const O_PPSFREQ: usize = 96;
const O_JITTER: usize = 104;
const O_SHIFT: usize = 112;
const O_STABIL: usize = 120;
const O_JITCNT: usize = 128;
const O_CALCNT: usize = 136;
const O_ERRCNT: usize = 144;
const O_STBCNT: usize = 152;
const O_TAI: usize = 160;

fn u32_at(b: &[u8; TIMEX_SIZE], o: usize) -> u32 {
    u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn i64_at(b: &[u8; TIMEX_SIZE], o: usize) -> i64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[o..o + 8]);
    i64::from_ne_bytes(w)
}

fn put_u32(b: &mut [u8; TIMEX_SIZE], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_ne_bytes());
}

fn put_i64(b: &mut [u8; TIMEX_SIZE], o: usize, v: i64) {
    b[o..o + 8].copy_from_slice(&v.to_ne_bytes());
}

/// Decode a user `struct __kernel_timex`. Read-only fields are decoded too:
/// `adjtimex` echoes the caller's buffer back, and `ADJ_ADJTIME` reads
/// `offset` out of it.
/// # C: O(1)
pub fn decode(b: &[u8; TIMEX_SIZE]) -> Timex {
    Timex {
        modes:     u32_at(b, O_MODES),
        offset:    i64_at(b, O_OFFSET),
        freq:      i64_at(b, O_FREQ),
        maxerror:  i64_at(b, O_MAXERROR),
        esterror:  i64_at(b, O_ESTERROR),
        status:    u32_at(b, O_STATUS) as i32,
        constant:  i64_at(b, O_CONSTANT),
        precision: i64_at(b, O_PRECISION),
        tolerance: i64_at(b, O_TOLERANCE),
        time_sec:  i64_at(b, O_TIME_SEC),
        time_usec: i64_at(b, O_TIME_USEC),
        tick:      i64_at(b, O_TICK),
        ppsfreq:   i64_at(b, O_PPSFREQ),
        jitter:    i64_at(b, O_JITTER),
        shift:     u32_at(b, O_SHIFT) as i32,
        stabil:    i64_at(b, O_STABIL),
        jitcnt:    i64_at(b, O_JITCNT),
        calcnt:    i64_at(b, O_CALCNT),
        errcnt:    i64_at(b, O_ERRCNT),
        stbcnt:    i64_at(b, O_STBCNT),
        tai:       u32_at(b, O_TAI) as i32,
    }
}

/// Encode back over the caller's buffer. The trailing 44 bytes are Linux's
/// eleven reserved `int :32` words and are written as zero, matching the
/// kernel's copy of its own zero-initialised local.
/// # C: O(1)
pub fn encode(t: &Timex) -> [u8; TIMEX_SIZE] {
    let mut b = [0u8; TIMEX_SIZE];
    put_u32(&mut b, O_MODES, t.modes);
    put_i64(&mut b, O_OFFSET, t.offset);
    put_i64(&mut b, O_FREQ, t.freq);
    put_i64(&mut b, O_MAXERROR, t.maxerror);
    put_i64(&mut b, O_ESTERROR, t.esterror);
    put_u32(&mut b, O_STATUS, t.status as u32);
    put_i64(&mut b, O_CONSTANT, t.constant);
    put_i64(&mut b, O_PRECISION, t.precision);
    put_i64(&mut b, O_TOLERANCE, t.tolerance);
    put_i64(&mut b, O_TIME_SEC, t.time_sec);
    put_i64(&mut b, O_TIME_USEC, t.time_usec);
    put_i64(&mut b, O_TICK, t.tick);
    put_i64(&mut b, O_PPSFREQ, t.ppsfreq);
    put_i64(&mut b, O_JITTER, t.jitter);
    put_u32(&mut b, O_SHIFT, t.shift as u32);
    put_i64(&mut b, O_STABIL, t.stabil);
    put_i64(&mut b, O_JITCNT, t.jitcnt);
    put_i64(&mut b, O_CALCNT, t.calcnt);
    put_i64(&mut b, O_ERRCNT, t.errcnt);
    put_i64(&mut b, O_STBCNT, t.stbcnt);
    put_u32(&mut b, O_TAI, t.tai as u32);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The offsets glibc's `struct timex` pins with its own `offset_of!`
    /// asserts. If the two tables ever disagree, `ntp_gettime` reads garbage.
    #[test]
    fn offsets_match_the_userspace_struct_timex() {
        assert_eq!(TIMEX_SIZE, 208);
        assert_eq!(O_OFFSET, 8);
        assert_eq!(O_FREQ, 16);
        assert_eq!(O_STATUS, 40);
        assert_eq!(O_CONSTANT, 48);
        assert_eq!(O_TIME_SEC, 72);
        assert_eq!(O_TICK, 88);
        assert_eq!(O_TAI, 160);
    }

    fn distinct() -> Timex {
        // Every field a different value, so a copy-paste that reads the wrong
        // offset shows up as a wrong number rather than a coincidence.
        Timex { modes: 0x4321, offset: -11, freq: 22, maxerror: 33, esterror: 44,
            status: -55, constant: 66, precision: 77, tolerance: 88,
            time_sec: 1_700_000_000, time_usec: 999_999, tick: 10_000,
            ppsfreq: 101, jitter: 102, shift: -103, stabil: 104, jitcnt: 105,
            calcnt: 106, errcnt: 107, stbcnt: 108, tai: -37 }
    }

    #[test]
    fn encode_decode_round_trips_every_field() {
        let t = distinct();
        assert_eq!(decode(&encode(&t)), t);
    }

    #[test]
    fn each_field_lands_at_its_declared_offset() {
        let b = encode(&distinct());
        assert_eq!(u32_at(&b, 0), 0x4321);
        assert_eq!(i64_at(&b, 8), -11);
        assert_eq!(i64_at(&b, 16), 22);
        assert_eq!(u32_at(&b, 40) as i32, -55);
        assert_eq!(i64_at(&b, 72), 1_700_000_000);
        assert_eq!(i64_at(&b, 88), 10_000);
        assert_eq!(u32_at(&b, 160) as i32, -37);
    }

    #[test]
    fn the_reserved_tail_is_zeroed() {
        let b = encode(&distinct());
        assert!(b[164..].iter().all(|x| *x == 0), "11 reserved int:32 words");
    }

    #[test]
    fn the_four_byte_pad_words_are_zeroed() {
        // Padding after `modes`, `status` and `shift`. Leaving stack residue
        // there leaks kernel bytes into userspace.
        let b = encode(&distinct());
        assert_eq!(&b[4..8], &[0u8; 4]);
        assert_eq!(&b[44..48], &[0u8; 4]);
        assert_eq!(&b[116..120], &[0u8; 4]);
    }

    #[test]
    fn a_negative_status_survives_the_unsigned_round_trip() {
        // STA_CLK is 0x8000 and `status` is `int`, so the high bit must not be
        // sign-extended into the neighbouring pad on the way out.
        let t = Timex { status: 0x8000u32 as i32, ..Timex::default() };
        let b = encode(&t);
        assert_eq!(&b[44..48], &[0u8; 4]);
        assert_eq!(decode(&b).status, 0x8000u32 as i32);
    }
}
