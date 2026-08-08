// The `acct_v3` on-disk record and its two numeric encodings, matching the
// standard `struct acct_v3` wire layout (`ACCT_VERSION 3`) byte for byte.
//
// Pure: no clock, no task, no file. Everything the record needs arrives as a
// value, so `cargo test -p fs` proves the bit layout and the two float-ish
// encodings without a boot — which matters because `sa`/`accton` parse these
// 64 bytes structurally and a single misplaced field silently corrupts every
// record ever written.

/// `ACCT_VERSION` for `struct acct_v3`. The record's version byte is
/// `ACCT_VERSION | ACCT_BYTEORDER`.
pub const ACCT_VERSION: u8 = 3;

/// `ACCT_BYTEORDER` — the high bit of the version byte, set when the records
/// are big-endian. Derived from the build target rather than assumed, because
/// a reader on another machine decides how to interpret every multi-byte field
/// in the file from this one bit. Both arches this kernel targets are
/// little-endian today; the derivation is what keeps that an observation
/// rather than a hardcoded assumption.
#[cfg(target_endian = "big")]
pub const ACCT_BYTEORDER: u8 = 0x80;
/// See the big-endian arm.
#[cfg(target_endian = "little")]
pub const ACCT_BYTEORDER: u8 = 0x00;

/// The byte written to `ac_version`.
pub const ACCT_VERSION_BYTE: u8 = ACCT_VERSION | ACCT_BYTEORDER;

/// `ACCT_COMM` — the command-name field width in `struct acct_v3`. Note it is
/// NOT NUL-terminated in v3 (v0/v1/v2 carry `ACCT_COMM + 1`).
pub const ACCT_COMM: usize = 16;

/// `sizeof(struct acct_v3)`. Every record is exactly this long and records are
/// appended back-to-back, so the reader indexes by multiplication.
pub const ACCT_V3_LEN: usize = 64;

/// `AHZ`: the fixed 100 Hz tick the accounting file
/// is denominated in, independent of the kernel's own `HZ`.
pub const AHZ: u64 = 100;

/// `... executed fork, but did not exec`.
pub const AFORK:  u8 = 0x01;
/// `... used super-user privileges` (Linux `PF_SUPERPRIV`).
pub const ASU:    u8 = 0x02;
/// `... dumped core`.
pub const ACORE:  u8 = 0x08;
/// `... was killed by a signal`.
pub const AXSIG:  u8 = 0x10;
/// `... was the last task of the process (task group)`.
pub const AGROUP: u8 = 0x20;

/// `MANTSIZE` — comp_t's 13-bit mantissa.
const MANTSIZE: u32 = 13;
/// `EXPSIZE` — comp_t's 3-bit, base-8 exponent.
const EXPSIZE: u32 = 3;
/// `MAXFRACT` — largest value representable without an exponent.
const MAXFRACT: u64 = (1 << MANTSIZE) - 1;

/// Linux `nsec_to_AHZ`. With `AHZ = 100` and `NSEC_PER_SEC % AHZ == 0` the
/// whole function collapses to the exact division `x / (NSEC_PER_SEC / AHZ)`,
/// i.e. nanoseconds to centiseconds. # C: O(1)
pub fn nsec_to_ahz(ns: u64) -> u64 { ns / (1_000_000_000 / AHZ) }

/// Linux `encode_comp_t`: a 16-bit float with a 3-bit base-8 exponent and a
/// 13-bit fraction, rounding half-up and saturating at all-ones.
/// # C: O(exponent) — at most 6 iterations before saturation
pub fn encode_comp_t(value: u64) -> u16 {
    let mut value = value;
    let mut exp: u64 = 0;
    let mut rnd: u64 = 0;
    while value > MAXFRACT {
        rnd = value & (1 << (EXPSIZE - 1));  // round up?
        value >>= EXPSIZE;                   // base-8 exponent == 3-bit shift
        exp += 1;
    }
    // Round up if asked, handling the carry out of the mantissa.
    if rnd != 0 {
        value += 1;
        if value > MAXFRACT { value >>= EXPSIZE; exp += 1; }
    }
    // `exp > ((comp_t)~0U >> MANTSIZE)` — the exponent no longer fits.
    if exp > (u16::MAX as u64 >> MANTSIZE) { return u16::MAX; }
    ((exp << MANTSIZE) + value) as u16
}

/// Linux `encode_float`: the IEEE-754 single-precision bit pattern of `value`,
/// produced by normalising in integer arithmetic. `ac_etime` is declared
/// `float` in the userspace view of `struct acct_v3` and `__u32` in the kernel
/// view, so the field carries these bits verbatim.
/// # C: O(64) worst case
pub fn encode_float(value: u64) -> u32 {
    // 190 = 127 (IEEE bias) + 63, the exponent of a value whose top bit is
    // bit 63; the normalising loop decrements it once per leading zero.
    let mut exp: u32 = 190;
    if value == 0 { return 0; }
    let mut value = value;
    while (value as i64) > 0 { value <<= 1; exp -= 1; }
    let u = ((value >> 40) as u32) & 0x007f_ffff;
    u | (exp << 23)
}

/// Linux `old_encode_dev`: the 16-bit `ac_tty` device number, `(major << 8) |
/// minor`, both truncated to 8 bits. Zero when the process had no controlling
/// terminal. # C: O(1)
pub fn old_encode_dev(rdev: u32) -> u16 {
    let major = (rdev >> 8) & 0xff;
    let minor = rdev & 0xff;
    ((major << 8) | minor) as u16
}

/// One process's accounting facts, in the units Linux collects them in
/// (nanoseconds, bytes, raw counts). Encoding to the record's compressed
/// fields happens in `encode`, so a caller never has to know `comp_t`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AcctFacts {
    /// `AFORK|ASU|ACORE|AXSIG|AGROUP`.
    pub flag:        u8,
    /// Controlling terminal, already `old_encode_dev`-encoded.
    pub tty:         u16,
    /// Raw `task->exit_code` (the wait-status encoding, not the exit status).
    pub exitcode:    u32,
    pub uid:         u32,
    pub gid:         u32,
    /// tgid as seen in the pid namespace that owns the accounting file.
    pub pid:         u32,
    /// Parent's tgid in that same namespace.
    pub ppid:        u32,
    /// Wall-clock process creation time, seconds since the epoch.
    pub btime:       u32,
    /// Wall-clock lifetime of the thread group.
    pub etime_ns:    u64,
    pub utime_ns:    u64,
    pub stime_ns:    u64,
    /// Average memory usage in KiB (`pacct->ac_mem`).
    pub mem_kb:      u64,
    /// Characters transferred (`ac_io`).
    pub io:          u64,
    /// Blocks read or written (`ac_rw`).
    pub rw:          u64,
    pub minflt:      u64,
    pub majflt:      u64,
    pub swaps:       u64,
    /// `current->comm`, space for 16 bytes, NUL-padded and NOT NUL-terminated.
    pub comm:        [u8; ACCT_COMM],
}

impl AcctFacts {
    /// Serialise to the 64-byte `struct acct_v3`, little-endian, in Linux's
    /// field order. Offsets are spelled out because the struct has no padding
    /// and every consumer (`sa`, `lastcomm`, `dump-acct`) indexes it by hand.
    /// # C: O(1)
    pub fn encode(&self) -> [u8; ACCT_V3_LEN] {
        let mut r = [0u8; ACCT_V3_LEN];
        r[0] = self.flag;
        r[1] = ACCT_VERSION_BYTE;
        r[2..4].copy_from_slice(&self.tty.to_le_bytes());
        r[4..8].copy_from_slice(&self.exitcode.to_le_bytes());
        r[8..12].copy_from_slice(&self.uid.to_le_bytes());
        r[12..16].copy_from_slice(&self.gid.to_le_bytes());
        r[16..20].copy_from_slice(&self.pid.to_le_bytes());
        r[20..24].copy_from_slice(&self.ppid.to_le_bytes());
        r[24..28].copy_from_slice(&self.btime.to_le_bytes());
        r[28..32].copy_from_slice(&encode_float(nsec_to_ahz(self.etime_ns)).to_le_bytes());
        r[32..34].copy_from_slice(&encode_comp_t(nsec_to_ahz(self.utime_ns)).to_le_bytes());
        r[34..36].copy_from_slice(&encode_comp_t(nsec_to_ahz(self.stime_ns)).to_le_bytes());
        r[36..38].copy_from_slice(&encode_comp_t(self.mem_kb).to_le_bytes());
        r[38..40].copy_from_slice(&encode_comp_t(self.io).to_le_bytes());
        r[40..42].copy_from_slice(&encode_comp_t(self.rw).to_le_bytes());
        r[42..44].copy_from_slice(&encode_comp_t(self.minflt).to_le_bytes());
        r[44..46].copy_from_slice(&encode_comp_t(self.majflt).to_le_bytes());
        r[46..48].copy_from_slice(&encode_comp_t(self.swaps).to_le_bytes());
        r[48..64].copy_from_slice(&self.comm);
        r
    }

    /// `strscpy(ac->ac_comm, current->comm, sizeof(ac->ac_comm))` — copy up to
    /// 16 bytes, NUL-pad the rest. v3's field is exactly `ACCT_COMM` wide with
    /// no reserved terminator, so a 16-byte name fills it completely.
    /// # C: O(ACCT_COMM)
    pub fn set_comm(&mut self, name: &[u8]) {
        self.comm = [0u8; ACCT_COMM];
        let n = core::cmp::min(name.len(), ACCT_COMM);
        self.comm[..n].copy_from_slice(&name[..n]);
    }

    /// `btime` from the wall clock and the process lifetime, as Linux computes
    /// it: `ktime_get_real_seconds() - elapsed_in_AHZ / AHZ`, clamped into the
    /// `__u32` the field provides (times from 1970 to 2106).
    /// # C: O(1)
    pub fn set_btime_from(&mut self, realtime_ns: u64, etime_ns: u64) {
        let now_s = realtime_ns / 1_000_000_000;
        let elapsed_s = nsec_to_ahz(etime_ns) / AHZ;
        self.btime = now_s.saturating_sub(elapsed_s).min(u32::MAX as u64) as u32;
    }
}
