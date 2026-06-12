// ALSA UAPI constants + struct offsets, transcribed from the authoritative
// `sound/asound.h` (SNDRV_PCM_VERSION 2.0.15) shipped in the cross
// toolchain. Offsets are for the LP64 layout (both oxide arches are 64-bit;
// snd_pcm_uframes_t = unsigned long = 8 B). ioctls are matched by magic +
// nr (the size/dir bits vary across the time32/time64 struct variants).

#![allow(dead_code)]

use hal::USER_VA_END;

// ioctl magic bytes.
pub const PCM_MAGIC: u64 = b'A' as u64;
pub const CTL_MAGIC: u64 = b'U' as u64;

// PCM ioctl nrs (magic 'A').
pub const PCM_PVERSION:  u64 = 0x00;
pub const PCM_INFO:      u64 = 0x01;
pub const PCM_TSTAMP:    u64 = 0x02;
pub const PCM_TTSTAMP:   u64 = 0x03;
pub const PCM_HW_REFINE: u64 = 0x10;
pub const PCM_HW_PARAMS: u64 = 0x11;
pub const PCM_HW_FREE:   u64 = 0x12;
pub const PCM_SW_PARAMS: u64 = 0x13;
pub const PCM_STATUS:    u64 = 0x20;
pub const PCM_DELAY:     u64 = 0x21;
pub const PCM_HWSYNC:    u64 = 0x22;
pub const PCM_SYNC_PTR:  u64 = 0x23;
pub const PCM_PREPARE:   u64 = 0x40;
pub const PCM_RESET:     u64 = 0x41;
pub const PCM_START:     u64 = 0x42;
pub const PCM_DROP:      u64 = 0x43;
pub const PCM_DRAIN:     u64 = 0x44;
pub const PCM_PAUSE:     u64 = 0x45;
pub const PCM_WRITEI:    u64 = 0x50;
pub const PCM_READI:     u64 = 0x51;

// Control ioctl nrs (magic 'U').
pub const CTL_PVERSION:       u64 = 0x00;
pub const CTL_CARD_INFO:      u64 = 0x01;
pub const CTL_ELEM_LIST:      u64 = 0x10;
pub const CTL_ELEM_INFO:      u64 = 0x11;
pub const CTL_ELEM_READ:      u64 = 0x12;
pub const CTL_ELEM_WRITE:     u64 = 0x13;
pub const CTL_SUBSCRIBE:      u64 = 0x16;
pub const CTL_PCM_NEXT_DEVICE: u64 = 0x30;
pub const CTL_PCM_INFO:       u64 = 0x31;

// Protocol versions.
pub const SNDRV_PCM_VERSION: u32 = (2 << 16) | 15; // 2.0.15
pub const SNDRV_CTL_VERSION: u32 = (2 << 16) | 9;  // 2.0.9

// SNDRV_PCM_STATE_*.
pub const STATE_OPEN: u32 = 0;
pub const STATE_SETUP: u32 = 1;
pub const STATE_PREPARED: u32 = 2;
pub const STATE_RUNNING: u32 = 3;
pub const STATE_XRUN: u32 = 4;
pub const STATE_DRAINING: u32 = 5;

// SNDRV_PCM_STREAM_*.
pub const STREAM_PLAYBACK: i32 = 0;
pub const STREAM_CAPTURE: i32 = 1;

// SNDRV_PCM_ACCESS_*.
pub const ACCESS_RW_INTERLEAVED: u32 = 3;

// SNDRV_PCM_FORMAT_* (ALSA enum) — the ones our device supports.
pub const FMT_S8: u32 = 0;
pub const FMT_U8: u32 = 1;
pub const FMT_S16_LE: u32 = 2;
pub const FMT_U16_LE: u32 = 4;
pub const FMT_MU_LAW: u32 = 20;
pub const FMT_A_LAW: u32 = 21;

// hw_params field offsets (struct snd_pcm_hw_params, 608 B, LP64).
pub const HWP_FLAGS: usize = 0;
pub const HWP_MASKS: usize = 4;            // masks[3]; each snd_mask = 32 B (bits[8])
pub const HWP_MASK_STRIDE: usize = 32;
pub const HWP_INTERVALS: usize = 260;      // intervals[12]; each = 12 B
pub const HWP_INTERVAL_STRIDE: usize = 12;
pub const HWP_RMASK: usize = 512;
pub const HWP_CMASK: usize = 516;
pub const HWP_INFO: usize = 520;
pub const HWP_MSBITS: usize = 524;
pub const HWP_RATE_NUM: usize = 528;
pub const HWP_RATE_DEN: usize = 532;
pub const HWP_FIFO_SIZE: usize = 536;
pub const HW_PARAMS_SIZE: usize = 608;

// SNDRV_PCM_HW_PARAM_* indices (mask 0..2, interval 8..19).
pub const P_ACCESS: usize = 0;
pub const P_FORMAT: usize = 1;
pub const P_SUBFORMAT: usize = 2;
pub const P_SAMPLE_BITS: usize = 8;
pub const P_FRAME_BITS: usize = 9;
pub const P_CHANNELS: usize = 10;
pub const P_RATE: usize = 11;
pub const P_PERIOD_TIME: usize = 12;
pub const P_PERIOD_SIZE: usize = 13;
pub const P_PERIOD_BYTES: usize = 14;
pub const P_PERIODS: usize = 15;
pub const P_BUFFER_TIME: usize = 16;
pub const P_BUFFER_SIZE: usize = 17;
pub const P_BUFFER_BYTES: usize = 18;
pub const P_TICK_TIME: usize = 19;

// sw_params offsets (LP64): avail_min@16, start_threshold@32, boundary@64
// (silence_threshold@48, silence_size@56 sit between).
pub const SWP_AVAIL_MIN: usize = 16;
pub const SWP_START_THRESHOLD: usize = 32;
pub const SWP_BOUNDARY: usize = 64;
pub const SW_PARAMS_SIZE: usize = 136;

// snd_pcm_status offsets (LP64).
pub const ST_STATE: usize = 0;
pub const ST_APPL_PTR: usize = 40;
pub const ST_HW_PTR: usize = 48;
pub const ST_AVAIL: usize = 64;
pub const ST_AVAIL_MAX: usize = 72;
pub const STATUS_SIZE: usize = 152;

// snd_pcm_sync_ptr offsets (LP64, non-time64-relevant fields).
pub const SP_FLAGS: usize = 0;
pub const SP_STATUS_STATE: usize = 8;
pub const SP_STATUS_HW_PTR: usize = 16;
pub const SP_CONTROL_APPL_PTR: usize = 72;
pub const SP_CONTROL_AVAIL_MIN: usize = 80;
pub const SYNC_PTR_SIZE: usize = 136;
pub const SYNC_PTR_HWSYNC: u32 = 1;
pub const SYNC_PTR_APPL: u32 = 2;
pub const SYNC_PTR_AVAIL_MIN: u32 = 4;

// snd_pcm_info offsets (LP64).
pub const PI_DEVICE: usize = 0;
pub const PI_SUBDEVICE: usize = 4;
pub const PI_STREAM: usize = 8;
pub const PI_CARD: usize = 12;
pub const PI_ID: usize = 16;       // [64]
pub const PI_NAME: usize = 80;     // [80]
pub const PI_SUBNAME: usize = 160; // [32]
pub const PI_SUBDEVICES_COUNT: usize = 200;
pub const PI_SUBDEVICES_AVAIL: usize = 204;
pub const PCM_INFO_SIZE: usize = 288;

// snd_ctl_card_info offsets.
pub const CI_CARD: usize = 0;
pub const CI_ID: usize = 8;        // [16]
pub const CI_DRIVER: usize = 24;   // [16]
pub const CI_NAME: usize = 40;     // [32]
pub const CI_LONGNAME: usize = 72; // [80]
pub const CI_MIXERNAME: usize = 168; // [80]
pub const CI_COMPONENTS: usize = 248; // [128]
pub const CARD_INFO_SIZE: usize = 376;

/// snd_xferi (LP64): result (sframes) @0, buf (ptr) @8, frames @16.
pub const XFERI_RESULT: usize = 0;
pub const XFERI_BUF: usize = 8;
pub const XFERI_FRAMES: usize = 16;
pub const XFERI_SIZE: usize = 24;

/// Bounds-checked userspace struct accessor: validates `[base, base+len)`
/// lies wholly within the user VA window once; offset accessors then assume
/// validity (caller passes `off+access ≤ len`).
pub struct UserBuf { base: u64, len: u64 }

impl UserBuf {
    /// # C: O(1)
    pub fn new(base: u64, len: usize) -> Option<UserBuf> {
        let len = len as u64;
        if base == 0 || len == 0 { return None; }
        match base.checked_add(len) {
            Some(end) if end <= USER_VA_END => Some(UserBuf { base, len }),
            _ => None,
        }
    }
    fn ok(&self, off: usize, sz: usize) -> bool { (off as u64) + (sz as u64) <= self.len }

    /// # C: O(1)
    pub fn r32(&self, off: usize) -> u32 {
        if !self.ok(off, 4) { return 0; }
        // SAFETY: base..base+len validated < USER_VA_END at construction;
        // off+4 ≤ len; CPL=0 read through the caller's address space.
        unsafe { core::ptr::read_volatile((self.base + off as u64) as *const u32) }
    }
    /// # C: O(1)
    pub fn r64(&self, off: usize) -> u64 {
        if !self.ok(off, 8) { return 0; }
        // SAFETY: base..+len validated < USER_VA_END; off+8 ≤ len; CPL=0 8-byte read.
        unsafe { core::ptr::read_volatile((self.base + off as u64) as *const u64) }
    }
    /// # C: O(1)
    pub fn r8(&self, off: usize) -> u8 {
        if !self.ok(off, 1) { return 0; }
        // SAFETY: as r32; off+1 ≤ len; single byte read.
        unsafe { core::ptr::read_volatile((self.base + off as u64) as *const u8) }
    }
    /// # C: O(1)
    pub fn w32(&self, off: usize, v: u32) {
        if !self.ok(off, 4) { return; }
        // SAFETY: as r32; aligned 4-byte write within the validated span.
        unsafe { core::ptr::write_volatile((self.base + off as u64) as *mut u32, v); }
    }
    /// # C: O(1)
    pub fn w64(&self, off: usize, v: u64) {
        if !self.ok(off, 8) { return; }
        // SAFETY: as r32; 8-byte write within the validated span.
        unsafe { core::ptr::write_volatile((self.base + off as u64) as *mut u64, v); }
    }
    /// Write a NUL-padded byte string of `cap` bytes. # C: O(cap)
    pub fn wstr(&self, off: usize, s: &[u8], cap: usize) {
        if !self.ok(off, cap) { return; }
        for i in 0..cap {
            let b = if i < s.len() { s[i] } else { 0 };
            // SAFETY: off+cap ≤ len validated; byte write within the span.
            unsafe { core::ptr::write_volatile((self.base + (off + i) as u64) as *mut u8, b); }
        }
    }
    /// Zero `n` bytes from `off`. # C: O(n)
    pub fn zero(&self, off: usize, n: usize) {
        if !self.ok(off, n) { return; }
        for i in 0..n {
            // SAFETY: off+n ≤ len validated; byte write within the span.
            unsafe { core::ptr::write_volatile((self.base + (off + i) as u64) as *mut u8, 0); }
        }
    }
}
