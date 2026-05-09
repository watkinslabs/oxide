// Linux Virtual Terminal layer per docs/50. /dev/tty0..tty63 +
// /dev/console + /dev/tty (controlling). Multiplexes 63 consoles
// over the fbcon glyph backend (49). Owns KDSETMODE/KDSKBMODE,
// VT_OPENQRY/VT_GETSTATE/VT_ACTIVATE/VT_RELDISP per
// linux/include/uapi/linux/vt.h + kd.h.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use core::sync::atomic::{AtomicU8, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

// ============================================================
// ioctl numbers (per linux/include/uapi/linux/{kd,vt}.h)
// ============================================================
pub const KDGETMODE:        u64 = 0x4B3B;
pub const KDSETMODE:        u64 = 0x4B3A;
pub const KDGKBMODE:        u64 = 0x4B44;
pub const KDSKBMODE:        u64 = 0x4B45;
pub const KDGKBTYPE:        u64 = 0x4B33;
pub const KDGETLED:         u64 = 0x4B31;
pub const KDSETLED:         u64 = 0x4B32;
pub const KDGKBLED:         u64 = 0x4B64;
pub const KDSKBLED:         u64 = 0x4B65;
pub const KDADDIO:          u64 = 0x4B34;
pub const KDDELIO:          u64 = 0x4B35;
pub const KDENABIO:         u64 = 0x4B36;
pub const KDDISABIO:        u64 = 0x4B37;
pub const KIOCSOUND:        u64 = 0x4B2F;
pub const KDMKTONE:         u64 = 0x4B30;
pub const KDFONTOP:         u64 = 0x4B72;

pub const KDGKBENT:         u64 = 0x4B46;
pub const KDSKBENT:         u64 = 0x4B47;
pub const KDGKBSENT:        u64 = 0x4B48;
pub const KDSKBSENT:        u64 = 0x4B49;
pub const KDGKBDIACR:       u64 = 0x4B4A;
pub const KDSKBDIACR:       u64 = 0x4B4B;
pub const KDGETKEYCODE:     u64 = 0x4B4C;
pub const KDSETKEYCODE:     u64 = 0x4B4D;
pub const KDSIGACCEPT:      u64 = 0x4B4E;
pub const KDGKBMAP:         u64 = 0x4B70;
pub const KDSKBMAP:         u64 = 0x4B71;

pub const VT_OPENQRY:       u64 = 0x5600;
pub const VT_GETMODE:       u64 = 0x5601;
pub const VT_SETMODE:       u64 = 0x5602;
pub const VT_GETSTATE:      u64 = 0x5603;
pub const VT_SENDSIG:       u64 = 0x5604;
pub const VT_RELDISP:       u64 = 0x5605;
pub const VT_ACTIVATE:      u64 = 0x5606;
pub const VT_WAITACTIVE:    u64 = 0x5607;
pub const VT_DISALLOCATE:   u64 = 0x5608;
pub const VT_RESIZE:        u64 = 0x5609;
pub const VT_RESIZEX:       u64 = 0x560A;
pub const VT_LOCKSWITCH:    u64 = 0x560B;
pub const VT_UNLOCKSWITCH:  u64 = 0x560C;
pub const VT_GETHIFONTMASK: u64 = 0x560D;
pub const TIOCLINUX:        u64 = 0x541C;

// KD_* mode values
pub const KD_TEXT:      u32 = 0x00;
pub const KD_GRAPHICS:  u32 = 0x01;
pub const KD_TEXT0:     u32 = 0x02;
pub const KD_TEXT1:     u32 = 0x03;

// K_* keyboard modes
pub const K_RAW:        u32 = 0x00;
pub const K_XLATE:      u32 = 0x01;
pub const K_MEDIUMRAW:  u32 = 0x02;
pub const K_UNICODE:    u32 = 0x03;
pub const K_OFF:        u32 = 0x04;

// Keyboard types (KDGKBTYPE)
pub const KB_84:        u32 = 0x01;
pub const KB_101:       u32 = 0x02;
pub const KB_OTHER:     u32 = 0x03;

// LED bits
pub const LED_SCR:      u32 = 0x01;
pub const LED_NUM:      u32 = 0x02;
pub const LED_CAP:      u32 = 0x04;

// VT_SETMODE.mode
pub const VT_AUTO:      u8 = 0;
pub const VT_PROCESS:   u8 = 1;
pub const VT_ACKACQ:    u8 = 2;

// Max number of VTs (Linux MAX_NR_CONSOLES)
pub const MAX_NR_CONSOLES: usize = 63;

// ============================================================
// Wire structs (per linux/include/uapi/linux/vt.h + kd.h)
// ============================================================

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct VtMode {
    pub mode:   u8,
    pub waitv:  u8,
    pub relsig: u16,
    pub acqsig: u16,
    pub frsig:  u16,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct VtStat {
    pub v_active: u16,
    pub v_signal: u16,
    pub v_state:  u16,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct VtSizes {
    pub v_rows:    u16,
    pub v_cols:    u16,
    pub v_scrollsize: u16,   // unused; kept for ABI compat
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct ConsoleFontOp {
    pub op:      u32,
    pub flags:   u32,
    pub width:   u32, pub height: u32,
    pub charcount: u32,
    pub data_ptr: u64,
}

pub const KD_FONT_OP_SET:         u32 = 0;
pub const KD_FONT_OP_GET:         u32 = 1;
pub const KD_FONT_OP_SET_DEFAULT: u32 = 2;
pub const KD_FONT_OP_COPY:        u32 = 3;

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct KbEntry { pub kb_table: u8, pub kb_index: u8, pub kb_value: u16 }

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct KbSentry { pub kb_func: u8, pub kb_string: [u8; 512] }

impl Default for KbSentry {
    fn default() -> Self { Self { kb_func: 0, kb_string: [0; 512] } }
}

// ============================================================
// Per-VT state
// ============================================================

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Inval, Busy, Perm }

pub type KResult<T> = core::result::Result<T, Error>;

#[derive(Copy, Clone)]
pub struct VtSlot {
    pub kd_mode:    u32,    // KD_TEXT / KD_GRAPHICS
    pub kb_mode:    u32,    // K_XLATE etc.
    pub vt_mode:    VtMode, // VT_AUTO or VT_PROCESS
    pub leds:       u32,
    pub cols:       u16,
    pub rows:       u16,
    pub locked:     bool,   // VT_LOCKSWITCH
    pub allocated:  bool,
}

impl Default for VtSlot {
    fn default() -> Self {
        Self {
            kd_mode: KD_TEXT, kb_mode: K_XLATE,
            vt_mode: VtMode { mode: VT_AUTO, waitv: 0, relsig: 0, acqsig: 0, frsig: 0 },
            leds: 0, cols: 80, rows: 25, locked: false, allocated: false,
        }
    }
}

// Active foreground VT (1..MAX_NR_CONSOLES). 0 ⇒ uninitialised.
static ACTIVE_VT: AtomicU8 = AtomicU8::new(0);

static SLOTS: Spinlock<[VtSlot; MAX_NR_CONSOLES], DriverLockClass>
    = Spinlock::new([
        VtSlot { kd_mode: KD_TEXT, kb_mode: K_XLATE,
                 vt_mode: VtMode { mode: VT_AUTO, waitv: 0, relsig: 0, acqsig: 0, frsig: 0 },
                 leds: 0, cols: 80, rows: 25, locked: false, allocated: false };
        MAX_NR_CONSOLES
    ]);

/// Initialise the VT subsystem. Allocates VT 1 as the foreground
/// console (matches Linux's "init starts on tty1" convention).
/// # SAFETY: caller is the boot path; pre-init; single-CPU.
/// # C: O(1)
pub unsafe fn init() -> KResult<()> {
    let mut g = SLOTS.lock();
    g[0].allocated = true;
    ACTIVE_VT.store(1, Ordering::Release);
    Ok(())
}

/// Foreground VT id (1..MAX_NR_CONSOLES) or 0 if uninitialised.
/// # C: O(1)
pub fn active() -> u8 { ACTIVE_VT.load(Ordering::Acquire) }

/// VT_OPENQRY: return the first unallocated VT id, or `Err(Busy)`
/// if every slot is taken.
/// # C: O(MAX_NR_CONSOLES)
pub fn openqry() -> KResult<u8> {
    let g = SLOTS.lock();
    for (i, slot) in g.iter().enumerate() {
        if !slot.allocated { return Ok((i + 1) as u8); }
    }
    Err(Error::Busy)
}

/// VT_ACTIVATE: switch foreground to VT `n` (1..63).
/// Allocates the slot if currently unallocated. Returns `Err(Inval)`
/// out of range, `Err(Busy)` if the source VT has VT_LOCKSWITCH set.
/// # C: O(1)
pub fn activate(n: u8) -> KResult<()> {
    if n < 1 || n as usize > MAX_NR_CONSOLES { return Err(Error::Inval); }
    let mut g = SLOTS.lock();
    let cur = ACTIVE_VT.load(Ordering::Acquire);
    if cur > 0 && g[(cur - 1) as usize].locked { return Err(Error::Busy); }
    g[(n - 1) as usize].allocated = true;
    drop(g);
    ACTIVE_VT.store(n, Ordering::Release);
    Ok(())
}

/// VT_GETSTATE.
/// # C: O(MAX_NR_CONSOLES)
pub fn get_state() -> VtStat {
    let g = SLOTS.lock();
    let mut bits = 0u16;
    for (i, slot) in g.iter().enumerate() {
        if slot.allocated { bits |= 1 << (i + 1); }
    }
    VtStat {
        v_active: ACTIVE_VT.load(Ordering::Acquire) as u16,
        v_signal: 0,
        v_state:  bits,
    }
}

/// VT_DISALLOCATE: free a VT (must be inactive).
/// # C: O(1)
pub fn disallocate(n: u8) -> KResult<()> {
    if n < 1 || n as usize > MAX_NR_CONSOLES { return Err(Error::Inval); }
    if ACTIVE_VT.load(Ordering::Acquire) == n { return Err(Error::Busy); }
    let mut g = SLOTS.lock();
    g[(n - 1) as usize] = VtSlot::default();
    Ok(())
}

/// KDSETMODE: set KD_TEXT / KD_GRAPHICS on VT n.
/// # C: O(1)
pub fn set_kd_mode(n: u8, mode: u32) -> KResult<()> {
    if n < 1 || n as usize > MAX_NR_CONSOLES { return Err(Error::Inval); }
    if mode != KD_TEXT && mode != KD_GRAPHICS && mode != KD_TEXT0 && mode != KD_TEXT1 {
        return Err(Error::Inval);
    }
    let mut g = SLOTS.lock();
    g[(n - 1) as usize].kd_mode = mode;
    Ok(())
}

/// KDSKBMODE: set keyboard mode (K_RAW/K_XLATE/K_MEDIUMRAW/K_UNICODE/K_OFF).
/// # C: O(1)
pub fn set_kb_mode(n: u8, mode: u32) -> KResult<()> {
    if n < 1 || n as usize > MAX_NR_CONSOLES { return Err(Error::Inval); }
    if mode > K_OFF { return Err(Error::Inval); }
    let mut g = SLOTS.lock();
    g[(n - 1) as usize].kb_mode = mode;
    Ok(())
}

/// VT_LOCKSWITCH: prevent VT switch from this console.
/// # C: O(1)
pub fn lock_switch(n: u8, locked: bool) -> KResult<()> {
    if n < 1 || n as usize > MAX_NR_CONSOLES { return Err(Error::Inval); }
    let mut g = SLOTS.lock();
    g[(n - 1) as usize].locked = locked;
    Ok(())
}

/// Snapshot a slot for inspection by the kernel ioctl glue.
/// # C: O(1)
pub fn slot(n: u8) -> Option<VtSlotSnap> {
    if n < 1 || n as usize > MAX_NR_CONSOLES { return None; }
    let g = SLOTS.lock();
    let s = &g[(n - 1) as usize];
    Some(VtSlotSnap {
        kd_mode: s.kd_mode, kb_mode: s.kb_mode, vt_mode: s.vt_mode,
        leds: s.leds, cols: s.cols, rows: s.rows,
        locked: s.locked, allocated: s.allocated,
    })
}

#[derive(Copy, Clone, Debug)]
pub struct VtSlotSnap {
    pub kd_mode: u32, pub kb_mode: u32, pub vt_mode: VtMode,
    pub leds: u32, pub cols: u16, pub rows: u16,
    pub locked: bool, pub allocated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset() {
        ACTIVE_VT.store(0, Ordering::Release);
        let mut g = SLOTS.lock();
        for s in g.iter_mut() { *s = VtSlot::default(); }
    }

    #[test]
    fn init_makes_tty1_active() {
        reset();
        // SAFETY: hosted-test path; init has no asm/IO side effects on host build.
        unsafe { init().unwrap(); }
        assert_eq!(active(), 1);
        assert!(slot(1).unwrap().allocated);
    }

    #[test]
    fn openqry_returns_first_free() {
        reset();
        // SAFETY: hosted-test path; init has no asm/IO side effects on host build.
        unsafe { init().unwrap(); }
        // VT1 is allocated, so openqry returns 2.
        assert_eq!(openqry().unwrap(), 2);
    }

    #[test]
    fn activate_switches_and_allocates() {
        reset();
        // SAFETY: hosted-test path; init has no asm/IO side effects on host build.
        unsafe { init().unwrap(); }
        activate(3).unwrap();
        assert_eq!(active(), 3);
        assert!(slot(3).unwrap().allocated);
    }

    #[test]
    fn activate_rejects_out_of_range() {
        reset();
        // SAFETY: hosted-test path; init has no asm/IO side effects on host build.
        unsafe { init().unwrap(); }
        assert!(matches!(activate(0), Err(Error::Inval)));
        assert!(matches!(activate(64), Err(Error::Inval)));
    }

    #[test]
    fn lockswitch_blocks_activate() {
        reset();
        // SAFETY: hosted-test path; init has no asm/IO side effects on host build.
        unsafe { init().unwrap(); }
        lock_switch(1, true).unwrap();
        assert!(matches!(activate(2), Err(Error::Busy)));
        lock_switch(1, false).unwrap();
        activate(2).unwrap();
    }

    #[test]
    fn kdsetmode_kd_graphics_only_when_valid() {
        reset();
        // SAFETY: hosted-test path; init has no asm/IO side effects on host build.
        unsafe { init().unwrap(); }
        assert!(set_kd_mode(1, KD_GRAPHICS).is_ok());
        assert!(matches!(set_kd_mode(1, 99), Err(Error::Inval)));
        assert_eq!(slot(1).unwrap().kd_mode, KD_GRAPHICS);
    }

    #[test]
    fn kdskbmode_validates_range() {
        reset();
        // SAFETY: hosted-test path; init has no asm/IO side effects on host build.
        unsafe { init().unwrap(); }
        assert!(set_kb_mode(1, K_UNICODE).is_ok());
        assert!(matches!(set_kb_mode(1, 99), Err(Error::Inval)));
    }

    #[test]
    fn vt_getstate_reports_allocations() {
        reset();
        // SAFETY: hosted-test path; init has no asm/IO side effects on host build.
        unsafe { init().unwrap(); }
        activate(5).unwrap();
        let st = get_state();
        assert_eq!(st.v_active, 5);
        assert!(st.v_state & (1 << 1) != 0);    // tty1 still allocated
        assert!(st.v_state & (1 << 5) != 0);    // tty5 allocated
    }

    #[test]
    fn disallocate_inactive_only() {
        reset();
        // SAFETY: hosted-test path; init has no asm/IO side effects on host build.
        unsafe { init().unwrap(); }
        activate(2).unwrap();
        // Active VT can't be disallocated.
        assert!(matches!(disallocate(2), Err(Error::Busy)));
        // Inactive VT 3 — first allocate it then free.
        activate(3).unwrap();
        activate(2).unwrap();
        assert!(disallocate(3).is_ok());
        assert!(!slot(3).unwrap().allocated);
    }

    #[test]
    fn vtmode_size() {
        // u8 + u8 + u16 + u16 + u16 = 8 bytes
        assert_eq!(core::mem::size_of::<VtMode>(), 8);
    }
}
