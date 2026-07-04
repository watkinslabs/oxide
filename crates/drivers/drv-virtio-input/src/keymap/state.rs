extern crate alloc;

use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use sync::{Spinlock, Tty as KbdLockClass};

const TABLE_SIZE: usize = 256;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Mods(u8);

impl Mods {
    pub const SHIFT: Self = Self(1 << 0);
    pub const CTRL: Self = Self(1 << 1);
    pub const ALT: Self = Self(1 << 2);
    pub const ALTGR: Self = Self(1 << 3);
    pub const META: Self = Self(1 << 4);
    pub const CAPS: Self = Self(1 << 5);
    pub const NUM: Self = Self(1 << 6);
    pub const SCROLL: Self = Self(1 << 7);

    /// # C: O(1)
    pub const fn empty() -> Self {
        Self(0)
    }

    /// # C: O(1)
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// # C: O(1)
    pub const fn from_bits_truncate(bits: u8) -> Self {
        Self(bits)
    }

    /// # C: O(1)
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Effective shift state for letter keys: `Shift XOR CapsLock`.
    /// # C: O(1)
    pub fn shifted_letter(self) -> bool {
        self.contains(Self::SHIFT) ^ self.contains(Self::CAPS)
    }
}

/// Runtime keymap. Each slot stores a Unicode codepoint (0 = no
/// mapping); `translate()` UTF-8-encodes on output. This lets
/// non-ASCII locales (DE umlauts, ES ñ, FR accents, …) ride the
/// same loader without a separate "multibyte" path.
/// Loaded from `/etc/keymap` via [`crate::keymap::load_text`];
/// callers must own it for as long as it is the active map.
pub struct Keymap {
    pub name: String,
    pub plain: [u32; TABLE_SIZE],
    pub shift: [u32; TABLE_SIZE],
    pub altgr: [u32; TABLE_SIZE],
    pub shift_altgr: [u32; TABLE_SIZE],
}

impl Keymap {
    /// Construct an all-zero map. Used as a placeholder before the
    /// first `load_text` lands; every entry returns `Out::None`.
    /// # C: O(TABLE_SIZE × 4)
    pub fn empty() -> Self {
        Self {
            name: String::new(),
            plain: [0; TABLE_SIZE],
            shift: [0; TABLE_SIZE],
            altgr: [0; TABLE_SIZE],
            shift_altgr: [0; TABLE_SIZE],
        }
    }
}

static ACTIVE: Spinlock<Option<alloc::boxed::Box<Keymap>>, KbdLockClass> = Spinlock::new(None);
static LOADED: AtomicBool = AtomicBool::new(false);

/// Live modifier mask. Updated by the drain.
static MODS_RAW: AtomicU8 = AtomicU8::new(0);

// Per-side flags.
static SHIFT_L: AtomicBool = AtomicBool::new(false);
static SHIFT_R: AtomicBool = AtomicBool::new(false);
static CTRL_L: AtomicBool = AtomicBool::new(false);
static CTRL_R: AtomicBool = AtomicBool::new(false);
static ALT_L: AtomicBool = AtomicBool::new(false);
static ALT_R: AtomicBool = AtomicBool::new(false);

/// Per-side modifier identity.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Side {
    ShiftLeft,
    ShiftRight,
    CtrlLeft,
    CtrlRight,
    AltLeft,
    AltRight,
}

pub(crate) fn active_keymap() -> sync::Guard<'static, Option<alloc::boxed::Box<Keymap>>, KbdLockClass> {
    ACTIVE.lock()
}

pub(crate) fn install_keymap(keymap: Keymap) {
    *ACTIVE.lock() = Some(alloc::boxed::Box::new(keymap));
    LOADED.store(true, Ordering::Release);
}

/// True iff at least one keymap has been loaded. Drain checks this
/// before translating; if false, EV_KEY events are dropped on the
/// floor (userspace must `loadkeys` before keystrokes flow).
/// # C: O(1)
pub fn is_loaded() -> bool {
    LOADED.load(Ordering::Acquire)
}

/// Read the live modifier mask. Lock-free.
/// # C: O(1)
pub fn mods() -> Mods {
    Mods::from_bits_truncate(MODS_RAW.load(Ordering::Acquire))
}

/// Update a level-triggered modifier bit.
/// # C: O(1)
pub fn set_mod(bit: Mods, pressed: bool) {
    if pressed {
        MODS_RAW.fetch_or(bit.bits(), Ordering::Release);
    } else {
        MODS_RAW.fetch_and(!bit.bits(), Ordering::Release);
    }
}

/// Toggle a Caps / Num / Scroll lock bit (call only on key press,
/// ignore the release).
/// # C: O(1)
pub fn toggle_lock(bit: Mods) {
    MODS_RAW.fetch_xor(bit.bits(), Ordering::Release);
}

/// Set the per-side flag and update the global merged bit so the
/// mask reflects "either side held".
/// # C: O(1)
pub fn set_side(side: Side, pressed: bool) {
    let (flag, group, peer) = match side {
        Side::ShiftLeft => (&SHIFT_L, Mods::SHIFT, &SHIFT_R),
        Side::ShiftRight => (&SHIFT_R, Mods::SHIFT, &SHIFT_L),
        Side::CtrlLeft => (&CTRL_L, Mods::CTRL, &CTRL_R),
        Side::CtrlRight => (&CTRL_R, Mods::CTRL, &CTRL_L),
        Side::AltLeft => (&ALT_L, Mods::ALT, &ALT_R),
        Side::AltRight => (&ALT_R, Mods::ALTGR, &ALT_L),
    };
    flag.store(pressed, Ordering::Release);
    let any = pressed || peer.load(Ordering::Acquire);
    set_mod(group, any);
}

#[cfg(test)]
pub(crate) fn set_loaded(loaded: bool) {
    LOADED.store(loaded, Ordering::Release);
}

#[cfg(test)]
pub(crate) fn set_mods_raw(bits: u8) {
    MODS_RAW.store(bits, Ordering::Relaxed);
}

#[cfg(test)]
pub(crate) fn test_serial_lock() -> sync::Guard<'static, (), KbdLockClass> {
    static SERIAL: Spinlock<(), KbdLockClass> = Spinlock::new(());
    SERIAL.lock()
}
