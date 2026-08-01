pub const INPUT_MAJOR: u32 = 13;
pub const EVENT_MINOR_BASE: u32 = 64;

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
pub const EV_MSC: u16 = 0x04;
pub const EV_SW: u16 = 0x05;
pub const EV_LED: u16 = 0x11;
pub const EV_SND: u16 = 0x12;
pub const EV_REP: u16 = 0x14;
pub const EV_FF: u16 = 0x15;
pub const EV_PWR: u16 = 0x16;
pub const EV_MAX: u16 = 0x1f;
pub const EV_CNT: usize = EV_MAX as usize + 1;

pub const SYN_REPORT: u16 = 0x00;
pub const SYN_CONFIG: u16 = 0x01;
pub const SYN_MT_REPORT: u16 = 0x02;

pub const KEY_RESERVED: u16 = 0;
pub const KEY_MAX: u16 = 0x2ff;
pub const KEY_CNT: usize = KEY_MAX as usize + 1;
pub const KEY_MIN_INTERESTING: usize = 0x71;

pub const REL_MAX: u16 = 0x0f;
pub const REL_CNT: usize = REL_MAX as usize + 1;
pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;
pub const ABS_MAX: u16 = 0x3f;
pub const ABS_CNT: usize = ABS_MAX as usize + 1;
pub const MSC_MAX: u16 = 0x07;
pub const MSC_CNT: usize = MSC_MAX as usize + 1;
pub const SW_MAX: u16 = 0x11;
pub const SW_CNT: usize = SW_MAX as usize + 1;
pub const LED_MAX: u16 = 0x0f;
pub const LED_CNT: usize = LED_MAX as usize + 1;
pub const SND_MAX: u16 = 0x07;
pub const SND_CNT: usize = SND_MAX as usize + 1;
pub const FF_MAX: u16 = 0x7f;
pub const FF_CNT: usize = FF_MAX as usize + 1;

pub const INPUT_PROP_MAX: u16 = 0x1f;
pub const INPUT_PROP_CNT: usize = INPUT_PROP_MAX as usize + 1;

pub const ABS_MT_SLOT: u16 = 0x2f;
pub const ABS_MT_FIRST: u16 = 0x30;
pub const ABS_MT_LAST: u16 = 0x3d;
pub const ABS_MT_TRACKING_ID: u16 = 0x39;

pub const REP_DELAY: u16 = 0;
pub const REP_PERIOD: u16 = 1;
pub const REP_CNT: usize = 2;

pub(crate) const KEY_RELEASED: i32 = 0;
pub(crate) const KEY_REPEAT: i32 = 2;
pub(crate) const SYNTHETIC_SYNC_VALUE: i32 = 1;

pub const INPUT_NAME_BYTES: usize = 128;
pub(crate) const INPUT_PHYS_BYTES: usize = 64;
pub(crate) const INPUT_SERIAL_BYTES: usize = 128;
pub(crate) const INPUT_EV_STORAGE_BYTES: usize = 32;
pub(crate) const INPUT_PROP_STORAGE_BYTES: usize = core::mem::size_of::<u64>();
pub(crate) const CAP_BITMAP_BYTES: usize = KEY_CNT / 8;
