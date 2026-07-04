#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct VtMode {
    pub mode: u8,
    pub waitv: u8,
    pub relsig: u16,
    pub acqsig: u16,
    pub frsig: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct VtStat {
    pub v_active: u16,
    pub v_signal: u16,
    pub v_state: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct VtSizes {
    pub v_rows: u16,
    pub v_cols: u16,
    pub v_scrollsize: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct ConsoleFontOp {
    pub op: u32,
    pub flags: u32,
    pub width: u32,
    pub height: u32,
    pub charcount: u32,
    pub data_ptr: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct KbEntry {
    pub kb_table: u8,
    pub kb_index: u8,
    pub kb_value: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct KbSentry {
    pub kb_func: u8,
    pub kb_string: [u8; 512],
}

impl Default for KbSentry {
    fn default() -> Self { Self { kb_func: 0, kb_string: [0; 512] } }
}

pub const KDGETMODE: u64 = 0x4B3B;
pub const KDSETMODE: u64 = 0x4B3A;
pub const KDGKBMODE: u64 = 0x4B44;
pub const KDSKBMODE: u64 = 0x4B45;
pub const KDGKBTYPE: u64 = 0x4B33;
pub const KDGETLED: u64 = 0x4B31;
pub const KDSETLED: u64 = 0x4B32;
pub const KDGKBLED: u64 = 0x4B64;
pub const KDSKBLED: u64 = 0x4B65;
pub const KDADDIO: u64 = 0x4B34;
pub const KDDELIO: u64 = 0x4B35;
pub const KDENABIO: u64 = 0x4B36;
pub const KDDISABIO: u64 = 0x4B37;
pub const KIOCSOUND: u64 = 0x4B2F;
pub const KDMKTONE: u64 = 0x4B30;
pub const KDFONTOP: u64 = 0x4B72;
pub const KDGKBENT: u64 = 0x4B46;
pub const KDSKBENT: u64 = 0x4B47;
pub const KDGKBSENT: u64 = 0x4B48;
pub const KDSKBSENT: u64 = 0x4B49;
pub const KDGKBDIACR: u64 = 0x4B4A;
pub const KDSKBDIACR: u64 = 0x4B4B;
pub const KDGETKEYCODE: u64 = 0x4B4C;
pub const KDSETKEYCODE: u64 = 0x4B4D;
pub const KDSIGACCEPT: u64 = 0x4B4E;
pub const KDGKBMAP: u64 = 0x4B70;
pub const KDSKBMAP: u64 = 0x4B71;
pub const GIO_UNIMAP: u64 = 0x4B66;
pub const PIO_UNIMAP: u64 = 0x4B67;
pub const PIO_UNIMAPCLR: u64 = 0x4B68;
pub const VT_OPENQRY: u64 = 0x5600;
pub const VT_GETMODE: u64 = 0x5601;
pub const VT_SETMODE: u64 = 0x5602;
pub const VT_GETSTATE: u64 = 0x5603;
pub const VT_SENDSIG: u64 = 0x5604;
pub const VT_RELDISP: u64 = 0x5605;
pub const VT_ACTIVATE: u64 = 0x5606;
pub const VT_WAITACTIVE: u64 = 0x5607;
pub const VT_DISALLOCATE: u64 = 0x5608;
pub const VT_RESIZE: u64 = 0x5609;
pub const VT_RESIZEX: u64 = 0x560A;
pub const VT_LOCKSWITCH: u64 = 0x560B;
pub const VT_UNLOCKSWITCH: u64 = 0x560C;
pub const VT_GETHIFONTMASK: u64 = 0x560D;
pub const TIOCLINUX: u64 = 0x541C;
pub const KD_TEXT: u32 = 0x00;
pub const KD_GRAPHICS: u32 = 0x01;
pub const KD_TEXT0: u32 = 0x02;
pub const KD_TEXT1: u32 = 0x03;
pub const K_RAW: u32 = 0x00;
pub const K_XLATE: u32 = 0x01;
pub const K_MEDIUMRAW: u32 = 0x02;
pub const K_UNICODE: u32 = 0x03;
pub const K_OFF: u32 = 0x04;
pub const KB_84: u32 = 0x01;
pub const KB_101: u32 = 0x02;
pub const KB_OTHER: u32 = 0x03;
pub const LED_SCR: u32 = 0x01;
pub const LED_NUM: u32 = 0x02;
pub const LED_CAP: u32 = 0x04;
pub const VT_AUTO: u8 = 0;
pub const VT_PROCESS: u8 = 1;
pub const VT_ACKACQ: u8 = 2;
pub const MAX_NR_CONSOLES: usize = 63;
pub const KD_FONT_OP_SET: u32 = 0;
pub const KD_FONT_OP_GET: u32 = 1;
pub const KD_FONT_OP_SET_DEFAULT: u32 = 2;
pub const KD_FONT_OP_COPY: u32 = 3;
