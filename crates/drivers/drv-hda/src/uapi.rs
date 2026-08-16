// Intel HD-Audio controller register file and bit definitions, plus the
// codec-side verb/parameter/capability encodings. Numbers only: every
// decision that consumes them lives in a module that owns that decision.

#![allow(dead_code)]

// ---- Controller global registers (byte offsets from BAR0) ----
pub const REG_GCAP: u64 = 0x00;
pub const REG_VMIN: u64 = 0x02;
pub const REG_VMAJ: u64 = 0x03;
pub const REG_OUTPAY: u64 = 0x04;
pub const REG_INPAY: u64 = 0x06;
pub const REG_GCTL: u64 = 0x08;
pub const REG_WAKEEN: u64 = 0x0c;
pub const REG_STATESTS: u64 = 0x0e;
pub const REG_GSTS: u64 = 0x10;
pub const REG_INTCTL: u64 = 0x20;
pub const REG_INTSTS: u64 = 0x24;
pub const REG_WALLCLK: u64 = 0x30;
pub const REG_SSYNC: u64 = 0x38;
pub const REG_CORBLBASE: u64 = 0x40;
pub const REG_CORBUBASE: u64 = 0x44;
pub const REG_CORBWP: u64 = 0x48;
pub const REG_CORBRP: u64 = 0x4a;
pub const REG_CORBCTL: u64 = 0x4c;
pub const REG_CORBSTS: u64 = 0x4d;
pub const REG_CORBSIZE: u64 = 0x4e;
pub const REG_RIRBLBASE: u64 = 0x50;
pub const REG_RIRBUBASE: u64 = 0x54;
pub const REG_RIRBWP: u64 = 0x58;
pub const REG_RINTCNT: u64 = 0x5a;
pub const REG_RIRBCTL: u64 = 0x5c;
pub const REG_RIRBSTS: u64 = 0x5d;
pub const REG_RIRBSIZE: u64 = 0x5e;
pub const REG_IC: u64 = 0x60;
pub const REG_IR: u64 = 0x64;
pub const REG_IRS: u64 = 0x68;
pub const REG_DPLBASE: u64 = 0x70;
pub const REG_DPUBASE: u64 = 0x74;

// ---- GCAP ----
pub const GCAP_64OK: u16 = 1 << 0;
pub const GCAP_ISS_SHIFT: u32 = 8;
pub const GCAP_OSS_SHIFT: u32 = 12;
pub const GCAP_BSS_SHIFT: u32 = 3;
pub const GCAP_STREAM_MASK: u16 = 0xf;
pub const GCAP_BSS_MASK: u16 = 0x1f;

// ---- GCTL ----
pub const GCTL_RESET: u32 = 1 << 0;
pub const GCTL_FCNTRL: u32 = 1 << 1;
pub const GCTL_UNSOL: u32 = 1 << 8;

/// STATESTS carries one bit per codec slot the controller supports.
pub const MAX_CODECS: u8 = 8;
pub const STATESTS_INT_MASK: u16 = (1 << MAX_CODECS) - 1;

// ---- INTCTL / INTSTS ----
pub const INT_ALL_STREAM: u32 = 0x3fff_ffff;
pub const INT_CTRL_EN: u32 = 1 << 30;
pub const INT_GLOBAL_EN: u32 = 1 << 31;

// ---- CORB / RIRB ----
pub const CORBRP_RST: u16 = 1 << 15;
pub const CORBCTL_CMEIE: u8 = 1 << 0;
pub const CORBCTL_RUN: u8 = 1 << 1;
pub const CORBSTS_CMEI: u8 = 1 << 0;
pub const RIRBWP_RST: u16 = 1 << 15;
pub const RIRBCTL_IRQ_EN: u8 = 1 << 0;
pub const RIRBCTL_DMA_EN: u8 = 1 << 1;
pub const RIRBCTL_OVERRUN_EN: u8 = 1 << 2;
pub const RIRBSTS_IRQ: u8 = 1 << 0;
pub const RIRBSTS_OVERRUN: u8 = 1 << 2;
pub const RIRBSTS_INT_MASK: u8 = RIRBSTS_IRQ | RIRBSTS_OVERRUN;
/// CORBSIZE/RIRBSIZE encoding for a 256-entry ring.
pub const RING_SIZE_256: u8 = 0x02;
pub const CORB_ENTRIES: usize = 256;
pub const RIRB_ENTRIES: usize = 256;
pub const CORB_ENTRY_BYTES: usize = 4;
pub const RIRB_ENTRY_BYTES: usize = 8;
/// The shared ring page places CORB at 0 and RIRB well past the CORB's 1 KiB.
pub const RIRB_PAGE_OFFSET: u64 = 2048;
/// RINTCNT: interrupt after every response.
pub const RIRB_INT_COUNT: u16 = 1;
/// `res_ex` bit marking a response as an unsolicited event.
pub const RIRB_EX_UNSOL_EV: u32 = 1 << 4;
pub const RIRB_EX_ADDR_MASK: u32 = 0xf;

// ---- Immediate command interface ----
pub const IRS_BUSY: u16 = 1 << 0;
pub const IRS_VALID: u16 = 1 << 1;
/// Immediate-command send and response polls, one microsecond apart.
pub const IMMEDIATE_POLLS: u32 = 50;

// ---- Stream descriptors ----
pub const SD_BASE: u64 = 0x80;
pub const SD_STRIDE: u64 = 0x20;
pub const SD_CTL: u64 = 0x00;
pub const SD_CTL_HIGH: u64 = 0x02;
pub const SD_STS: u64 = 0x03;
pub const SD_LPIB: u64 = 0x04;
pub const SD_CBL: u64 = 0x08;
pub const SD_LVI: u64 = 0x0c;
pub const SD_FIFOW: u64 = 0x0e;
pub const SD_FIFOSIZE: u64 = 0x10;
pub const SD_FORMAT: u64 = 0x12;
pub const SD_BDLPL: u64 = 0x18;
pub const SD_BDLPU: u64 = 0x1c;

pub const SD_CTL_STREAM_RESET: u32 = 1 << 0;
pub const SD_CTL_DMA_START: u32 = 1 << 1;
pub const SD_INT_COMPLETE: u32 = 1 << 2;
pub const SD_INT_FIFO_ERR: u32 = 1 << 3;
pub const SD_INT_DESC_ERR: u32 = 1 << 4;
pub const SD_INT_MASK: u32 = SD_INT_COMPLETE | SD_INT_FIFO_ERR | SD_INT_DESC_ERR;
pub const SD_CTL_STRIPE_SHIFT: u32 = 16;
pub const SD_CTL_STRIPE_MASK: u32 = 0x3 << SD_CTL_STRIPE_SHIFT;
pub const SD_CTL_TRAFFIC_PRIO: u32 = 1 << 18;
pub const SD_CTL_DIR: u32 = 1 << 19;
pub const SD_CTL_STREAM_TAG_SHIFT: u32 = 20;
pub const SD_CTL_STREAM_TAG_MASK: u32 = 0xf << SD_CTL_STREAM_TAG_SHIFT;
pub const SD_STS_FIFO_READY: u8 = 0x20;

/// DMA position buffer: one 8-byte slot per stream, enable bit in DPLBASE.
pub const DPLBASE_ENABLE: u32 = 1 << 0;
pub const POSBUF_STRIDE: u64 = 8;

// ---- BDL ----
pub const BDL_BYTES: usize = 4096;
pub const BDL_ENTRY_BYTES: usize = 16;
pub const BDL_MAX_ENTRIES: usize = BDL_BYTES / BDL_ENTRY_BYTES;
pub const BDL_IOC: u32 = 1 << 0;
/// A period must be a whole number of 128-byte blocks.
pub const PERIOD_ALIGN_BYTES: u32 = 128;

// ---- Stream format (SDxFMT and AC_VERB_SET_STREAM_FORMAT) ----
pub const FMT_CHAN_MASK: u16 = 0x000f;
pub const FMT_BITS_SHIFT: u32 = 4;
pub const FMT_BITS_8: u16 = 0 << 4;
pub const FMT_BITS_16: u16 = 1 << 4;
pub const FMT_BITS_20: u16 = 2 << 4;
pub const FMT_BITS_24: u16 = 3 << 4;
pub const FMT_BITS_32: u16 = 4 << 4;
pub const FMT_DIV_SHIFT: u32 = 8;
pub const FMT_MULT_SHIFT: u32 = 11;
pub const FMT_BASE_48K: u16 = 0 << 14;
pub const FMT_BASE_44K: u16 = 1 << 14;
pub const FMT_TYPE_NON_PCM: u16 = 1 << 15;
/// Widest channel count a stream format can encode.
pub const FMT_MAX_CHANNELS: u32 = 16;

// ---- PCI ----
/// Base 0x04 multimedia, subclass 0x03 HD Audio, prog-if 0x00.
pub const HDA_CLASS24: u32 = 0x04_03_00;
/// PCI config byte holding the traffic-class select field.
pub const PCI_TCSEL: u16 = 0x44;
pub const PCI_TCSEL_MASK: u8 = 0x07;
