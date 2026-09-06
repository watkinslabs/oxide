//! Versioned native thread factory ABI (`31n§2`).

pub const INFO_CLASS: u64 = 1006;
pub const VERSION: u64 = 1;
pub const REGISTER: u64 = 0;
pub const PREPARE: u64 = 1;
pub const READY: u64 = 2;
pub const PUBLISH: u64 = 3;
pub const ENTER: u64 = 4;
pub const RETURN: u64 = 5;
pub const RELEASE: u64 = 6;
pub const COMPLETE: u64 = 7;
pub const CALLBACK_KIND: u64 = 0x4e54_5448;
pub const SUCCESS: u64 = 0;
pub const INVALID: u64 = 0xc000_000d;
pub const NO_MEMORY: u64 = 0xc000_0017;
pub const NOT_READY: u64 = 0xc000_00a3;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Prepared { pub teb: u64, pub peb: u64 }

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct FactoryRequest { pub creator: u64, pub generation: u64 }
