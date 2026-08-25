use core::ffi::c_void;
use core::mem::align_of;
use core::sync::atomic::{AtomicU32, AtomicUsize};

#[cfg(target_os = "oxide-kernel")]
use alloc::vec::Vec;
#[cfg(target_os = "oxide-kernel")]
use sync::{Modules as ModulesLockClass, Spinlock};

pub(crate) const ALLOC_MAGIC: u64 = 0x4f58_4b50_4941_4c4c;
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) const PAGE_MAGIC: u64 = 0x4f58_4b50_4950_4147;
pub(crate) const CACHE_MAGIC: u64 = 0x4f58_4b50_4943_4143;
pub(crate) const MIN_ALIGN: usize = align_of::<usize>();
pub(crate) const GFP_ZERO: u32 = 0x8000;
pub(crate) const PAGE_SIZE: usize = 4096;
pub(crate) const KMALLOC_CACHE_SLOTS: usize = 128;

#[repr(C)]
pub struct LinuxKmemCache {
    pub(crate) magic: u64,
    pub(crate) object_size: usize,
    pub(crate) align: usize,
    pub(crate) ctor: Option<unsafe extern "C" fn(*mut c_void)>,
}

pub(crate) static KMALLOC_CACHES: [usize; KMALLOC_CACHE_SLOTS] = [0; KMALLOC_CACHE_SLOTS];
pub(crate) static RANDOM_KMALLOC_SEED: usize = 0;
pub(crate) static PAGE_OFFSET_BASE: AtomicUsize = AtomicUsize::new(0);
pub(crate) static VMEMMAP_BASE: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "oxide-kernel")]
#[derive(Copy, Clone)]
pub(crate) struct NativePageRun { pub(crate) pa: u64, pub(crate) order: u32 }

#[cfg(target_os = "oxide-kernel")]
pub(crate) static NATIVE_PAGE_RUNS: Spinlock<Vec<NativePageRun>, ModulesLockClass> =
    Spinlock::new(Vec::new());

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct Header {
    pub(crate) magic: u64,
    pub(crate) total: usize,
    pub(crate) align: usize,
    pub(crate) off: usize,
}

#[repr(C)]
pub struct LinuxPage {
    pub(crate) magic: u64,
    pub(crate) pa: u64,
    pub(crate) va: *mut u8,
    pub(crate) order: u32,
    pub(crate) refs: AtomicU32,
}

