use core::mem::{align_of, size_of};

use hal::PAGE_SIZE_BYTES;

use crate::slab_page;

const PAGE: usize = PAGE_SIZE_BYTES as usize;

/// Subsystem error per `38`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NoMem,
    Inval,
    DoubleFree,
    Corruption,
    WrongCache,
}

pub type KResult<T> = core::result::Result<T, Error>;

/// Per-cache fixed parameters computed once at construction.
#[derive(Copy, Clone, Debug)]
pub struct CacheLayout {
    /// Slot size: `max(size_of<T>(), 16)` rounded up to `obj_align`.
    /// 16-byte minimum makes room for the poison cookie + free-list
    /// offset overlay used while the slot is free.
    pub obj_size: u16,
    /// `max(min(size_of<T>(), 64), align_of<T>())` per `12§1`.
    pub obj_align: u16,
    /// Number of object slots per slab page.
    pub nr_objs: u16,
    /// Byte offset of slot 0 from page start (header size + alignment pad).
    pub obj_offset: u16,
}

impl CacheLayout {
    /// Compute layout for `T`. Panics if `T` is too large for one slab page.
    /// # C: O(1) const-foldable arithmetic.
    pub fn for_type<T>() -> Self {
        Self::for_raw(size_of::<T>(), align_of::<T>())
    }

    /// # C: O(1)
    pub fn for_raw(raw_size: usize, raw_align: usize) -> Self {
        // Spec `12§1` I1: align = max(min(size, 64), requested_align).
        let target_align = core::cmp::max(core::cmp::min(raw_size.max(1), 64), raw_align);
        // Min slot 16B for poison(8) + offset(2) + pad(6).
        let min_slot = 16usize.max(raw_size);
        let obj_size = (min_slot + target_align - 1) & !(target_align - 1);
        let obj_align = target_align;
        let header_padded = (slab_page::HEADER_SIZE + obj_align - 1) & !(obj_align - 1);
        assert!(header_padded < PAGE, "obj_align too large for one slab page");
        let usable = PAGE - header_padded;
        let nr_objs = usable / obj_size;
        assert!(nr_objs > 0, "obj_size too large for one slab page");
        assert!(nr_objs <= u16::MAX as usize, "nr_objs overflow u16");
        Self {
            obj_size: obj_size as u16,
            obj_align: obj_align as u16,
            nr_objs: nr_objs as u16,
            obj_offset: header_padded as u16,
        }
    }
}
