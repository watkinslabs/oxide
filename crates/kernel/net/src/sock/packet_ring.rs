use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

const PAGE_SIZE: u32 = 4096;
const V3_ALIGNMENT: u32 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketRingKind { Rx, Tx }

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketRingRequest {
    pub block_size: u32,
    pub block_nr: u32,
    pub frame_size: u32,
    pub frame_nr: u32,
    pub retire_block_timeout: u32,
    pub private_size: u32,
    pub feature_request: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketRingLayout {
    pub kind: PacketRingKind,
    pub version: u8,
    pub reserve: u32,
    pub request: PacketRingRequest,
    pub frames_per_block: u32,
}

struct PacketRingBlock {
    pa: u64,
    mapped_pages: u32,
    allocated_pages: u32,
    owns_frames: bool,
    #[cfg(not(target_os = "oxide-kernel"))]
    allocation_size: usize,
}

impl Drop for PacketRingBlock {
    fn drop(&mut self) {
        #[cfg(not(target_os = "oxide-kernel"))]
        {
            let layout = alloc::alloc::Layout::from_size_align(self.allocation_size, PAGE_SIZE as usize)
                .expect("validated packet ring allocation layout");
            // SAFETY: hosted allocation was returned by alloc_zeroed with this exact layout
            // and remains uniquely owned by this packet-ring block until final drop.
            unsafe { alloc::alloc::dealloc(self.pa as *mut u8, layout) };
            return;
        }
        #[cfg(target_os = "oxide-kernel")]
        {
            if !self.owns_frames { return; }
            for page in 0..self.allocated_pages {
                // SAFETY: each allocation page carries exactly one ring-object
                // reference; VMA PTE references are independently refcounted.
                unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(
                    self.pa + page as u64 * PAGE_SIZE as u64) };
            }
        }
    }
}

pub struct PacketRingMemory {
    layout: PacketRingLayout,
    blocks: Vec<PacketRingBlock>,
    len: u64,
    head: AtomicU32,
}

impl PacketRingMemory {
    fn allocate(layout: PacketRingLayout) -> crate::NetResult<Arc<Self>> {
        let mut blocks = Vec::new();
        blocks.try_reserve_exact(layout.request.block_nr as usize)
            .map_err(|_| crate::NetError::Enomem)?;
        let mapped_pages = layout.request.block_size / PAGE_SIZE;
        let order = mapped_pages.next_power_of_two().trailing_zeros() as u8;
        if order > pmm::MAX_ORDER { return Err(crate::NetError::Enomem); }
        for _ in 0..layout.request.block_nr {
            #[cfg(target_os = "oxide-kernel")]
            let pa = pmm::setup::alloc_contig_object(pmm::Order(order))
                .ok_or(crate::NetError::Enomem)?;
            #[cfg(not(target_os = "oxide-kernel"))]
            let pa = {
                let size = (1usize << order) * PAGE_SIZE as usize;
                let allocation = alloc::alloc::Layout::from_size_align(size, PAGE_SIZE as usize)
                    .map_err(|_| crate::NetError::Enomem)?;
                // SAFETY: validated nonzero power-of-two layout is retained by the block
                // and deallocated only after all ring and mapping owners have disappeared.
                let ptr = unsafe { alloc::alloc::alloc_zeroed(allocation) };
                if ptr.is_null() { return Err(crate::NetError::Enomem); }
                ptr as u64
            };
            #[cfg(target_os = "oxide-kernel")]
            {
                // SAFETY: alloc_contig_object owns this HHDM-backed run exclusively;
                // mapped bytes are initialized before any ring reference is published.
                unsafe { core::ptr::write_bytes(
                    (pmm::user_as::hhdm_offset() + pa) as *mut u8, 0,
                    layout.request.block_size as usize) };
            }
            blocks.push(PacketRingBlock {
                pa, mapped_pages, allocated_pages: 1u32 << order,
                owns_frames: cfg!(target_os = "oxide-kernel"),
                #[cfg(not(target_os = "oxide-kernel"))]
                allocation_size: (1usize << order) * PAGE_SIZE as usize,
            });
        }
        Ok(Arc::new(Self {
            len: layout.request.block_size as u64 * layout.request.block_nr as u64,
            layout, blocks, head: AtomicU32::new(0),
        }))
    }

    /// Return the validated ring contract. # C: O(1)
    pub fn layout(&self) -> PacketRingLayout { self.layout }

    /// Return exact mmap byte length. # C: O(1)
    pub fn len(&self) -> u64 { self.len }

    /// Resolve one page-aligned ring offset to its owned frame. # C: O(blocks)
    pub fn frame(&self, off: u64) -> Option<u64> {
        if off & (PAGE_SIZE as u64 - 1) != 0 || off >= self.len { return None; }
        let mut page = off / PAGE_SIZE as u64;
        for block in &self.blocks {
            if page < block.mapped_pages as u64 {
                return Some(block.pa + page * PAGE_SIZE as u64);
            }
            page -= block.mapped_pages as u64;
        }
        None
    }

    /// Return validated V1/V2 frame count. # C: O(1)
    pub(crate) fn frame_count(&self) -> u32 { self.layout.request.frame_nr }

    /// Read the next kernel receive-frame index. # C: O(1)
    pub(crate) fn head(&self) -> u32 { self.head.load(Ordering::Acquire) }

    /// Advance the kernel receive head with ring wrap. # C: O(1)
    pub(crate) fn advance_head(&self) {
        let next = self.head().wrapping_add(1) % self.frame_count();
        self.head.store(next, Ordering::Release);
    }

    /// Resolve one frame index to its mapped byte offset. # C: O(1)
    pub(crate) fn frame_offset(&self, index: u32) -> Option<u64> {
        if index >= self.frame_count() { return None; }
        let block = index / self.layout.frames_per_block;
        let frame = index % self.layout.frames_per_block;
        Some(block as u64 * self.layout.request.block_size as u64
            + frame as u64 * self.layout.request.frame_size as u64)
    }

    fn byte_ptr(&self, off: u64, len: usize) -> Option<*mut u8> {
        let end = off.checked_add(len as u64)?;
        if end > self.len { return None; }
        let block_index = off / self.layout.request.block_size as u64;
        let block_offset = off % self.layout.request.block_size as u64;
        if block_offset.checked_add(len as u64)? > self.layout.request.block_size as u64 {
            return None;
        }
        let block = self.blocks.get(block_index as usize)?;
        #[cfg(target_os = "oxide-kernel")]
        let address = pmm::user_as::hhdm_offset().checked_add(block.pa)?;
        #[cfg(not(target_os = "oxide-kernel"))]
        let address = block.pa;
        Some((address + block_offset) as *mut u8)
    }

    /// Copy kernel-owned bytes into unpublished ring storage. # C: O(bytes)
    pub(crate) fn write(&self, off: u64, bytes: &[u8]) -> bool {
        if bytes.is_empty() { return true; }
        let Some(destination) = self.byte_ptr(off, bytes.len()) else { return false; };
        for (index, byte) in bytes.iter().enumerate() {
            // SAFETY: byte_ptr validates the whole live mapped range; volatile access
            // preserves shared-memory semantics while userspace may concurrently inspect it.
            unsafe { core::ptr::write_volatile(destination.add(index), *byte) };
        }
        true
    }

    fn status_offset(&self, index: u32) -> Option<u64> {
        let frame = self.frame_offset(index)?;
        if self.layout.version == crate::uapi::TPACKET_V3
            && self.layout.kind == PacketRingKind::Tx
        { frame.checked_add(20) } else { Some(frame) }
    }

    /// Acquire one shared userspace frame status. # C: O(1)
    pub(crate) fn status(&self, index: u32) -> Option<u32> {
        let off = self.status_offset(index)?;
        let ptr = self.byte_ptr(off, packet_status_len(self.layout.version))?;
        // SAFETY: frame starts are 16-byte aligned and status widths are 8/4 bytes;
        // shared userspace ownership transitions require an atomic acquire load.
        let status = unsafe {
            if self.layout.version == crate::uapi::TPACKET_V1 {
                (*(ptr as *const core::sync::atomic::AtomicU64)).load(Ordering::Acquire) as u32
            } else {
                (*(ptr as *const AtomicU32)).load(Ordering::Acquire)
            }
        };
        Some(status)
    }

    /// Release one completed frame status to userspace. # C: O(1)
    pub(crate) fn publish_status(&self, index: u32, status: u32) -> bool {
        let Some(off) = self.status_offset(index) else { return false; };
        let Some(ptr) = self.byte_ptr(off, packet_status_len(self.layout.version)) else { return false; };
        // SAFETY: validated frame alignment satisfies both atomic status layouts;
        // release makes all payload and metadata writes visible before TP_STATUS_USER.
        unsafe {
            if self.layout.version == crate::uapi::TPACKET_V1 {
                (*(ptr as *const core::sync::atomic::AtomicU64)).store(status as u64, Ordering::Release);
            } else {
                (*(ptr as *const AtomicU32)).store(status, Ordering::Release);
            }
        }
        true
    }

    /// Atomically claim one userspace TX frame for kernel transmission. # C: O(1)
    pub(crate) fn claim_status(&self, index: u32, expected: u32, status: u32) -> bool {
        let Some(off) = self.status_offset(index) else { return false; };
        let Some(ptr) = self.byte_ptr(off, packet_status_len(self.layout.version)) else { return false; };
        // SAFETY: validated frame/status alignment satisfies the selected atomic width;
        // compare-exchange linearizes competing userspace and kernel ownership changes.
        unsafe {
            if self.layout.version == crate::uapi::TPACKET_V1 {
                (*(ptr as *const core::sync::atomic::AtomicU64)).compare_exchange(
                    expected as u64, status as u64, Ordering::AcqRel, Ordering::Acquire).is_ok()
            } else {
                (*(ptr as *const AtomicU32)).compare_exchange(
                    expected, status, Ordering::AcqRel, Ordering::Acquire).is_ok()
            }
        }
    }

    /// Acquire one native u32 ownership field by ring offset. # C: O(1)
    pub(crate) fn load_u32(&self, off: u64) -> Option<u32> {
        let ptr = self.byte_ptr(off, core::mem::size_of::<u32>())?;
        // SAFETY: every V3 block status is naturally u32 aligned and mapped;
        // userspace ownership transitions require an atomic acquire load.
        Some(unsafe { (*(ptr as *const AtomicU32)).load(Ordering::Acquire) })
    }

    /// Release one native u32 ownership field by ring offset. # C: O(1)
    pub(crate) fn store_u32(&self, off: u64, value: u32) -> bool {
        let Some(ptr) = self.byte_ptr(off, core::mem::size_of::<u32>()) else { return false; };
        // SAFETY: validated V3 status offsets are naturally u32 aligned;
        // release publishes all block packet and descriptor writes first.
        unsafe { (*(ptr as *const AtomicU32)).store(value, Ordering::Release) };
        true
    }

    /// Copy initialized ring bytes into kernel-owned storage. # C: O(bytes)
    pub(crate) fn copy(&self, off: u64, bytes: &mut [u8]) -> bool {
        if bytes.is_empty() { return true; }
        let Some(source) = self.byte_ptr(off, bytes.len()) else { return false; };
        for (index, byte) in bytes.iter_mut().enumerate() {
            // SAFETY: byte_ptr validates the whole initialized mapped range; volatile
            // reads snapshot memory that hostile userspace may concurrently modify.
            *byte = unsafe { core::ptr::read_volatile(source.add(index)) };
        }
        true
    }

}

fn packet_status_len(version: u8) -> usize {
    if version == crate::uapi::TPACKET_V1 { core::mem::size_of::<u64>() }
    else { core::mem::size_of::<u32>() }
}

pub struct PacketRings {
    pub(crate) rx: Option<Arc<PacketRingMemory>>,
    pub(crate) tx: Option<Arc<PacketRingMemory>>,
    mapped: Arc<AtomicU32>,
    pub(crate) rx_v3: Option<PacketV3State>,
}

impl Default for PacketRings {
    fn default() -> Self {
        Self { rx: None, tx: None, mapped: Arc::new(AtomicU32::new(0)), rx_v3: None }
    }
}

impl PacketRings {
    /// Report whether either socket-owned ring exists. # C: O(1)
    pub(crate) fn busy(&self) -> bool { self.rx.is_some() || self.tx.is_some() }
    /// Borrow the socket-owned receive ring. # C: O(1)
    pub(crate) fn rx(&self) -> Option<&Arc<PacketRingMemory>> { self.rx.as_ref() }
    /// Borrow the socket-owned transmit ring. # C: O(1)
    pub(crate) fn tx(&self) -> Option<&Arc<PacketRingMemory>> { self.tx.as_ref() }
}

pub struct PacketRingMmap {
    pub(crate) rings: Vec<Arc<PacketRingMemory>>,
    mapped: Arc<AtomicU32>,
    len: u64,
}

impl PacketRingMmap {
    /// Return exact combined RX-then-TX mapping length. # C: O(1)
    pub fn len(&self) -> u64 { self.len }

    /// Resolve combined RX-then-TX page offset. # C: O(rings + blocks)
    pub fn frame(&self, mut off: u64) -> Option<u64> {
        for ring in &self.rings {
            if off < ring.len() { return ring.frame(off); }
            off -= ring.len();
        }
        None
    }

}

impl Drop for PacketRingMmap {
    fn drop(&mut self) { self.mapped.fetch_sub(1, Ordering::AcqRel); }
}

fn align(value: u32, alignment: u32) -> Option<u32> {
    value.checked_add(alignment - 1).map(|v| v & !(alignment - 1))
}

/// Return Linux's raw tpacket header size for PACKET_HDRLEN. # C: O(1)
pub fn packet_header_len(version: u8) -> crate::NetResult<u32> {
    match version {
        crate::uapi::TPACKET_V1 => Ok(crate::uapi::TPACKET_V1_HEADER_LEN),
        crate::uapi::TPACKET_V2 => Ok(crate::uapi::TPACKET_V2_HEADER_LEN),
        crate::uapi::TPACKET_V3 => Ok(crate::uapi::TPACKET_V3_HEADER_LEN),
        _ => Err(crate::NetError::Einval),
    }
}

fn ring_header_len(version: u8) -> crate::NetResult<u32> {
    align(packet_header_len(version)?, crate::uapi::TPACKET_ALIGNMENT)
        .and_then(|header| header.checked_add(crate::uapi::SOCKADDR_LL_LEN))
        .ok_or(crate::NetError::Einval)
}

fn validate_layout(kind: PacketRingKind, version: u8, reserve: u32,
                   request: PacketRingRequest) -> crate::NetResult<Option<PacketRingLayout>> {
    if request.block_nr == 0 {
        if request.frame_nr != 0 { return Err(crate::NetError::Einval); }
        return Ok(None);
    }
    if request.block_size == 0 || request.block_size > i32::MAX as u32
        || request.block_size % PAGE_SIZE != 0
    { return Err(crate::NetError::Einval); }
    let min_frame = ring_header_len(version)?.checked_add(reserve)
        .ok_or(crate::NetError::Einval)?;
    if request.frame_size < min_frame
        || request.frame_size % crate::uapi::TPACKET_ALIGNMENT != 0
    { return Err(crate::NetError::Einval); }
    if version == crate::uapi::TPACKET_V3 {
        let private = align(request.private_size, V3_ALIGNMENT)
            .ok_or(crate::NetError::Einval)?;
        let block_min = crate::uapi::TPACKET_V3_BLOCK_HEADER_LEN
            .checked_add(private).and_then(|v| v.checked_add(min_frame))
            .ok_or(crate::NetError::Einval)?;
        if request.block_size < block_min { return Err(crate::NetError::Einval); }
    }
    let frames_per_block = request.block_size / request.frame_size;
    if frames_per_block == 0 || frames_per_block.checked_mul(request.block_nr)
        != Some(request.frame_nr)
    { return Err(crate::NetError::Einval); }
    Ok(Some(PacketRingLayout { kind, version, reserve, request, frames_per_block }))
}

impl InetSocket {
    /// Configure or remove one Linux packet ring. # C: O(blocks)
    pub fn set_packet_ring(&self, kind: PacketRingKind, request: PacketRingRequest)
        -> crate::NetResult<()> {
        let version = self.packet_version()?;
        self.set_packet_ring_versioned(kind, version, request)
    }

    /// Configure a ring parsed for one exact TPACKET ABI version. # C: O(blocks)
    pub fn set_packet_ring_versioned(&self, kind: PacketRingKind, expected_version: u8,
                                     request: PacketRingRequest) -> crate::NetResult<()> {
        let _tx = self.packet_tx.lock();
        loop {
            let (version, reserve) = {
                let rings = self.packet_rings.lock();
                if rings.mapped.load(Ordering::Acquire) != 0 {
                    return Err(crate::NetError::Ebusy);
                }
                let occupied = match kind {
                    PacketRingKind::Rx => rings.rx.is_some(),
                    PacketRingKind::Tx => rings.tx.is_some(),
                };
                if request.block_nr != 0 && occupied { return Err(crate::NetError::Ebusy); }
                let socket = self.kind.lock();
                let SockKind::Packet { options, .. } = &*socket else {
                    return Err(crate::NetError::Enoprotoopt);
                };
                if options.version() != expected_version { return Err(crate::NetError::Einval); }
                (options.version(), options.reserve())
            };
            let layout = validate_layout(kind, version, reserve, request)?;
            let candidate = match layout {
                Some(layout) => Some(PacketRingMemory::allocate(layout)?), None => None,
            };
            if candidate.is_some() && expected_version == crate::uapi::TPACKET_V3
                && kind == PacketRingKind::Tx && (request.retire_block_timeout != 0
                || request.private_size != 0 || request.feature_request != 0)
            { return Err(crate::NetError::Einval); }
            let mut rings = self.packet_rings.lock();
            if rings.mapped.load(Ordering::Acquire) != 0 { return Err(crate::NetError::Ebusy); }
            let socket = self.kind.lock();
            let SockKind::Packet { options, .. } = &*socket else {
                return Err(crate::NetError::Enoprotoopt);
            };
            if options.version() != expected_version { return Err(crate::NetError::Einval); }
            if candidate.is_some() && options.reserve() != reserve {
                drop(socket); drop(rings); continue;
            }
            let slot = match kind {
                PacketRingKind::Rx => &mut rings.rx,
                PacketRingKind::Tx => &mut rings.tx,
            };
            if candidate.is_some() && slot.is_some() { return Err(crate::NetError::Ebusy); }
            *slot = candidate;
            if kind == PacketRingKind::Rx {
                rings.rx_v3 = rings.rx.as_ref().and_then(|ring| {
                    if ring.layout().version == crate::uapi::TPACKET_V3 {
                        Some(PacketV3State::new(ring, packet_monotonic_ns(),
                            vfs::inode_times::realtime_now_ns()))
                    } else { None }
                });
            }
            return Ok(());
        }
    }

    /// Pin the exact combined packet-ring mmap object. # C: O(1)
    pub fn packet_ring_mmap(&self, off: u64, len: u64) -> crate::NetResult<PacketRingMmap> {
        if off != 0 { return Err(crate::NetError::Einval); }
        if !matches!(*self.kind.lock(), SockKind::Packet { .. }) {
            return Err(crate::NetError::Enoprotoopt);
        }
        let rings = self.packet_rings.lock();
        let mut selected = Vec::new();
        if let Some(rx) = rings.rx.as_ref() { selected.push(rx.clone()); }
        if let Some(tx) = rings.tx.as_ref() { selected.push(tx.clone()); }
        let expected = selected.iter().try_fold(0u64, |sum, ring| sum.checked_add(ring.len()))
            .ok_or(crate::NetError::Einval)?;
        if expected == 0 || len != expected { return Err(crate::NetError::Einval); }
        rings.mapped.fetch_add(1, Ordering::AcqRel);
        Ok(PacketRingMmap { rings: selected, mapped: rings.mapped.clone(), len: expected })
    }

    /// Drop socket ownership while mapped VMAs retain page pins. # C: O(1)
    pub(crate) fn release_packet_rings(&self) {
        let _tx = self.packet_tx.lock();
        let mut rings = self.packet_rings.lock();
        rings.rx = None;
        rings.rx_v3 = None;
        rings.tx = None;
    }
}
