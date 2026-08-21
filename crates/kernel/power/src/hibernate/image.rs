// Persistent hibernation image transaction per `32b§8`.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::RefCell;

use super::format::{self, Header, Page, MAP_ENTRIES};
use super::bitmap::Bitmap;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Io, NoImage, SwapSignature, Format, Unsupported, Bounds, Cycle, Duplicate,
    PrematureEnd, TrailingEntry, Checksum,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Compression { None, Lzo, Lz4 }

/// Page-addressed persistence used by image I/O. The production adapter owns
/// block-size conversion and maps `commit_page` to preflush/FUA.
pub trait Storage {
    type Error;
    /// Number of addressable image pages. # C: O(1)
    fn page_count(&self) -> u64;
    /// Read one complete page. # C: one device read
    fn read_page(&mut self, page: u64, out: &mut Page) -> Result<(), Self::Error>;
    /// Write one page without claiming it is durable yet. # C: one device write
    fn write_page(&mut self, page: u64, data: &Page) -> Result<(), Self::Error>;
    /// Make every preceding ordinary write durable. # C: one device flush
    fn flush(&mut self) -> Result<(), Self::Error>;
    /// Durably replace one page after a preflush, with FUA semantics. # C: one durable write
    fn commit_page(&mut self, page: u64, data: &Page) -> Result<(), Self::Error>;
}

/// Borrowed logical image stream; implementations reuse `out` per page.
pub trait PageSource {
    /// Logical page count. # C: O(1)
    fn len(&self) -> usize;
    /// Whether this source is empty. # C: O(1)
    fn is_empty(&self) -> bool { self.len() == 0 }
    /// Materialize one logical page into caller-owned storage. # C: O(PAGE_SIZE)
    fn read_page(&self, index: usize, out: &mut Page) -> Result<(), Error>;
}

impl PageSource for [Page] {
    fn len(&self) -> usize { <[Page]>::len(self) }
    fn read_page(&self, index: usize, out: &mut Page) -> Result<(), Error> {
        *out = *self.get(index).ok_or(Error::Bounds)?;
        Ok(())
    }
}

impl<const N: usize> PageSource for [Page; N] {
    fn len(&self) -> usize { N }
    fn read_page(&self, index: usize, out: &mut Page) -> Result<(), Error> {
        self.as_slice().read_page(index, out)
    }
}

impl PageSource for Vec<Page> {
    fn len(&self) -> usize { Vec::len(self) }
    fn read_page(&self, index: usize, out: &mut Page) -> Result<(), Error> {
        self.as_slice().read_page(index, out)
    }
}

pub struct Plan<'a> {
    pub header_page: u64,
    pub map_pages: &'a [u64],
    pub data_pages: &'a [u64],
}

/// Reserved physical payload pages required for a selected logical stream. # C: O(1)
pub fn max_stored_pages(logical_pages: usize, compression: Compression) -> Result<usize, Error> {
    if logical_pages == 0 { return Err(Error::Bounds); }
    if compression == Compression::None { return Ok(logical_pages); }
    let full = logical_pages / super::codec::CHUNK_PAGES;
    let tail = logical_pages % super::codec::CHUNK_PAGES;
    let framed = |pages: usize| pages.checked_mul(format::PAGE_SIZE).ok_or(Error::Bounds)
        .map(super::codec::worst_size)?
        .checked_add(super::codec::LENGTH_BYTES).ok_or(Error::Bounds)
        .map(|bytes| bytes.div_ceil(format::PAGE_SIZE));
    let mut capacity = full.checked_mul(framed(super::codec::CHUNK_PAGES)?).ok_or(Error::Bounds)?;
    if tail != 0 { capacity = capacity.checked_add(framed(tail)?).ok_or(Error::Bounds)?; }
    Ok(capacity)
}

pub struct ImageReader {
    pub header: Header,
    locators: Vec<u64>,
    chunks: Vec<Chunk>,
    workspace: Option<RefCell<super::codec::Decoder>>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OpenFailure { pub error: Error, pub marker_consumed: bool }

struct Chunk { locator: usize, encoded: usize, logical: usize, pages: usize }

/// Staged payload/map transaction whose marker is not yet visible.
pub struct PreparedMarker { header_page: u64, page: Box<Page> }

fn unique_locations(capacity: u64, plan: &Plan<'_>) -> Result<(), Error> {
    if plan.header_page >= capacity { return Err(Error::Bounds); }
    if plan.data_pages.is_empty() || plan.map_pages.len() != plan.data_pages.len().div_ceil(MAP_ENTRIES) { return Err(Error::Bounds); }
    let mut seen = Bitmap::new(capacity).map_err(|_| Error::Bounds)?;
    seen.claim(plan.header_page).map_err(|_| Error::Bounds)?;
    for page in plan.map_pages.iter().chain(plan.data_pages.iter()) {
        if *page == 0 || *page >= capacity { return Err(Error::Bounds); }
        if !seen.claim(*page).map_err(|_| Error::Bounds)? { return Err(Error::Duplicate); }
    }
    Ok(())
}

/// Persist payload and maps without publishing the valid-image marker. # C: O(image pages)
pub fn stage_image<S: Storage, P: PageSource + ?Sized>(store: &mut S, plan: &Plan<'_>,
        mut header: Header, pages: &P, compression: Compression) -> Result<PreparedMarker, Error> {
    if pages.is_empty() || compression == Compression::None && pages.len() != plan.data_pages.len() {
        return Err(Error::Bounds);
    }
    unique_locations(store.page_count(), plan)?;
    let mut swap = super::scratch::zeroed::<u8, { format::PAGE_SIZE }>().ok_or(Error::Bounds)?;
    super::log::serialize_phase(super::log::SerializePhase::HeaderRead,
        super::log::SerializeBoundary::Begin);
    store.read_page(plan.header_page, &mut swap).map_err(|_| Error::Io)?;
    super::log::serialize_phase(super::log::SerializePhase::HeaderRead,
        super::log::SerializeBoundary::End);
    if !format::is_swap_header(&swap) { return Err(Error::SwapSignature); }
    let mut checksum = 0;
    super::log::serialize_work(super::log::SerializeWork::PageScratch,
        super::log::SerializeBoundary::Begin, 0, format::PAGE_SIZE);
    let mut page = super::scratch::zeroed::<u8, { format::PAGE_SIZE }>().ok_or(Error::Bounds)?;
    super::log::serialize_work(super::log::SerializeWork::PageScratch,
        super::log::SerializeBoundary::End, 0, format::PAGE_SIZE);
    let mut stored = 0usize;
    match compression {
        Compression::None => for (index, locator) in plan.data_pages.iter().enumerate() {
            pages.read_page(index, &mut page)?;
            checksum = format::crc32(checksum, &page);
            store.write_page(*locator, &page).map_err(|_| Error::Io)?;
            stored += 1;
        },
        Compression::Lzo | Compression::Lz4 => {
            super::log::serialize_work(super::log::SerializeWork::Input,
                super::log::SerializeBoundary::Begin, 0, super::codec::CHUNK_BYTES);
            let mut input = Vec::with_capacity(super::codec::CHUNK_BYTES);
            super::log::serialize_work(super::log::SerializeWork::Input,
                super::log::SerializeBoundary::End, 0, input.capacity());
            super::log::serialize_work(super::log::SerializeWork::Encoder,
                super::log::SerializeBoundary::Begin, 0, super::codec::CHUNK_BYTES);
            let mut encoder = super::codec::Encoder::new();
            super::log::serialize_work(super::log::SerializeWork::Encoder,
                super::log::SerializeBoundary::End, 0, super::codec::CHUNK_BYTES);
            let mut first = 0usize;
            while first < pages.len() {
                let count = core::cmp::min(super::codec::CHUNK_PAGES, pages.len() - first);
                if first == 0 { super::log::serialize_work(super::log::SerializeWork::Chunk,
                    super::log::SerializeBoundary::Begin, first, count); }
                input.clear();
                for index in first..first + count {
                    if first == 0 { super::log::serialize_work(super::log::SerializeWork::Source,
                        super::log::SerializeBoundary::Begin, index, 0); }
                    pages.read_page(index, &mut page)?;
                    if first == 0 { super::log::serialize_work(super::log::SerializeWork::Source,
                        super::log::SerializeBoundary::End, index, 0);
                        super::log::serialize_work(super::log::SerializeWork::Crc,
                            super::log::SerializeBoundary::Begin, index, 0); }
                    checksum = format::crc32(checksum, &page);
                    if first == 0 { super::log::serialize_work(super::log::SerializeWork::Crc,
                        super::log::SerializeBoundary::End, index, checksum as usize);
                        super::log::serialize_work(super::log::SerializeWork::Append,
                            super::log::SerializeBoundary::Begin, index, input.len()); }
                    input.extend_from_slice(&*page);
                    if first == 0 { super::log::serialize_work(super::log::SerializeWork::Append,
                        super::log::SerializeBoundary::End, index, input.len()); }
                }
                if first == 0 { super::log::serialize_work(super::log::SerializeWork::Encode,
                    super::log::SerializeBoundary::Begin, first, input.len()); }
                let encoded = encoder.encode(compression, &input)?;
                if first == 0 { super::log::serialize_work(super::log::SerializeWork::Encode,
                    super::log::SerializeBoundary::End, first, encoded.len());
                    super::log::serialize_work(super::log::SerializeWork::Chunk,
                        super::log::SerializeBoundary::End, first, encoded.len()); }
                let framed = encoded.len().checked_add(super::codec::LENGTH_BYTES).ok_or(Error::Bounds)?;
                let physical = framed.div_ceil(format::PAGE_SIZE);
                if stored.checked_add(physical).ok_or(Error::Bounds)? > plan.data_pages.len() {
                    return Err(Error::Bounds);
                }
                for physical_index in 0..physical {
                    page.fill(0);
                    if physical_index == 0 {
                        page[..super::codec::LENGTH_BYTES].copy_from_slice(&(encoded.len() as u64).to_le_bytes());
                    }
                    let frame_start = physical_index * format::PAGE_SIZE;
                    let encoded_start = frame_start.saturating_sub(super::codec::LENGTH_BYTES);
                    let page_start = if physical_index == 0 { super::codec::LENGTH_BYTES } else { 0 };
                    let count = core::cmp::min(format::PAGE_SIZE - page_start,
                        encoded.len().saturating_sub(encoded_start));
                    page[page_start..page_start + count]
                        .copy_from_slice(&encoded[encoded_start..encoded_start + count]);
                    store.write_page(plan.data_pages[stored], &page).map_err(|_| Error::Io)?;
                    stored += 1;
                }
                first += count;
            }
        }
    }
    let maps = stored.div_ceil(MAP_ENTRIES);
    for (i, locator) in plan.map_pages[..maps].iter().enumerate() {
        let start = i * MAP_ENTRIES;
        let end = core::cmp::min(start + MAP_ENTRIES, stored);
        let next = plan.map_pages.get(i + 1).filter(|_| i + 1 < maps).copied().unwrap_or(0);
        format::encode_map_into(&mut page, &plan.data_pages[start..end], next)
            .map_err(|_| Error::Format)?;
        store.write_page(*locator, &page).map_err(|_| Error::Io)?;
    }
    store.flush().map_err(|_| Error::Io)?;
    header.flags = match compression {
        Compression::None => format::FLAG_NOCOMPRESS | format::FLAG_CRC32,
        Compression::Lzo => format::FLAG_CRC32,
        Compression::Lz4 => format::FLAG_CRC32 | format::FLAG_LZ4,
    };
    header.checksum = checksum;
    header.first_map = plan.map_pages[0];
    header.stream_pages = pages.len() as u64;
    if header.image_pages == 0 { header.image_pages = header.stream_pages; }
    if header.zero_pages > header.image_pages { return Err(Error::Format); }
    format::mark(&mut swap, &header).map_err(|_| Error::Format)?;
    Ok(PreparedMarker { header_page: plan.header_page, page: swap })
}

/// Publish one fully staged marker with preflush/FUA semantics. # C: one durable write
pub fn commit_image<S: Storage>(store: &mut S, marker: PreparedMarker) -> Result<(), Error> {
    store.commit_page(marker.header_page, &*marker.page).map_err(|_| Error::Io)
}

/// Durably establish an unmarked swap header after a possibly-published abort.
///
/// This is deliberately idempotent: a failed PREFLUSH|FUA marker commit may
/// have failed before or after publication. In either case the currently
/// visible swap header is committed again with FUA, so success is proof of a
/// durable non-marker rather than a guess about the failed command.
/// # C: one read + one durable write
pub fn unmark_image<S: Storage>(store: &mut S, header_page: u64) -> Result<(), Error> {
    let mut page = super::scratch::zeroed::<u8, { format::PAGE_SIZE }>().ok_or(Error::Bounds)?;
    store.read_page(header_page, &mut page).map_err(|_| Error::Io)?;
    if format::is_marked(&page) {
        format::consume(&mut page).map_err(|_| Error::Format)?;
    } else if !format::is_swap_header(&page) {
        return Err(Error::Format);
    }
    store.commit_page(header_page, &page).map_err(|_| Error::Io)
}

/// Stage and publish an image using the selected stream codec. # C: O(image pages)
pub fn write_image_with<S: Storage, P: PageSource + ?Sized>(store: &mut S, plan: &Plan<'_>,
        header: Header, pages: &P, compression: Compression) -> Result<(), Error> {
    let marker = stage_image(store, plan, header, pages, compression)?;
    commit_image(store, marker)
}

/// Mandatory uncompressed+CRC convenience path. # C: O(image pages)
pub fn write_image<S: Storage, P: PageSource + ?Sized>(store: &mut S, plan: &Plan<'_>, header: Header,
                                                       pages: &P) -> Result<(), Error> {
    write_image_with(store, plan, header, pages, Compression::None)
}

impl ImageReader {
    /// Consume a valid marker durably, then validate and retain its map. # C: O(image pages)
    pub fn open<S: Storage>(store: &mut S, header_page: u64) -> Result<Self, Error> {
        Self::open_report(store, header_page).map_err(|failure| failure.error)
    }

    /// Open with exact durable marker-consumption status for rejection logs.
    /// # C: O(image pages)
    pub fn open_report<S: Storage>(store: &mut S, header_page: u64)
        -> Result<Self, OpenFailure>
    {
        let mut marker_consumed = false;
        Self::open_inner(store, header_page, &mut marker_consumed)
            .map_err(|error| OpenFailure { error, marker_consumed })
    }

    fn open_inner<S: Storage>(store: &mut S, header_page: u64,
        marker_consumed: &mut bool) -> Result<Self, Error>
    {
        if header_page >= store.page_count() { return Err(Error::Bounds); }
        let mut raw = super::scratch::zeroed::<u8, { format::PAGE_SIZE }>().ok_or(Error::Bounds)?;
        store.read_page(header_page, &mut raw).map_err(|_| Error::Io)?;
        if !format::is_marked(&raw) { return Err(Error::NoImage); }
        format::consume(&mut raw).map_err(|_| Error::Format)?;
        store.commit_page(header_page, &raw).map_err(|_| Error::Io)?;
        *marker_consumed = true;
        let header = format::decode(&raw).map_err(|e| match e {
            format::FormatError::Flags => Error::Unsupported,
            _ => Error::Format,
        })?;
        let compression = format::compression(header.flags).map_err(|_| Error::Unsupported)?;
        if header.stream_pages >= store.page_count() { return Err(Error::Bounds); }
        let count = usize::try_from(header.stream_pages).map_err(|_| Error::Bounds)?;
        if count == 0 || header.first_map == 0 { return Err(Error::Bounds); }
        let mut occupied = Bitmap::new(store.page_count()).map_err(|_| Error::Bounds)?;
        let mut maps = Bitmap::new(store.page_count()).map_err(|_| Error::Bounds)?;
        occupied.claim(header_page).map_err(|_| Error::Bounds)?;
        let mut locators = Vec::new();
        let mut map_locator = header.first_map;
        while map_locator != 0 {
            if map_locator >= store.page_count() { return Err(Error::Bounds); }
            if maps.contains(map_locator) { return Err(Error::Cycle); }
            if !occupied.claim(map_locator).map_err(|_| Error::Bounds)? {
                return Err(Error::Duplicate);
            }
            maps.claim(map_locator).map_err(|_| Error::Bounds)?;
            let mut page = super::scratch::zeroed::<u8, { format::PAGE_SIZE }>().ok_or(Error::Bounds)?;
            store.read_page(map_locator, &mut page).map_err(|_| Error::Io)?;
            let mut ended = false;
            for index in 0..format::MAP_ENTRIES {
                let entry = format::map_entry(&page, index).unwrap();
                if entry == 0 { ended = true; continue; }
                if ended { return Err(Error::TrailingEntry); }
                if entry >= store.page_count() || entry == header_page { return Err(Error::Bounds); }
                if !occupied.claim(entry).map_err(|_| Error::Bounds)? {
                    return Err(Error::Duplicate);
                }
                locators.push(entry);
            }
            let next = format::map_next(&page);
            if ended && next != 0 { return Err(Error::TrailingEntry); }
            map_locator = next;
        }
        if locators.is_empty() { return Err(Error::PrematureEnd); }
        let workspace = if compression == Compression::None { None }
            else { Some(RefCell::new(super::codec::Decoder::new())) };
        let mut reader = Self { header, locators, chunks: Vec::new(), workspace };
        match compression {
            Compression::None => {
                if reader.locators.len() < count { return Err(Error::PrematureEnd); }
                if reader.locators.len() > count { return Err(Error::TrailingEntry); }
            }
            Compression::Lzo | Compression::Lz4 => reader.scan_chunks(store, compression)?,
        }
        Ok(reader)
    }

    /// Number of logical image pages. # C: O(1)
    pub fn len(&self) -> usize { self.header.stream_pages as usize }

    /// Whether the image stream is empty. # C: O(1)
    pub fn is_empty(&self) -> bool { self.header.stream_pages == 0 }

    /// Read one logical image page. # C: one device read
    pub fn read_page<S: Storage>(&self, store: &mut S, index: usize, out: &mut Page) -> Result<(), Error> {
        if index >= self.len() { return Err(Error::Bounds); }
        match format::compression(self.header.flags).map_err(|_| Error::Unsupported)? {
            Compression::None => store.read_page(self.locators[index], out).map_err(|_| Error::Io),
            compression => {
                let chunk = self.chunks.iter().find(|chunk|
                    index >= chunk.logical && index < chunk.logical + chunk.pages).ok_or(Error::Bounds)?;
                let mut workspace = self.workspace.as_ref().ok_or(Error::Format)?.borrow_mut();
                let decoded = Self::read_chunk(&self.locators, store, chunk, compression, &mut workspace)?;
                let start = (index - chunk.logical) * format::PAGE_SIZE;
                out.copy_from_slice(&decoded[start..start + format::PAGE_SIZE]);
                Ok(())
            }
        }
    }

    /// Check the uncompressed logical stream checksum without retaining it. # C: O(image pages)
    pub fn verify_checksum<S: Storage>(&self, store: &mut S) -> Result<(), Error> {
        let mut crc = 0;
        let mut page = super::scratch::zeroed::<u8, { format::PAGE_SIZE }>().ok_or(Error::Bounds)?;
        match format::compression(self.header.flags).map_err(|_| Error::Unsupported)? {
            Compression::None => for locator in &self.locators {
                store.read_page(*locator, &mut page).map_err(|_| Error::Io)?;
                crc = format::crc32(crc, &page);
            },
            compression => {
                let mut workspace = self.workspace.as_ref().ok_or(Error::Format)?.borrow_mut();
                for chunk in &self.chunks {
                let decoded = Self::read_chunk(&self.locators, store, chunk, compression,
                    &mut workspace)?;
                for logical in decoded.chunks_exact(format::PAGE_SIZE) {
                    page.copy_from_slice(logical);
                    crc = format::crc32(crc, &page);
                }
                }
            },
        }
        if crc != self.header.checksum { return Err(Error::Checksum); }
        Ok(())
    }

    fn scan_chunks<S: Storage>(&mut self, store: &mut S, compression: Compression) -> Result<(), Error> {
        let expected = usize::try_from(self.header.stream_pages).map_err(|_| Error::Bounds)?;
        let workspace = self.workspace.as_ref().ok_or(Error::Format)?;
        let mut workspace = workspace.borrow_mut();
        let mut locator = 0usize;
        let mut logical = 0usize;
        while logical < expected {
            let mut first = super::scratch::zeroed::<u8, { format::PAGE_SIZE }>().ok_or(Error::Bounds)?;
            let first_locator = *self.locators.get(locator).ok_or(Error::PrematureEnd)?;
            store.read_page(first_locator, &mut first).map_err(|_| Error::Io)?;
            let encoded = u64::from_le_bytes(first[..super::codec::LENGTH_BYTES].try_into().unwrap());
            let encoded = usize::try_from(encoded).map_err(|_| Error::Format)?;
            if encoded == 0 || encoded > super::codec::worst_size(super::codec::CHUNK_BYTES) {
                return Err(Error::Format);
            }
            let physical = encoded.checked_add(super::codec::LENGTH_BYTES).ok_or(Error::Format)?
                .div_ceil(format::PAGE_SIZE);
            if locator.checked_add(physical).ok_or(Error::Bounds)? > self.locators.len() {
                return Err(Error::PrematureEnd);
            }
            let provisional = Chunk { locator, encoded, logical, pages: 0 };
            let decoded = Self::read_chunk(&self.locators, store, &provisional, compression,
                &mut workspace)?;
            let pages = decoded.len() / format::PAGE_SIZE;
            if logical.checked_add(pages).ok_or(Error::Bounds)? > expected { return Err(Error::TrailingEntry); }
            self.chunks.push(Chunk { locator, encoded, logical, pages });
            logical += pages;
            locator += physical;
        }
        if logical != expected { return Err(Error::PrematureEnd); }
        if locator != self.locators.len() { return Err(Error::TrailingEntry); }
        Ok(())
    }

    fn read_chunk<'a, S: Storage>(locators: &[u64], store: &mut S, chunk: &Chunk,
            compression: Compression, workspace: &'a mut super::codec::Decoder) -> Result<&'a [u8], Error> {
        let physical = chunk.encoded.checked_add(super::codec::LENGTH_BYTES).ok_or(Error::Format)?
            .div_ceil(format::PAGE_SIZE);
        workspace.begin(chunk.encoded)?;
        let mut page = super::scratch::zeroed::<u8, { format::PAGE_SIZE }>().ok_or(Error::Bounds)?;
        for index in 0..physical {
            let locator = *locators.get(chunk.locator + index).ok_or(Error::PrematureEnd)?;
            store.read_page(locator, &mut page).map_err(|_| Error::Io)?;
            let start = if index == 0 {
                let persisted = u64::from_le_bytes(page[..super::codec::LENGTH_BYTES].try_into().unwrap());
                if usize::try_from(persisted).ok() != Some(chunk.encoded) { return Err(Error::Format); }
                super::codec::LENGTH_BYTES
            } else { 0 };
            let count = core::cmp::min(format::PAGE_SIZE - start,
                chunk.encoded - workspace.encoded_len());
            workspace.push(&page[start..start + count])?;
        }
        if workspace.encoded_len() != chunk.encoded { return Err(Error::PrematureEnd); }
        workspace.decode(compression)
    }
}

#[cfg(test)]
#[path = "image/tests.rs"]
mod tests;
