use super::*;

const RECV_PAGE: usize = hal::PAGE_SIZE_BYTES as usize;

/// Snapshot byte returned by hosted TCP test inspection.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg(test)]
pub struct RecvByte { pub byte: u8, pub timestamp_ns: u64 }

/// One page-granular receive segment.  Kernel builds retain the received
/// stream in an object frame; hosted builds retain the identical stream shape
/// in ordinary memory so the TCP state machine stays testable without PMM.
#[derive(Debug)]
struct RecvPage {
    timestamp_ns: u64,
    stamps: VecDeque<(usize, u64)>,
    start: usize,
    len: usize,
    pa: Option<u64>,
    bytes: Vec<u8>,
}

impl RecvPage {
    fn new(payload: &[u8], timestamp_ns: u64) -> Self {
        #[cfg(target_os = "oxide-kernel")]
        {
            if let Some(pa) = pmm::setup::alloc_object_frame() {
                let Some(dst) = pmm::setup::frame_ptr(pa) else {
                    pmm::setup::release_object_frame(pa);
                    return Self { timestamp_ns, stamps: core::iter::once((0, timestamp_ns)).collect(), start: 0, len: payload.len(), pa: None, bytes: payload.to_vec() };
                };
                // SAFETY: `pa` is this receive segment's fresh object frame;
                // `dst` spans its full page and `payload` is capped to it.
                unsafe { core::ptr::copy_nonoverlapping(payload.as_ptr(), dst, payload.len()); }
                return Self { timestamp_ns, stamps: core::iter::once((0, timestamp_ns)).collect(), start: 0, len: payload.len(), pa: Some(pa), bytes: Vec::new() };
            }
            Self { timestamp_ns, stamps: core::iter::once((0, timestamp_ns)).collect(), start: 0, len: payload.len(), pa: None, bytes: payload.to_vec() }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        { Self { timestamp_ns, stamps: core::iter::once((0, timestamp_ns)).collect(), start: 0, len: payload.len(), pa: None, bytes: payload.to_vec() } }
    }

    fn byte(&self, off: usize) -> u8 {
        #[cfg(target_os = "oxide-kernel")]
        {
            let Some(pa) = self.pa else { return self.bytes[self.start + off]; };
            let Some(src) = pmm::setup::frame_ptr(pa) else { return self.bytes[self.start + off]; };
            // SAFETY: `off < len` is established by RecvBuf and `start + off`
            // is inside the object frame this segment owns.
            unsafe { *src.add(self.start + off) }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        { self.bytes[self.start + off] }
    }

    fn release(&mut self) {
        #[cfg(target_os = "oxide-kernel")]
        if let Some(pa) = self.pa.take() { pmm::setup::release_object_frame(pa); }
    }

    fn timestamp(&self) -> u64 {
        self.stamps.iter().filter(|(at, _)| *at <= self.start).last()
            .map(|(_, timestamp)| *timestamp).unwrap_or(self.timestamp_ns)
    }

    fn append(&mut self, payload: &[u8], timestamp_ns: u64) {
        let at = self.start + self.len;
        #[cfg(target_os = "oxide-kernel")]
        if let Some(pa) = self.pa {
            if let Some(dst) = pmm::setup::frame_ptr(pa) {
                // SAFETY: `at + payload.len()` is bounded by this page's free tail.
                unsafe { core::ptr::copy_nonoverlapping(payload.as_ptr(), dst.add(at), payload.len()); }
            }
        } else { self.bytes.extend_from_slice(payload); }
        #[cfg(not(target_os = "oxide-kernel"))]
        self.bytes.extend_from_slice(payload);
        if self.stamps.back().map(|(_, stamp)| *stamp != timestamp_ns).unwrap_or(true) {
            self.stamps.push_back((at, timestamp_ns));
        }
        self.len += payload.len();
    }
}

impl Drop for RecvPage { fn drop(&mut self) { self.release(); } }

/// Canonical TCP receive stream, segmented by the pages that own its bytes.
#[derive(Debug, Default)]
pub struct RecvBuf { pages: VecDeque<RecvPage>, pub len: usize }

impl RecvBuf {
    /// # C: O(1)
    pub(crate) fn is_empty(&self) -> bool { self.len == 0 }

    /// # C: O(payload)
    pub(crate) fn push_payload(&mut self, payload: &[u8], timestamp_ns: u64) {
        let mut payload = payload;
        if let Some(page) = self.pages.back_mut() {
            let used = page.start + page.len;
            if used < RECV_PAGE {
                let take = payload.len().min(RECV_PAGE - used);
                page.append(&payload[..take], timestamp_ns);
                self.len += take;
                payload = &payload[take..];
            }
        }
        for chunk in payload.chunks(RECV_PAGE) {
            let page = RecvPage::new(chunk, timestamp_ns);
            self.len += page.len;
            self.pages.push_back(page);
        }
    }

    /// # C: O(max + pages)
    pub(crate) fn bytes(&self, offset: usize, max: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(max.min(self.len.saturating_sub(offset)));
        let mut skip = offset;
        for page in &self.pages {
            if skip >= page.len { skip -= page.len; continue; }
            let take = (page.len - skip).min(max - out.len());
            for index in 0..take { out.push(page.byte(skip + index)); }
            if out.len() == max { break; }
            skip = 0;
        }
        out
    }

    #[cfg(test)]
    /// Test-only flattened view. Production reads directly from the page-backed
    /// buffer so this allocation cannot enter the receive path. # C: O(recv_buf.len())
    pub(crate) fn iter(&self) -> alloc::vec::IntoIter<RecvByte> {
        let mut out = Vec::with_capacity(self.len);
        for page in &self.pages {
            for offset in 0..page.len {
                out.push(RecvByte { byte: page.byte(offset), timestamp_ns: page.timestamp_ns });
            }
        }
        out.into_iter()
    }

    /// # C: O(pages consumed)
    pub(crate) fn consume(&mut self, mut bytes: usize) {
        bytes = bytes.min(self.len);
        self.len -= bytes;
        while bytes != 0 {
            let page = self.pages.front_mut().unwrap();
            let take = bytes.min(page.len);
            page.start += take;
            page.len -= take;
            bytes -= take;
            if page.len == 0 { self.pages.pop_front(); }
        }
    }

    /// # C: O(pages before offset)
    pub(crate) fn remove(&mut self, mut offset: usize) {
        if offset >= self.len { return; }
        for page in &mut self.pages {
            if offset >= page.len { offset -= page.len; continue; }
            #[cfg(target_os = "oxide-kernel")]
            if let Some(pa) = page.pa {
                if let Some(ptr) = pmm::setup::frame_ptr(pa) {
                    // SAFETY: shift stays inside this owned frame; copy permits overlap.
                    unsafe { core::ptr::copy(ptr.add(page.start + offset + 1), ptr.add(page.start + offset), page.len - offset - 1); }
                }
            } else {
                page.bytes.remove(page.start + offset);
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            { page.bytes.remove(page.start + offset); }
            page.len -= 1;
            self.len -= 1;
            return;
        }
    }

    /// # C: O(1)
    pub(crate) fn timestamp(&self) -> Option<u64> { self.pages.front().map(RecvPage::timestamp) }

    #[cfg(target_os = "oxide-kernel")]
    /// Transfer the object-frame reference of an aligned full-page prefix.
    /// The window becomes the only object owner after this succeeds.
    /// # C: O(1)
    pub(crate) fn take_page(&mut self) -> Option<u64> {
        let page = self.pages.front()?;
        if page.start != 0 || page.len != RECV_PAGE || page.pa.is_none() { return None; }
        let mut page = self.pages.pop_front().unwrap();
        self.len -= RECV_PAGE;
        page.pa.take()
    }
}
