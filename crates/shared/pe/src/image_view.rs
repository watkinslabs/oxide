// Image-shaped view layout: where each part of a PE lands in its mapping,
// with what protection, and how much of it the file supplies.
//
// A view of an image-attributed section is not the file laid out flat. The
// headers and every section occupy their own relative address in the view,
// each carries the protection its section characteristics ask for, and the
// bytes past a section's raw size are address space the file does not supply
// and the mapper must zero.
use alloc::vec::Vec;
use crate::parser::{Error, Image, SectionFlags};

/// Mapping granularity every image view is rounded to.
pub const PAGE_BYTES: u32 = 0x1000;

/// Protection one span of a view is mapped with.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SpanProt { pub read: bool, pub write: bool, pub exec: bool }
impl SpanProt {
    /// Protection the headers span is mapped with. # C: O(1)
    pub const fn headers() -> Self { Self { read: true, write: false, exec: false } }
    /// Protection one section's characteristics ask for. # C: O(1)
    pub const fn of(characteristics: SectionFlags) -> Self {
        Self {
            read: characteristics.contains(SectionFlags::MEM_READ),
            write: characteristics.contains(SectionFlags::MEM_WRITE),
            exec: characteristics.contains(SectionFlags::MEM_EXECUTE),
        }
    }
}

/// One placed span of an image view. `size` is the address space the span
/// occupies; `file_bytes` of it come from the file at `file_offset` and the
/// remainder is zero.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ViewSpan { pub rva: u32, pub size: u32, pub prot: SpanProt, pub file_offset: u32, pub file_bytes: u32 }
impl ViewSpan {
    /// Bytes of this span the file does not supply. # C: O(1)
    pub fn zero_fill(&self) -> u32 { self.size - self.file_bytes }
}

/// A section every view of the image shares writes to, rather than taking a
/// private copy of. Such a section needs a backing store shared between views;
/// a private view of one silently gives each process its own copy.
pub fn shared_writable_sections(image: &Image<'_>) -> usize {
    image.sections.iter()
        .filter(|section| section.characteristics.contains(SectionFlags::MEM_SHARED | SectionFlags::MEM_WRITE))
        .count()
}

/// Alignment an image's spans are rounded to. # C: O(1)
pub fn view_alignment(image: &Image<'_>) -> u32 { image.section_alignment.max(PAGE_BYTES) }

/// Lay out the headers and every section of one image within its view, in
/// ascending relative address. # C: O(N_sections)
pub fn view_layout(image: &Image<'_>) -> Result<Vec<ViewSpan>, Error> {
    let align = view_alignment(image);
    let total = image.size_of_image;
    let mut spans = Vec::new();
    spans.try_reserve_exact(image.sections.len() + 1).map_err(|_| Error::Einval)?;
    let header_size = align_up(image.size_of_headers, align).ok_or(Error::Einval)?;
    if header_size > total { return Err(Error::Einval); }
    spans.push(ViewSpan { rva: 0, size: header_size, prot: SpanProt::headers(), file_offset: 0, file_bytes: image.size_of_headers });
    for section in &image.sections {
        let span = if section.virtual_size != 0 { section.virtual_size } else { section.raw_size };
        let size = align_up(span, align).ok_or(Error::Einval)?;
        if size == 0 { continue; }
        let end = section.virtual_address.checked_add(size).ok_or(Error::Einval)?;
        if section.virtual_address > total || end > total { return Err(Error::Einval); }
        let file_bytes = if section.raw_offset == 0 { 0 } else { section.raw_size.min(size) };
        spans.push(ViewSpan {
            rva: section.virtual_address, size, prot: SpanProt::of(section.characteristics),
            file_offset: section.raw_offset, file_bytes,
        });
    }
    Ok(spans)
}

/// Build the byte image one view maps: every span at its own relative address,
/// each span's tail past its file bytes zero. # C: O(SizeOfImage)
pub fn materialize_view(image: &Image<'_>) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(image.size_of_image as usize).map_err(|_| Error::Einval)?;
    out.resize(image.size_of_image as usize, 0);
    for span in view_layout(image)? {
        if span.file_bytes == 0 { continue; }
        let at = span.rva as usize;
        let to = at.checked_add(span.file_bytes as usize).ok_or(Error::Einval)?;
        let from = span.file_offset as usize;
        let from_end = from.checked_add(span.file_bytes as usize).ok_or(Error::Einval)?;
        out.get_mut(at..to).ok_or(Error::Einval)?
            .copy_from_slice(image.raw.get(from..from_end).ok_or(Error::Einval)?);
    }
    Ok(out)
}

fn align_up(value: u32, align: u32) -> Option<u32> { value.checked_add(align - 1).map(|v| v & !(align - 1)) }

/// Everything an image-attributed section object retains about its image: the
/// byte image one view maps, where each span of it goes, the record a section
/// query answers with, and the base the image asked for.
pub struct ImageSection {
    pub bytes: alloc::sync::Arc<[u8]>, pub spans: Vec<ViewSpan>,
    pub information: crate::image_info::ImageInformation, pub preferred_base: u64, pub entry_rva: u32,
}

impl ImageSection {
    /// The section extent, which for an image is SizeOfImage. # C: O(1)
    pub fn size(&self) -> usize { self.bytes.len() }
    /// Whether a view based here sits at the image's preferred base. # C: O(1)
    pub fn at_preferred_base(&self, base: u64) -> bool { base == self.preferred_base }
    /// The image information a query of a view based here reports. # C: O(1)
    pub fn information_at(&self, base: u64) -> crate::image_info::ImageInformation {
        self.information.at_base(base, self.entry_rva)
    }
    /// The widest protection any span of this view asks for. # C: O(N_spans)
    pub fn max_prot(&self) -> SpanProt {
        self.spans.iter().fold(SpanProt { read: false, write: false, exec: false }, |acc, span| SpanProt {
            read: acc.read || span.prot.read, write: acc.write || span.prot.write, exec: acc.exec || span.prot.exec,
        })
    }
}

/// Build the image section one file's bytes describe. # C: O(SizeOfImage)
pub fn image_section(blob: &[u8], file_size: u64) -> Result<ImageSection, Error> {
    let parsed = crate::parser::parse(blob)?;
    let information = crate::image_info::image_information(&parsed, file_size)?;
    let spans = view_layout(&parsed)?;
    let bytes: alloc::sync::Arc<[u8]> = materialize_view(&parsed)?.into();
    Ok(ImageSection { bytes, spans, information, preferred_base: parsed.image_base, entry_rva: parsed.entry_rva })
}
