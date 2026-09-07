// Image-attributed section objects: the bytes one image section holds, and the
// image-shaped view a map of it produces.
//
// A data section is the file laid out flat. An image section is not: its
// extent is the image's own, every section of the image occupies its own
// relative address inside it, each carries the protection its characteristics
// ask for, and a section's tail past its file bytes is zero-filled address
// space the image legitimately uses. A view that could not be placed at the
// image's preferred base is reported, not refused, because reporting it is
// what lets the loader relocate (`pe::apply_relocations`).
use hal::UserVirtAddr;
use vmm::{AddressSpace, VmaProt};

/// Install each span's own protection over a mapped image view. # C: O(N_spans)
pub fn protect_view(as_: &AddressSpace, base: UserVirtAddr, spans: &[pe::ViewSpan]) -> Result<(), pe::Error> {
    for span in spans {
        if span.size == 0 { continue; }
        let start = base.as_u64().checked_add(span.rva as u64).ok_or(pe::Error::Einval)?;
        let start = UserVirtAddr::new(start).ok_or(pe::Error::Einval)?;
        as_.mprotect(start, span.size as usize, span_protection(span.prot)).map_err(|_| pe::Error::Einval)?;
    }
    Ok(())
}

/// The address-space protection one view span's characteristics ask for. # C: O(1)
pub fn span_protection(prot: pe::SpanProt) -> VmaProt {
    let mut out = VmaProt::empty();
    if prot.read { out |= VmaProt::READ; }
    if prot.write { out |= VmaProt::WRITE; }
    if prot.exec { out |= VmaProt::EXEC; }
    out
}

#[cfg(test)] #[path = "tests/nt_image_section.rs"] mod tests;
