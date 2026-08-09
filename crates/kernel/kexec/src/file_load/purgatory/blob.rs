// The purgatory itself: a self-contained, position-independent 64-bit blob
// assembled into the running kernel and copied out as a segment.
//
// WHY THIS SHAPE, against the reference. The reference builds its purgatory as
// a SEPARATE compilation unit — an ET_REL object with its own flags — embeds
// that object in the kernel, and at load time walks its section headers,
// applies R_X86_64_{64,32,32S,PC32,PLT32} relocations against the address the
// segment will occupy, and then patches three named ELF symbols. This build
// system has no second compilation unit and no ELF relocation pass, so the
// same three objects live at offsets the blob's own layout fixes (`layout.rs`)
// and the code addresses every one of them RIP-relatively. The CONTRACT is
// unchanged: one segment, patched in three places, entered at a fixed address,
// hashing live physical memory at the destinations and halting forever on a
// mismatch. What is lost is the ability to relocate an arbitrary object; what
// is gained is that the shipped bytes are testable (see the tests below, which
// call the blob's own SHA-256 on the host, via `blob/tests.rs`).
//
// POSITION INDEPENDENCE IS NOT OPTIONAL and is not a compiler setting here:
// every memory reference in the code below is `[rip + label]`, and the one
// absolute the machine demands — the GDT base inside the `lgdt` operand — is
// computed at run time with `lea` and stored before the `lgdt`. The reference
// gets that quad filled in by its relocation pass instead.
//
// STATE AT ENTRY (`machine/x86.rs` fixes it): long mode, identity page tables,
// interrupts masked, GDT and IDT limits ZEROED, every general register zero.
// The zeroed GDT limit is why the first thing here is an `lgdt` — any segment
// register load or far transfer before it faults, and there is no IDT to take
// the fault.

#![cfg(target_arch = "x86_64")]

mod asm;

#[cfg(test)]
mod tests;

extern "C" {
    static oxide_purgatory_blob_start: u8;
    static oxide_purgatory_blob_end: u8;
}

/// The assembled purgatory, as the bytes a segment is cut from.
/// # C: O(1)
pub fn bytes() -> &'static [u8] {
    // SAFETY: `bytes` reads only the addresses of the two bound labels the
    // assembler emits around one contiguous blob in one section; the range is
    // kernel image data, mapped for the kernel's whole life.
    let (start, end) = unsafe {
        (&oxide_purgatory_blob_start as *const u8, &oxide_purgatory_blob_end as *const u8)
    };
    // SAFETY: `start..end` is that same emitted range, byte-addressable and
    // never written after link time.
    unsafe { core::slice::from_raw_parts(start, end as usize - start as usize) }
}
