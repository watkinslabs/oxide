// An independent parser for the images the builder produces.
//
// Written from the format rather than from the builder, so a case that reads a
// field back is checking the file, not restating the code that wrote it.

use alloc::vec::Vec;

use crate::coredump::elf::uapi::{EHDR64_BYTES, NOTE_ALIGN, NOTE_HDR_BYTES, PHDR64_BYTES};

pub struct Image<'a> { pub bytes: &'a [u8] }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Phdr {
    pub ty: u32, pub flags: u32, pub offset: u64, pub vaddr: u64, pub paddr: u64,
    pub filesz: u64, pub memsz: u64, pub align: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note { pub name: Vec<u8>, pub ty: u32, pub desc: Vec<u8> }

fn rd16(b: &[u8], o: usize) -> u16 { u16::from_le_bytes([b[o], b[o + 1]]) }
fn rd32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn rd64(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }

impl<'a> Image<'a> {
    pub fn new(bytes: &'a [u8]) -> Self { Image { bytes } }

    pub fn ident(&self) -> &[u8] { &self.bytes[..16] }
    pub fn e_type(&self) -> u16 { rd16(self.bytes, 16) }
    pub fn e_machine(&self) -> u16 { rd16(self.bytes, 18) }
    pub fn e_version(&self) -> u32 { rd32(self.bytes, 20) }
    pub fn e_entry(&self) -> u64 { rd64(self.bytes, 24) }
    pub fn e_phoff(&self) -> u64 { rd64(self.bytes, 32) }
    pub fn e_shoff(&self) -> u64 { rd64(self.bytes, 40) }
    pub fn e_flags(&self) -> u32 { rd32(self.bytes, 48) }
    pub fn e_ehsize(&self) -> u16 { rd16(self.bytes, 52) }
    pub fn e_phentsize(&self) -> u16 { rd16(self.bytes, 54) }
    pub fn e_phnum(&self) -> u16 { rd16(self.bytes, 56) }
    pub fn e_shentsize(&self) -> u16 { rd16(self.bytes, 58) }
    pub fn e_shnum(&self) -> u16 { rd16(self.bytes, 60) }
    pub fn e_shstrndx(&self) -> u16 { rd16(self.bytes, 62) }

    /// Program header `i`, read at the offset and stride the header publishes.
    pub fn phdr(&self, i: usize) -> Phdr {
        let o = self.e_phoff() as usize + i * self.e_phentsize() as usize;
        Phdr {
            ty: rd32(self.bytes, o), flags: rd32(self.bytes, o + 4),
            offset: rd64(self.bytes, o + 8), vaddr: rd64(self.bytes, o + 16),
            paddr: rd64(self.bytes, o + 24), filesz: rd64(self.bytes, o + 32),
            memsz: rd64(self.bytes, o + 40), align: rd64(self.bytes, o + 48),
        }
    }

    /// Real program-header count: the escape moves it into `sh_info` of the
    /// section header at index 0.
    pub fn phdr_count(&self) -> u64 {
        let n = self.e_phnum();
        if n != crate::coredump::elf::uapi::PN_XNUM { return n as u64 }
        rd32(self.bytes, self.e_shoff() as usize + 44) as u64
    }

    pub fn phdrs(&self) -> Vec<Phdr> {
        (0..self.phdr_count() as usize).map(|i| self.phdr(i)).collect()
    }

    /// The `PT_NOTE` segment's contents, split back into notes.
    pub fn notes(&self) -> Vec<Note> {
        let ph = self.phdrs();
        let n = ph.iter().find(|p| p.ty == crate::coredump::elf::uapi::PT_NOTE).expect("PT_NOTE");
        let seg = &self.bytes[n.offset as usize..(n.offset + n.filesz) as usize];
        let mut out = Vec::new();
        let mut o = 0usize;
        while o + NOTE_HDR_BYTES <= seg.len() {
            let namesz = rd32(seg, o) as usize;
            let descsz = rd32(seg, o + 4) as usize;
            let ty = rd32(seg, o + 8);
            let name_off = o + NOTE_HDR_BYTES;
            let desc_off = name_off + round_up(namesz, NOTE_ALIGN);
            // The name carries a terminator the note's owner string does not.
            let name = seg[name_off..name_off + namesz - 1].to_vec();
            let desc = seg[desc_off..desc_off + descsz].to_vec();
            out.push(Note { name, ty, desc });
            o = desc_off + round_up(descsz, NOTE_ALIGN);
        }
        out
    }

    pub fn note(&self, ty: u32) -> Note {
        self.notes().into_iter().find(|n| n.ty == ty).expect("note present")
    }

    pub fn header_bytes(&self) -> u64 {
        EHDR64_BYTES as u64 + self.phdr_count() * PHDR64_BYTES as u64
    }
}

pub fn round_up(v: usize, a: usize) -> usize { (v + a - 1) / a * a }
