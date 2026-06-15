// Build a link-map entry from a mapped object (docs/59§5). Given a load bias,
// the image end (from loader::map_object), and the object's _DYNAMIC, parse
// the dynamic tags and expose its symtab/strtab/hash/version tables as byte
// windows for the resolver. d_ptr-class tags are link-time vaddrs; runtime
// address = base + d_val for both the kernel-mapped app and rtld-mapped libs.
// Freestanding (raw memory); the mmap lives for the process so the windows
// are valid for the whole link/run.
#![cfg(feature = "freestanding")]
use crate::dynamic::{self, Dyn, DynInfo};
use crate::linkmap::ObjView;
use crate::symbol::SymView;
use core::slice::from_raw_parts;

pub struct OwnedObj {
    pub base: u64,
    pub image_end: u64,
    pub info: DynInfo,
}

/// Parse a mapped object's _DYNAMIC into an OwnedObj.
/// # C: dynamic::parse_ptr(base + dyn) + record base/end
pub unsafe fn build_objview(base: u64, image_end: u64, dyn_ptr: *const Dyn) -> OwnedObj {
    // SAFETY: dyn_ptr is the object's runtime _DYNAMIC; parse_ptr walks it to
    // DT_NULL within the mapping.
    unsafe { OwnedObj { base, image_end, info: dynamic::parse_ptr(dyn_ptr) } }
}

impl OwnedObj {
    /// Borrow this object's tables as an ObjView. Slices reference the live
    /// mapping (valid for the process); bounded by the image end so no read
    /// leaves the mapping.
    ///
    /// # C: ObjView over base+vaddr windows (strtab by STRSZ, rest to img end)
    pub unsafe fn view(&self) -> ObjView<'static> {
        // SAFETY: every window starts at base+vaddr inside the mapping and is
        // bounded by the image end (strtab by its exact STRSZ); the tables'
        // own counts keep lookups in-range.
        unsafe {
            let b = self.base;
            let end = self.image_end;
            let to_end = |v: u64| from_raw_parts((b + v) as *const u8, (end - (b + v)) as usize);
            let strtab = self.info.strtab.map(|v| from_raw_parts((b + v) as *const u8, self.info.strsz as usize)).unwrap_or(&[]);
            let symtab = self.info.symtab.map(|v| {
                let start = b + v;
                let send = self.info.strtab.map(|s| b + s).filter(|&s| s > start).unwrap_or(end);
                from_raw_parts(start as *const u8, (send - start) as usize)
            }).unwrap_or(&[]);
            ObjView {
                base: b,
                gnu_hash: self.info.gnu_hash.map(to_end),
                sysv_hash: self.info.hash.map(to_end),
                sym: SymView { symtab, strtab },
                versym: self.info.versym.map(to_end),
                verdef: self.info.verdef.map(to_end),
            }
        }
    }

    /// Read a strtab string at offset `off` (e.g. a DT_NEEDED soname).
    /// # C: &strtab[off..NUL]
    pub unsafe fn str_at(&self, off: u64) -> &'static [u8] {
        // SAFETY: strtab is within the mapping; we read to the NUL terminator.
        unsafe {
            match self.info.strtab {
                Some(v) => {
                    let p = (self.base + v + off) as *const u8;
                    let mut n = 0usize;
                    while *p.add(n) != 0 { n += 1; }
                    from_raw_parts(p, n)
                }
                None => &[],
            }
        }
    }
}
