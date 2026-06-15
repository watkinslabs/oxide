// Symbol versioning (docs/59§5). glibc symbols are versioned —
// printf@@GLIBC_2.2.5 — so the rtld must resolve a versioned *reference* to a
// definition carrying the same version name. Three tables:
//   DT_VERSYM   : u16 per symbol index; low 15 bits = version index,
//                 bit15 (0x8000) = "hidden" (non-default version).
//   DT_VERNEED  : referencing side — Verneed(file) → Vernaux(version index →
//                 version-name strtab offset), what each ref *requires*.
//   DT_VERDEF   : defining side — Verdef(version index) → Verdaux(name), what
//                 each def *provides*.
// Pure parsing over borrowed windows; hosted-tested. Wiring into the resolver
// is in linkmap/relocate.

pub const VER_NDX_LOCAL: u16 = 0;
pub const VER_NDX_GLOBAL: u16 = 1;
pub const VERSYM_HIDDEN: u16 = 0x8000;
pub const VERSYM_VERSION: u16 = 0x7fff;

// ELF version-struct field offsets (Elf64): Verneed{version@0,cnt@2,file@4,
// aux@8,next@12}=16; Vernaux{hash@0,flags@4,other@6,name@8,next@12}=16;
// Verdef{version@0,flags@2,ndx@4,cnt@6,hash@8,aux@12,next@16}=20;
// Verdaux{name@0,next@4}=8. The walkers advance by the structs' own aux/next
// fields, so only the test builders need the sizes (kept there).

#[inline]
fn rd_u16(b: &[u8], o: usize) -> Option<u16> { b.get(o..o + 2).map(|s| u16::from_le_bytes(s.try_into().unwrap())) }
#[inline]
fn rd_u32(b: &[u8], o: usize) -> Option<u32> { b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap())) }

fn cstr(strtab: &[u8], off: u32) -> Option<&[u8]> {
    let s = strtab.get(off as usize..)?;
    let end = s.iter().position(|&b| b == 0)?;
    Some(&s[..end])
}

/// (version index, hidden) for symbol `sym_idx` from DT_VERSYM, or None.
/// # C: versym[sym_idx] split into (index, hidden)
pub fn versym(versym: &[u8], sym_idx: u32) -> Option<(u16, bool)> {
    let raw = rd_u16(versym, sym_idx as usize * 2)?;
    Some((raw & VERSYM_VERSION, raw & VERSYM_HIDDEN != 0))
}

/// Version name a *reference* requires, given its version index: walk
/// DT_VERNEED's Verneed→Vernaux chains for vna_other == version index.
/// # C: verneed[..].vernaux[vna_other==idx].vna_name
pub fn needed_name<'a>(verneed: &[u8], strtab: &'a [u8], idx: u16) -> Option<&'a [u8]> {
    let mut vn = 0usize;
    loop {
        let cnt = rd_u16(verneed, vn + 2)?;
        let aux = rd_u32(verneed, vn + 8)? as usize;
        let next = rd_u32(verneed, vn + 12)?;
        let mut va = vn + aux;
        for _ in 0..cnt {
            let other = rd_u16(verneed, va + 6)?;
            let name = rd_u32(verneed, va + 8)?;
            if other == idx { return cstr(strtab, name); }
            let vnext = rd_u32(verneed, va + 12)? as usize;
            if vnext == 0 { break; }
            va += vnext;
        }
        if next == 0 { return None; }
        vn += next as usize;
    }
}

/// Version name a *definition* provides, given its version index: walk
/// DT_VERDEF's Verdef chain for vd_ndx == index, return its first Verdaux.
/// # C: verdef[vd_ndx==idx].verdaux[0].vda_name
pub fn def_name<'a>(verdef: &[u8], strtab: &'a [u8], idx: u16) -> Option<&'a [u8]> {
    let mut vd = 0usize;
    loop {
        let ndx = rd_u16(verdef, vd + 4)?;
        let aux = rd_u32(verdef, vd + 12)? as usize;
        let next = rd_u32(verdef, vd + 16)?;
        if ndx == (idx & VERSYM_VERSION) {
            let name = rd_u32(verdef, vd + aux)?; // first Verdaux.vda_name
            return cstr(strtab, name);
        }
        if next == 0 { return None; }
        vd += next as usize;
    }
}

/// Does definition `def_idx` in a defining object satisfy a reference that
/// requires `req` (None = unversioned ref, matches anything)? A versioned
/// ref matches a def whose version name equals `req`; an unversioned ref
/// matches the default (non-hidden) definition.
///
/// # C: version-match a def against a (possibly versioned) ref
pub fn def_satisfies(def_versym: Option<&[u8]>, verdef: Option<&[u8]>, strtab: &[u8], def_idx: u32, req: Option<&[u8]>) -> bool {
    match req {
        // unversioned ref: accept unless the def is a hidden (non-default) version
        None => match def_versym {
            Some(vs) => versym(vs, def_idx).map(|(_, hidden)| !hidden).unwrap_or(true),
            None => true,
        },
        Some(want) => {
            let (Some(vs), Some(vd)) = (def_versym, verdef) else { return false; };
            match versym(vs, def_idx) {
                Some((vi, _)) => def_name(vd, strtab, vi).map(|n| n == want).unwrap_or(false),
                None => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    const VERNEED_SZ: usize = 16;
    const VERNAUX_SZ: usize = 16;
    const VERDEF_SZ: usize = 20;
    const VERDAUX_SZ: usize = 8;

    #[test]
    fn versym_split() {
        let mut vs = Vec::new();
        for v in [VER_NDX_LOCAL, VER_NDX_GLOBAL, 2u16, 3u16 | VERSYM_HIDDEN] { vs.extend_from_slice(&v.to_le_bytes()); }
        assert_eq!(versym(&vs, 0), Some((0, false)));
        assert_eq!(versym(&vs, 2), Some((2, false)));
        assert_eq!(versym(&vs, 3), Some((3, true))); // hidden bit stripped
    }

    // one Verneed(file="libc.so.6") with two Vernaux: idx2=GLIBC_2.2.5, idx3=GLIBC_2.34
    fn build_verneed() -> (Vec<u8>, Vec<u8>) {
        let mut st = std::vec![0u8];
        let off = |st: &mut Vec<u8>, s: &[u8]| { let o = st.len() as u32; st.extend_from_slice(s); st.push(0); o };
        let n_225 = off(&mut st, b"GLIBC_2.2.5");
        let n_234 = off(&mut st, b"GLIBC_2.34");
        let mut b = std::vec![0u8; VERNEED_SZ + 2 * VERNAUX_SZ];
        // Verneed @0: version=1, cnt=2, file@4=0, aux@8=16, next@12=0
        b[0..2].copy_from_slice(&1u16.to_le_bytes());
        b[2..4].copy_from_slice(&2u16.to_le_bytes());
        b[4..8].copy_from_slice(&0u32.to_le_bytes());
        b[8..12].copy_from_slice(&(VERNEED_SZ as u32).to_le_bytes());
        b[12..16].copy_from_slice(&0u32.to_le_bytes());
        // Vernaux[0] @16: other=2, name=n_225, next=16
        let a0 = VERNEED_SZ;
        b[a0 + 6..a0 + 8].copy_from_slice(&2u16.to_le_bytes());
        b[a0 + 8..a0 + 12].copy_from_slice(&n_225.to_le_bytes());
        b[a0 + 12..a0 + 16].copy_from_slice(&(VERNAUX_SZ as u32).to_le_bytes());
        // Vernaux[1] @32: other=3, name=n_234, next=0
        let a1 = VERNEED_SZ + VERNAUX_SZ;
        b[a1 + 6..a1 + 8].copy_from_slice(&3u16.to_le_bytes());
        b[a1 + 8..a1 + 12].copy_from_slice(&n_234.to_le_bytes());
        (b, st)
    }

    #[test]
    fn needed_name_lookup() {
        let (vn, st) = build_verneed();
        assert_eq!(needed_name(&vn, &st, 2), Some(&b"GLIBC_2.2.5"[..]));
        assert_eq!(needed_name(&vn, &st, 3), Some(&b"GLIBC_2.34"[..]));
        assert_eq!(needed_name(&vn, &st, 9), None);
    }

    // one Verdef ndx=2 name "GLIBC_2.2.5"
    fn build_verdef() -> (Vec<u8>, Vec<u8>) {
        let mut st = std::vec![0u8];
        let o = st.len() as u32; st.extend_from_slice(b"GLIBC_2.2.5"); st.push(0);
        let mut b = std::vec![0u8; VERDEF_SZ + VERDAUX_SZ];
        // Verdef @0: version=1, flags=0, ndx=2, cnt=1, hash=0, aux=20, next=0
        b[0..2].copy_from_slice(&1u16.to_le_bytes());
        b[4..6].copy_from_slice(&2u16.to_le_bytes());
        b[6..8].copy_from_slice(&1u16.to_le_bytes());
        b[12..16].copy_from_slice(&(VERDEF_SZ as u32).to_le_bytes());
        // Verdaux @20: name=o, next=0
        b[VERDEF_SZ..VERDEF_SZ + 4].copy_from_slice(&o.to_le_bytes());
        (b, st)
    }

    #[test]
    fn def_name_lookup() {
        let (vd, st) = build_verdef();
        assert_eq!(def_name(&vd, &st, 2), Some(&b"GLIBC_2.2.5"[..]));
        assert_eq!(def_name(&vd, &st, 5), None);
    }

    #[test]
    fn satisfies_versioned_and_unversioned() {
        let (vd, st) = build_verdef();
        // def symbol idx 1 has version index 2 (GLIBC_2.2.5), not hidden
        let mut vs = Vec::new();
        for v in [VER_NDX_LOCAL, 2u16] { vs.extend_from_slice(&v.to_le_bytes()); }
        // versioned ref requiring GLIBC_2.2.5 → matches
        assert!(def_satisfies(Some(&vs), Some(&vd), &st, 1, Some(b"GLIBC_2.2.5")));
        // requiring a different version → no
        assert!(!def_satisfies(Some(&vs), Some(&vd), &st, 1, Some(b"GLIBC_2.34")));
        // unversioned ref → accepts a non-hidden def
        assert!(def_satisfies(Some(&vs), Some(&vd), &st, 1, None));
        // hidden def + unversioned ref → rejected
        let mut vsh = Vec::new();
        for v in [VER_NDX_LOCAL, 2u16 | VERSYM_HIDDEN] { vsh.extend_from_slice(&v.to_le_bytes()); }
        assert!(!def_satisfies(Some(&vsh), Some(&vd), &st, 1, None));
    }
}
