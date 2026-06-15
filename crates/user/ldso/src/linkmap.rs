// The global link map (docs/59§5). Holds every loaded object and defines
// the two scope operations the rest of the linker is built on:
//   1. dependency order — the breadth-first DT_NEEDED walk that decides load
//      and default symbol-search order (glibc semantics: root first, then
//      its NEEDED in order, then theirs, deduped).
//   2. global symbol lookup — resolve a name against the whole map in scope
//      order; the first object with a *defined* (non-UNDEF) match wins.
// Pure logic over borrowed views; the freestanding mmap loader (G12e) fills
// the views in from real mappings.
use crate::symbol::SymView;
use alloc::string::String;
use alloc::vec::Vec;

/// Breadth-first dependency order from `root`, deduped, root first. `deps`
/// yields the DT_NEEDED sonames of a given object. Matches glibc's load /
/// default-scope order.
///
/// # C: BFS over DT_NEEDED from root, deduped, root-first
pub fn dependency_order<F>(root: &str, mut deps: F) -> Vec<String>
where
    F: FnMut(&str) -> Vec<String>,
{
    let mut order: Vec<String> = Vec::new();
    order.push(String::from(root));
    let mut i = 0;
    while i < order.len() {
        let cur = order[i].clone();
        for d in deps(&cur) {
            if !order.contains(&d) {
                order.push(d);
            }
        }
        i += 1;
    }
    order
}

/// One object's resolved views, as borrowed byte windows into its mapping.
/// `versym`/`verdef` (when present) let lookup honor symbol versions.
pub struct ObjView<'a> {
    pub base: u64,
    pub gnu_hash: Option<&'a [u8]>,
    pub sysv_hash: Option<&'a [u8]>,
    pub sym: SymView<'a>,
    pub versym: Option<&'a [u8]>,
    pub verdef: Option<&'a [u8]>,
}

/// Resolve `name` (optionally requiring version `req`) against the whole link
/// map in scope order. Returns `(object index, runtime address = base +
/// st_value)` for the first object that *defines* it with a matching version
/// (skips SHN_UNDEF and version mismatches). None if unresolved.
///
/// # C: first in-scope object defining `name`@`req` → base + st_value
pub fn lookup_global(map: &[ObjView], name: &[u8], req: Option<&[u8]>) -> Option<(usize, u64)> {
    for (i, obj) in map.iter().enumerate() {
        if let Some(idx) = crate::symbol::resolve(obj.gnu_hash, obj.sysv_hash, &obj.sym, name) {
            if obj.sym.is_defined(idx)
                && crate::version::def_satisfies(obj.versym, obj.verdef, obj.sym.strtab, idx, req)
            {
                if let Some(v) = obj.sym.value(idx) {
                    return Some((i, obj.base.wrapping_add(v)));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbol::{SymView, SYMENT, STB_GLOBAL, SHN_UNDEF};

    #[test]
    fn bfs_order_dedup_root_first() {
        // graph: a -> b,c ; b -> d ; c -> d ; d -> (none)
        let order = dependency_order("a", |n| match n {
            "a" => std::vec![String::from("b"), String::from("c")],
            "b" => std::vec![String::from("d")],
            "c" => std::vec![String::from("d")],
            _ => std::vec![],
        });
        assert_eq!(order, std::vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn bfs_handles_cycles() {
        // a -> b -> a (cycle) must terminate, each once
        let order = dependency_order("a", |n| match n {
            "a" => std::vec![String::from("b")],
            "b" => std::vec![String::from("a")],
            _ => std::vec![],
        });
        assert_eq!(order, std::vec!["a", "b"]);
    }

    // Build a sysv-hashed object exporting the given (name,value,shndx) syms.
    fn obj(syms: &[(&[u8], u64, u16)]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut strtab = std::vec![0u8];
        let mut symtab = std::vec![0u8; SYMENT];
        let nbucket = 16u32;
        let mut buckets = std::vec![0u32; nbucket as usize];
        let nchain = (syms.len() + 1) as u32;
        let mut chain = std::vec![0u32; nchain as usize];
        for (i, (name, value, shndx)) in syms.iter().enumerate() {
            let idx = (i + 1) as u32;
            let st_name = strtab.len() as u32;
            strtab.extend_from_slice(name);
            strtab.push(0);
            let mut e = std::vec![0u8; SYMENT];
            e[0..4].copy_from_slice(&st_name.to_le_bytes());
            e[4] = STB_GLOBAL << 4;
            e[6..8].copy_from_slice(&shndx.to_le_bytes());
            e[8..16].copy_from_slice(&value.to_le_bytes());
            symtab.extend_from_slice(&e);
            let h = elf::elf_hash(name) % nbucket;
            // chain insert at bucket head
            chain[idx as usize] = buckets[h as usize];
            buckets[h as usize] = idx;
        }
        let mut hash = std::vec::Vec::new();
        hash.extend_from_slice(&nbucket.to_le_bytes());
        hash.extend_from_slice(&nchain.to_le_bytes());
        for b in &buckets { hash.extend_from_slice(&b.to_le_bytes()); }
        for c in &chain { hash.extend_from_slice(&c.to_le_bytes()); }
        (symtab, strtab, hash)
    }

    #[test]
    fn global_lookup_first_definer_wins() {
        // obj0 references "g" as UNDEF + defines "a"; obj1 defines "g".
        let (s0, st0, h0) = obj(&[(b"a", 0x10, 7), (b"g", 0, SHN_UNDEF)]);
        let (s1, st1, h1) = obj(&[(b"g", 0x20, 7)]);
        let map = std::vec![
            ObjView { base: 0x1000, gnu_hash: None, sysv_hash: Some(&h0), sym: SymView { symtab: &s0, strtab: &st0 }, versym: None, verdef: None },
            ObjView { base: 0x2000, gnu_hash: None, sysv_hash: Some(&h1), sym: SymView { symtab: &s1, strtab: &st1 }, versym: None, verdef: None },
        ];
        // "a" resolves in obj0
        assert_eq!(lookup_global(&map, b"a", None), Some((0, 0x1010)));
        // "g" is UNDEF in obj0, defined in obj1 → resolves there
        assert_eq!(lookup_global(&map, b"g", None), Some((1, 0x2020)));
        // unknown
        assert_eq!(lookup_global(&map, b"nope", None), None);
    }

    #[test]
    fn versioned_lookup_filters_by_version() {
        use crate::version::{VER_NDX_LOCAL, VERSYM_HIDDEN};
        // obj defines "f" (idx 1) at version index 2. Build a Verdef ndx=2
        // name "V2", and a versym [LOCAL, 2].
        let (s, st0, h) = obj(&[(b"f", 0x40, 7)]);
        // append version name to a fresh strtab copy so def_name can find it
        let mut st = st0.clone();
        let v2_off = st.len() as u32;
        st.extend_from_slice(b"V2");
        st.push(0);
        // Verdef: version@0=1, ndx@4=2, cnt@6=1, aux@12=20, next@16=0; Verdaux name@20=v2_off
        let mut vd = std::vec![0u8; 28];
        vd[0..2].copy_from_slice(&1u16.to_le_bytes());
        vd[4..6].copy_from_slice(&2u16.to_le_bytes());
        vd[6..8].copy_from_slice(&1u16.to_le_bytes());
        vd[12..16].copy_from_slice(&20u32.to_le_bytes());
        vd[20..24].copy_from_slice(&v2_off.to_le_bytes());
        let mut vs = std::vec::Vec::new();
        for v in [VER_NDX_LOCAL, 2u16] { vs.extend_from_slice(&v.to_le_bytes()); }
        let map = std::vec![ObjView {
            base: 0x3000, gnu_hash: None, sysv_hash: Some(&h),
            sym: SymView { symtab: &s, strtab: &st }, versym: Some(&vs), verdef: Some(&vd),
        }];
        // requiring V2 → resolves; requiring V9 → no; unversioned → default ok
        assert_eq!(lookup_global(&map, b"f", Some(b"V2")), Some((0, 0x3040)));
        assert_eq!(lookup_global(&map, b"f", Some(b"V9")), None);
        assert_eq!(lookup_global(&map, b"f", None), Some((0, 0x3040)));
        let _ = VERSYM_HIDDEN;
    }
}
