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
            if !order.iter().any(|o| *o == d) {
                order.push(d);
            }
        }
        i += 1;
    }
    order
}

/// One object's resolved views, as borrowed byte windows into its mapping.
pub struct ObjView<'a> {
    pub base: u64,
    pub gnu_hash: Option<&'a [u8]>,
    pub sysv_hash: Option<&'a [u8]>,
    pub sym: SymView<'a>,
}

/// Resolve `name` against the whole link map in scope order. Returns
/// `(object index, runtime address = base + st_value)` for the first object
/// that *defines* it (skips SHN_UNDEF references). None if unresolved.
///
/// # C: first in-scope object defining `name` → base + st_value
pub fn lookup_global(map: &[ObjView], name: &[u8]) -> Option<(usize, u64)> {
    for (i, obj) in map.iter().enumerate() {
        if let Some(idx) = crate::symbol::resolve(obj.gnu_hash, obj.sysv_hash, &obj.sym, name) {
            if obj.sym.is_defined(idx) {
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
            ObjView { base: 0x1000, gnu_hash: None, sysv_hash: Some(&h0), sym: SymView { symtab: &s0, strtab: &st0 } },
            ObjView { base: 0x2000, gnu_hash: None, sysv_hash: Some(&h1), sym: SymView { symtab: &s1, strtab: &st1 } },
        ];
        // "a" resolves in obj0
        assert_eq!(lookup_global(&map, b"a"), Some((0, 0x1010)));
        // "g" is UNDEF in obj0, defined in obj1 → resolves there
        assert_eq!(lookup_global(&map, b"g"), Some((1, 0x2020)));
        // unknown
        assert_eq!(lookup_global(&map, b"nope"), None);
    }
}
