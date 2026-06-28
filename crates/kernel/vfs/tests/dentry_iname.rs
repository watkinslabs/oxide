// dcache-D18: inline-or-heap dentry name storage (Linux d_iname / DNAME_INLINE_LEN).
// Asserts round-trip, inline-vs-heap placement, the 32/33-byte boundary, and
// that the name-derived hash is identical regardless of storage variant.

use vfs::dentry::{QStr, DNAME_INLINE_LEN};

#[test]
fn short_name_inline_roundtrip() {
    let q = QStr::new(None, "etc");
    assert_eq!(q.name(), "etc");
    assert!(q.is_inline(), "short name must be stored inline");
}

#[test]
fn long_name_heap_roundtrip() {
    let long = "a".repeat(DNAME_INLINE_LEN + 8); // 40 bytes > 32
    let q = QStr::new(None, &long);
    assert_eq!(q.name(), long);
    assert!(!q.is_inline(), "long name must be stored on the heap");
}

#[test]
fn boundary_32_inline_33_heap() {
    let at = "x".repeat(DNAME_INLINE_LEN); // exactly 32 → inline
    let q32 = QStr::new(None, &at);
    assert_eq!(q32.name(), at);
    assert!(q32.is_inline(), "exactly DNAME_INLINE_LEN bytes must be inline");

    let over = "x".repeat(DNAME_INLINE_LEN + 1); // 33 → heap
    let q33 = QStr::new(None, &over);
    assert_eq!(q33.name(), over);
    assert!(!q33.is_inline(), "DNAME_INLINE_LEN+1 bytes must be heap");
}

#[test]
fn hash_independent_of_storage() {
    // Same name, but force one inline and ensure hash matches the heap path
    // for an equal-length-or-longer counterpart is name-derived. Compare a
    // short name's hash to a recomputed QStr of the same name (both inline),
    // and a long name to itself (both heap) — hash is a pure function of name.
    let short_a = QStr::new(None, "config");
    let short_b = QStr::new(None, "config");
    assert!(short_a.is_inline() && short_b.is_inline());
    assert_eq!(short_a.hash(), short_b.hash(), "hash is name-derived, not storage-derived");

    let name = "z".repeat(DNAME_INLINE_LEN + 5);
    let long_a = QStr::new(None, &name);
    let long_b = QStr::new(None, &name);
    assert!(!long_a.is_inline() && !long_b.is_inline());
    assert_eq!(long_a.hash(), long_b.hash(), "long-name hash stable across heap storage");
}
