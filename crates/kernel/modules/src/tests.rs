// Hosted tests for the module symbol table. The table is kernel-global, so
// every test that clears or writes it takes the crate's symbol-table claim
// (`test_serial::symtab`) — the claim owns the reset. This file used to keep
// its own `SERIAL` for its own nine tests while seventeen other files cleared
// the same table without it.

extern crate alloc;
use super::*;
use crate::symtab::*;

#[test]
fn license_recognition() {
    let _modules = crate::test_serial::claim();
    assert!(license_is_gpl("GPL"));
    assert!(license_is_gpl("GPL v2"));
    assert!(license_is_gpl("Dual BSD/GPL"));
    assert!(license_is_gpl("Dual MIT/GPL"));
    assert!(!license_is_gpl("BSD"));
    assert!(!license_is_gpl("Proprietary"));
    assert!(!license_is_gpl(""));
}

#[test]
fn export_then_resolve_round_trip() {
    let _modules = crate::test_serial::claim();
    export("kfree",  0x1000, false);
    export("kmalloc", 0x2000, false);
    let f = resolve("kfree",   true).unwrap();
    let k = resolve("kmalloc", true).unwrap();
    assert_eq!(f.addr, 0x1000);
    assert_eq!(k.addr, 0x2000);
    assert!(!f.gpl_only);
    assert!(k.module.is_none(), "built-in symbols carry no module name");
}

#[test]
fn missing_symbol_is_enoent() {
    let _modules = crate::test_serial::claim();
    assert_eq!(resolve("nonexistent", true), Err(SymError::Enoent));
}

#[test]
fn gpl_symbol_blocks_non_gpl_consumer() {
    let _modules = crate::test_serial::claim();
    export("rcu_register_callback", 0x3000, true);
    // GPL consumer: OK.
    let g = resolve("rcu_register_callback", true).unwrap();
    assert_eq!(g.addr, 0x3000);
    // Proprietary consumer: Eacces.
    assert_eq!(
        resolve("rcu_register_callback", false),
        Err(SymError::Eacces),
    );
}

#[test]
fn non_gpl_symbol_resolves_for_anyone() {
    let _modules = crate::test_serial::claim();
    export("printk", 0x4000, false);
    assert!(resolve("printk", true).is_ok());
    assert!(resolve("printk", false).is_ok());
}

#[test]
fn module_export_carries_provider_name() {
    let _modules = crate::test_serial::claim();
    export_module("my_drv_init", 0x5000, false, "my_drv");
    let e = resolve("my_drv_init", true).unwrap();
    assert_eq!(e.module, Some("my_drv"));
}

#[test]
fn unexport_module_drops_only_its_own_symbols() {
    let _modules = crate::test_serial::claim();
    export("kfree", 0x1000, false);
    export_module("foo_a", 0x2000, false, "foo");
    export_module("foo_b", 0x2100, false, "foo");
    export_module("bar_a", 0x3000, false, "bar");
    assert_eq!(count(), 4);

    let dropped = unexport_module("foo");
    assert_eq!(dropped, 2);
    assert!(is_exported("kfree"));
    assert!(!is_exported("foo_a"));
    assert!(!is_exported("foo_b"));
    assert!(is_exported("bar_a"));
}

#[test]
fn re_export_replaces_prior_entry() {
    let _modules = crate::test_serial::claim();
    let prev = export("addr_x", 0xAAA, false);
    assert!(prev.is_none());
    let prev = export("addr_x", 0xBBB, true);
    assert_eq!(prev.map(|e| e.addr), Some(0xAAA));
    let now = resolve("addr_x", true).unwrap();
    assert_eq!(now.addr, 0xBBB);
    assert!(now.gpl_only);
}

#[test]
fn snapshot_returns_all_entries() {
    let _modules = crate::test_serial::claim();
    export("a", 1, false);
    export("b", 2, true);
    export_module("c", 3, false, "mod");
    let snap = snapshot();
    let names: alloc::vec::Vec<&str> = snap.iter().map(|(n, _)| *n).collect();
    assert!(names.contains(&"a"));
    assert!(names.contains(&"b"));
    assert!(names.contains(&"c"));
    assert_eq!(count(), 3);
}

#[test]
fn is_exported_does_not_apply_gpl_gate() {
    let _modules = crate::test_serial::claim();
    export("gpl_only", 1, true);
    // Pure existence query — no GPL filter.
    assert!(is_exported("gpl_only"));
    // resolve still gates.
    assert_eq!(resolve("gpl_only", false), Err(SymError::Eacces));
}
