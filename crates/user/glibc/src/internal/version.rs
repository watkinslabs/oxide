// Symbol versioning (docs/59§2 R02). Real binaries reference
// e.g. `memcpy@GLIBC_2.14`; the dynamic linker rejects unversioned libc.
// Two halves:
//   1. `glibc.ld.version` (version script) declares the version nodes +
//      which symbols belong to each — fed to the linker by `xtask glibc`.
//   2. `symver!` emits the `.symver <impl>, <name>@[@]<node>` directive
//      binding a default/non-default versioned alias to an impl symbol.
//
// Inert until G2+ defines real exports; defined now so the mechanism is
// in place and one-fn-per-file modules can `symver!` at birth.
#![allow(unused_macros)]

// symver!(real = strlen_impl, name = "strlen", node = "GLIBC_2.2.5");           // default
// symver!(real = strlen_old,  name = "strlen", node = "GLIBC_2.0", default = false);
#[macro_export]
macro_rules! symver {
    (real = $real:ident, name = $name:literal, node = $node:literal) => {
        core::arch::global_asm!(concat!(".symver ", stringify!($real), ", ", $name, "@@", $node));
    };
    (real = $real:ident, name = $name:literal, node = $node:literal, default = false) => {
        core::arch::global_asm!(concat!(".symver ", stringify!($real), ", ", $name, "@", $node));
    };
}
