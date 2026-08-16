//! Test manifest for name handling. One file per surface, because a single
//! one would pass the length cap before it covered the format.

#[path = "tests/codepage.rs"] mod codepage;
#[path = "tests/short.rs"] mod short;
#[path = "tests/lfn.rs"] mod lfn;
#[path = "tests/shortgen.rs"] mod shortgen;
#[path = "tests/compare.rs"] mod compare;
#[path = "tests/msdos.rs"] mod msdos;
