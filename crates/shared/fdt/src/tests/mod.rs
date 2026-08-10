// Hosted tests for the FDT reader. Every case is built from `fixture::Fdt`, a
// minimal blob writer, so the fixtures are exact wire images rather than
// hand-typed hex — a test that cannot construct the shape it claims to test
// cannot fail for the right reason either.

mod build_tests;
mod header_tests;
mod uapi_tests;
mod of_tree_tests;
mod props_tests;
mod walk_tests;

pub use crate::fixture::{virt_like, Fdt};
