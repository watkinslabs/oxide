// Walker tests.
//
// Module manifest:
//   `harness` — the hosted page-table tree and bit encoding the cases share.
//   `mapping` — leaf install/replace/teardown per level and reverse translation.
//   `swap`    — the non-present encodings and the teardown that walks them.

mod harness;
mod mapping;
mod swap;
